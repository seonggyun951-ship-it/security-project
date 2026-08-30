-- 수집을 시간표가 아니라 '변화가 있을 때'만 돌린다.
--
-- 하루 한 번 무조건 돌리면 아무것도 안 바뀐 날에도 AWS를 긁고, 반대로 오전에 승인한
-- 리소스는 다음 날까지 드롭다운에 안 나온다. 승인이 곧 리소스 변화이므로 그걸 신호로 쓴다.
--
-- 승인마다 즉시 수집하지는 않는다. 관리자가 대기열을 몰아서 처리하면 수집이 연달아
-- 열 번 돈다. 대신 '수집 필요' 표시만 세워두고, 잠깐 기다렸다가 한 번에 처리한다.
--
--   승인 → dirty = true  (여러 건이 와도 표시는 하나)
--   10분마다 → dirty면 수집 1회 → dirty = false
--
-- 10분 주기 작업은 dirty가 아니면 http 호출 자체를 만들지 않는다(조건이 SQL에 있다).
-- 아무 일도 없으면 가벼운 조회 한 번으로 끝난다.

create table if not exists public.collect_state (
  id                integer primary key default 1,
  last_collected_at timestamptz,
  dirty             boolean not null default false,
  constraint collect_state_single_row check (id = 1)
);

insert into public.collect_state (id, dirty) values (1, false)
on conflict (id) do nothing;

alter table public.collect_state enable row level security;

drop policy if exists "admin can select collect_state" on public.collect_state;
create policy "admin can select collect_state"
  on public.collect_state for select to authenticated
  using (exists (select 1 from public.admins a where a.user_id = auth.uid()));

-- 적용이 끝난 순간을 잡는다.
--
-- Edge Function이 아니라 트리거에 두는 이유: 신청이 적용되는 경로가 둘이다.
-- SG·IAM·NACL은 aws-request-apply가, VPC·EC2 같은 Terraform 리소스는 로컬 에이전트가
-- DB를 직접 갱신한다. 트리거는 둘 다 잡는다.
create or replace function public.mark_collect_dirty()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.collect_state set dirty = true where id = 1;
  return null;
end;
$$;

drop trigger if exists aws_requests_applied_collect on public.aws_requests;
create trigger aws_requests_applied_collect
  after update of status on public.aws_requests
  for each row
  when (new.status = 'applied' and old.status is distinct from 'applied')
  execute function public.mark_collect_dirty();

-- 시간표 수집은 걷어낸다.
select cron.unschedule('aws-collect-daily')
where exists (select 1 from cron.job where jobname = 'aws-collect-daily');

-- dirty일 때만 수집한다. 아니면 http 호출이 아예 만들어지지 않는다.
select cron.schedule(
  'aws-collect-sweep',
  '*/10 * * * *',
  $$
  select net.http_post(
    url := 'https://phqiejtztwhychazikim.supabase.co/functions/v1/aws-collect',
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'x-cron-secret', (select decrypted_secret from vault.decrypted_secrets where name = 'cron_secret')
    ),
    body := '{}'::jsonb,
    timeout_milliseconds := 120000
  )
  from public.collect_state
  where id = 1
    and dirty
    and (last_collected_at is null or now() - last_collected_at >= interval '10 minutes');
  $$
);
