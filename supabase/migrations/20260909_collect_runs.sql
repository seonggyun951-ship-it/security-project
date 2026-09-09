-- 수집을 언제 돌렸는지 남긴다.
--
-- 지금까지는 aws_resource_snapshots가 '변경 이력'과 '수집 기록'을 겸하고 있었다.
-- 그런데 변경이 없으면 행이 생기지 않으므로, 화면에서는
--   "수집이 돌았고 바뀐 게 없었다"  와  "수집이 아예 안 돌았다"
-- 를 구별할 수 없다. 둘 다 아무것도 안 보이기 때문이다.
--
-- 점검 쪽에는 이미 scan_runs가 있어 같은 문제를 겪지 않는다. 수집에도 같은 자리를 둔다.
--
-- 스냅샷 표는 그대로 둔다. 그쪽은 '무엇이 어떻게 바뀌었나'를 담고,
-- 이 표는 '언제 돌았고 몇 개를 봤나'를 담는다. 역할이 다르다.

create table if not exists public.collect_runs (
  id          bigint generated always as identity primary key,
  started_at  timestamptz not null default now(),
  finished_at timestamptz,
  -- 이번에 실제로 조회된 리소스 수. 종류별 내역은 counts에 둔다.
  seen        integer,
  -- 그중 값이 바뀌어 새 스냅샷을 남긴 수. 0이면 '돌았지만 변화 없음'이다.
  changed     integer,
  counts      jsonb,
  -- 크론이 돌렸는지 사람이 눌렀는지. 왜 이 시각에 돌았는지 되짚을 때 쓴다.
  trigger     text,
  error       text
);

create index if not exists collect_runs_started_idx on public.collect_runs (started_at desc);

alter table public.collect_runs enable row level security;

-- 읽기는 관리자만. AWS 현황 화면이 관리자 전용이다.
drop policy if exists "admin can select collect_runs" on public.collect_runs;
create policy "admin can select collect_runs"
  on public.collect_runs for select to authenticated
  using (exists (select 1 from public.admins a where a.user_id = auth.uid()));

-- 쓰기는 Edge Function(서비스 키)만. 실제로 돌지 않은 수집이 기록되면
-- '언제 돌았나'를 믿을 수 없게 된다.

comment on table public.collect_runs is
  '수집 실행 기록. changed=0이면 돌았지만 바뀐 게 없었다는 뜻이다.';
