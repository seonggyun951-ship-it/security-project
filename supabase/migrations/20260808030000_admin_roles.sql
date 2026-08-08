-- 1단계: 관리자(승인 권한) 분리
-- Supabase 대시보드 > SQL Editor 에서 실행
--
-- 문제: 기존 정책은 로그인만 하면 누구나 aws_requests.status를 'approved'로 바꿀 수 있었고,
--       Terraform 에이전트가 그걸 그대로 AWS에 적용했다. Edge Function을 우회하는 경로였음.
--       gcp_requests는 'for all using (true)'라 익명 사용자도 전부 가능했다.

-- ---- 관리자 테이블 ----
create table if not exists admins (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  email      text,
  created_at timestamptz not null default now()
);

alter table admins enable row level security;

-- 본인이 관리자인지만 확인 가능 (관리자 명단 전체는 노출하지 않음).
-- insert/update/delete 정책이 없으므로 service_role로만 관리자를 추가할 수 있다.
drop policy if exists "read own admin row" on admins;
create policy "read own admin row"
  on admins for select to authenticated
  using (user_id = auth.uid());

-- RLS 정책 안에서 쓸 관리자 판별 함수.
-- security definer라 admins 테이블의 RLS를 우회해서 조회한다(정책 재귀 방지).
create or replace function is_admin()
returns boolean
language sql
security definer
stable
set search_path = public
as $$
  select exists (select 1 from admins where user_id = auth.uid());
$$;

revoke all on function is_admin() from public;
grant execute on function is_admin() to authenticated;

-- ---- aws_requests 정책 재정의 ----
-- 조회: 로그인 사용자 전부 (신청자도 자기 신청 현황을 봐야 함)
drop policy if exists "authenticated can select aws_requests" on aws_requests;
create policy "authenticated can select aws_requests"
  on aws_requests for select to authenticated using (true);

-- 신청: 로그인 사용자 전부. 단 pending으로만, 본인 명의로만 넣을 수 있다.
drop policy if exists "authenticated can insert aws_requests" on aws_requests;
create policy "authenticated can insert aws_requests"
  on aws_requests for insert to authenticated
  with check (status = 'pending' and requester_id = auth.uid());

-- 승인/거부/삭제: 관리자만
drop policy if exists "authenticated can update aws_requests" on aws_requests;
drop policy if exists "admin can update aws_requests" on aws_requests;
create policy "admin can update aws_requests"
  on aws_requests for update to authenticated
  using (is_admin()) with check (is_admin());

drop policy if exists "authenticated can delete aws_requests" on aws_requests;
drop policy if exists "admin can delete aws_requests" on aws_requests;
create policy "admin can delete aws_requests"
  on aws_requests for delete to authenticated
  using (is_admin());

-- ---- gcp_requests 정책 재정의 ----
-- 기존 gcp_requests_all은 to 지정이 없어 anon에게도 열려 있었다. 반드시 제거.
drop policy if exists "gcp_requests_all" on gcp_requests;

drop policy if exists "authenticated can select gcp_requests" on gcp_requests;
create policy "authenticated can select gcp_requests"
  on gcp_requests for select to authenticated using (true);

drop policy if exists "authenticated can insert gcp_requests" on gcp_requests;
create policy "authenticated can insert gcp_requests"
  on gcp_requests for insert to authenticated
  with check (status = 'pending' and requester_id = auth.uid());

drop policy if exists "admin can update gcp_requests" on gcp_requests;
create policy "admin can update gcp_requests"
  on gcp_requests for update to authenticated
  using (is_admin()) with check (is_admin());

drop policy if exists "admin can delete gcp_requests" on gcp_requests;
create policy "admin can delete gcp_requests"
  on gcp_requests for delete to authenticated
  using (is_admin());

-- ---- 첫 관리자 등록 ----
insert into admins (user_id, email)
select id, email from auth.users where email = 'han@g.com'
on conflict (user_id) do nothing;
