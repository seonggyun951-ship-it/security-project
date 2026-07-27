-- AWS 자동화: 리소스 타입 무관 범용 신청 테이블
-- 신청자 페이지에서 insert, 승인자 페이지에서 승인/거절/AWS 반영
-- Supabase 대시보드 > SQL Editor 에서 실행

create table if not exists aws_requests (
  id uuid primary key default gen_random_uuid(),
  resource_type text not null,            -- 'security_group' | 'waf_web_acl'
  action text not null,                   -- SG: 'create_sg' | 'add_rules' / WAF: 'create_acl' | 'add_waf_rules'
  title text,                             -- 표시용 이름 (sg 이름 / acl 이름 / 대상 리소스명)
  target_id text,                         -- 기존 리소스에 추가하는 경우 대상 ID (sg-xxxx / web acl id)
  payload jsonb not null default '{}',    -- 타입/액션별 상세 필드 전부
  reason text,                            -- 신청 사유
  status text not null default 'pending', -- pending | approved | applied | rejected | failed
  error_message text,
  result jsonb,                           -- 반영 결과 (예: {"created_id": "sg-...", "web_acl_id": "..."})
  requester_id uuid,                      -- 신청자 auth.users.id
  requester_email text,                   -- 신청자 이메일 (표시용)
  requested_at timestamptz not null default now(),
  reviewed_at timestamptz,
  applied_at timestamptz
);

create index if not exists idx_aws_requests_status on aws_requests (status);
create index if not exists idx_aws_requests_requested_at on aws_requests (requested_at desc);

alter table aws_requests enable row level security;

-- 포트폴리오 단일 관리자 단계: 로그인(authenticated)한 사용자는 모두 조회/신청/처리 가능.
-- 추후 신청자/승인자 role 분리 시 update 정책을 admin으로 좁히면 됨.
drop policy if exists "authenticated can select aws_requests" on aws_requests;
create policy "authenticated can select aws_requests"
  on aws_requests for select to authenticated using (true);

drop policy if exists "authenticated can insert aws_requests" on aws_requests;
create policy "authenticated can insert aws_requests"
  on aws_requests for insert to authenticated with check (true);

drop policy if exists "authenticated can update aws_requests" on aws_requests;
create policy "authenticated can update aws_requests"
  on aws_requests for update to authenticated using (true);

drop policy if exists "authenticated can delete aws_requests" on aws_requests;
create policy "authenticated can delete aws_requests"
  on aws_requests for delete to authenticated using (true);
