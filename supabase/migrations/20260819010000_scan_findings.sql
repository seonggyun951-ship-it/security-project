-- 자동 점검 결과.
--
-- Prowler가 AWS 계정을 점검한 결과를 담는다. 목적은 목록을 쌓는 것이 아니라
-- 고리를 닫는 것이다: 점검 → 알림 → 조치 신청 → 승인·적용 → 재점검 → 닫힘 확인.
--
-- 같은 위반이 매일 새 행으로 쌓이면 "어제부터 있던 건지 오늘 새로 생긴 건지"를 알 수 없다.
-- 그래서 (체크, 리소스) 하나당 한 행만 두고, 볼 때마다 last_seen_at을 갱신한다.
-- 다음 점검에서 안 보이면 고쳐진 것이므로 resolved_at을 찍는다.

create table if not exists scan_findings (
  id uuid primary key default gen_random_uuid(),

  check_id text not null,           -- ec2_securitygroup_not_used 등. 지식 베이스 ref와 같은 값
  resource_id text not null,        -- sg-08fa..., acl-0b1d... (ARN에서 끝부분만)
  resource_arn text,
  region text,
  severity text,                    -- critical | high | medium | low
  title text,
  detail text,

  -- 이 리소스를 만든 신청. 앱을 거치지 않고 콘솔에서 만든 것은 null이다.
  -- null이면 주인을 알 수 없으므로 관리자에게만 알린다.
  request_id uuid references aws_requests(id) on delete set null,
  owner_email text,

  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  resolved_at timestamptz,          -- 다음 점검에서 사라지면 찍힌다

  -- 알림을 이미 보냈는지. 같은 위반을 매일 다시 알리지 않는다.
  notified_at timestamptz,

  -- 조치하지 않기로 한 것. 기본 VPC의 NACL처럼 바꿀 수 없거나 감수하는 항목.
  muted_reason text,
  muted_by text,
  muted_at timestamptz
);

-- 같은 (체크, 리소스)는 한 행만. 점검을 다시 돌려도 중복이 쌓이지 않는다.
create unique index if not exists scan_findings_key
  on scan_findings (check_id, resource_id);

-- 화면이 주로 보는 것: 아직 안 고쳐진 것을 심각도 순으로
create index if not exists scan_findings_open_idx
  on scan_findings (severity, last_seen_at desc)
  where resolved_at is null;

create index if not exists scan_findings_owner_idx
  on scan_findings (owner_email)
  where resolved_at is null;

alter table scan_findings enable row level security;

-- 관리자는 전부 본다.
drop policy if exists scan_findings_admin_read on scan_findings;
create policy scan_findings_admin_read on scan_findings
  for select to authenticated
  using (exists (select 1 from admins a where a.user_id = auth.uid()));

-- 신청자는 자기가 신청해서 만들어진 리소스의 것만 본다.
-- 주인을 알 수 없는 것(콘솔에서 직접 만든 것)은 여기 걸리지 않는다.
drop policy if exists scan_findings_own_read on scan_findings;
create policy scan_findings_own_read on scan_findings
  for select to authenticated
  using (
    request_id is not null
    and exists (
      select 1 from aws_requests r
      where r.id = scan_findings.request_id and r.requester_id = auth.uid()
    )
  );

-- 쓰기 정책은 두지 않는다. 점검 결과는 에이전트(service_role)만 기록한다.

comment on table scan_findings is
  '자동 점검(Prowler) 결과. (check_id, resource_id) 하나당 한 행이며 재점검 시 갱신된다.';
comment on column scan_findings.resolved_at is
  '다음 점검에서 이 위반이 보이지 않으면 찍힌다. 조치가 실제로 먹혔는지 확인하는 값.';
comment on column scan_findings.request_id is
  '이 리소스를 만든 신청. null이면 앱을 거치지 않고 만들어진 것이라 주인을 알 수 없다.';

-- 점검 한 번의 기록. 언제 돌았고 몇 건이 나왔는지.
create table if not exists scan_runs (
  id uuid primary key default gen_random_uuid(),
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  provider text not null default 'aws',
  services text[],                  -- 점검한 서비스. null이면 전체
  total int,
  failed int,
  passed int,
  new_findings int,                 -- 이번에 처음 나온 것
  resolved_findings int,            -- 이번에 사라진 것
  error text
);

alter table scan_runs enable row level security;

drop policy if exists scan_runs_admin_read on scan_runs;
create policy scan_runs_admin_read on scan_runs
  for select to authenticated
  using (exists (select 1 from admins a where a.user_id = auth.uid()));

comment on table scan_runs is '점검 실행 기록. 언제 돌았고 무엇이 늘고 줄었는지.';
