-- 만료된 권한 자동 회수
--
-- 신청 화면에는 예전부터 만료 기간(1일/1주/1개월…)을 고르는 칸이 있었고 승인 화면에도
-- 만료일이 표시됐지만, 날짜가 지나도 실제로 회수하는 코드가 없었다. 화면에 뜨는 만료일이
-- 사실과 달랐던 셈이다. 이 마이그레이션과 expire-access 함수가 그 부분을 채운다.
--
-- 회수 대상:
--   grant_env_access  — IAM 그룹에서 빼기
--   create_sg/add_rules — SG 규칙 회수
--
-- 이미 회수한 건을 다시 건드리지 않도록 expired_at을 남긴다.

alter table aws_requests
  add column if not exists expired_at timestamptz;

comment on column aws_requests.expired_at is
  '만료로 자동 회수된 시각. 값이 있으면 회수가 끝난 건이라 다시 처리하지 않는다.';

-- 만료 배치가 매번 훑는 조건에 맞춘 부분 인덱스.
-- 적용 완료됐고 아직 회수하지 않은 건만 대상이라 인덱스가 작게 유지된다.
create index if not exists aws_requests_pending_expiry_idx
  on aws_requests ((payload ->> 'expires_at'))
  where status = 'applied' and expired_at is null;
