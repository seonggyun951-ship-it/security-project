-- 점검 결과에 환경(VPC) 이름을 담는다.
--
-- Prowler 결과에는 VPC 정보가 없다. acl-0b1d... 만 봐서는 dev인지 prod인지 알 수 없어
-- "어느 환경 문제인지"를 화면에서 판단할 수 없었다.
-- 스캔할 때 AWS를 한 번 더 조회해 붙인다.

alter table scan_findings
  add column if not exists environment text;

comment on column scan_findings.environment is
  '이 리소스가 속한 VPC의 이름. Prowler가 주지 않아 스캔 시 따로 조회해 채운다.';
