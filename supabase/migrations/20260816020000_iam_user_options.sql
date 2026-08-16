-- IAM 사용자를 신청 화면 드롭다운에서 고를 수 있게 한다.
--
-- 지금은 사용자 이름을 손으로 적게 돼 있어 오타가 나면 승인 후 적용 단계에서야 실패한다.
-- 수집해 둔 목록에서 고르면 그런 일이 없다.
--
-- 어떤 환경 권한을 이미 갖고 있는지도 함께 보여준다. 승인자가 "이 사람 이미 prod 있는데"
-- 같은 판단을 화면에서 바로 할 수 있어야 한다.
--
-- 주의: create or replace view는 기존 컬럼의 순서·타입을 바꾸지 못한다. 끝에만 덧붙인다.

create or replace view aws_resource_options as
select
  resource_type,
  resource_id,
  resource_name,
  collected_at,
  raw_data ->> 'VpcId' as vpc_id,
  region,
  raw_data ->> 'EnvGroups' as env_groups
from aws_resource_snapshots;

grant select on aws_resource_options to authenticated;
