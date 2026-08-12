-- 선택 옵션 뷰에 region 추가
--
-- 배경: WAF는 스코프(REGIONAL / CLOUDFRONT)마다 호출해야 할 API 엔드포인트가 다르다.
--       기존 Web ACL에 규칙을 추가하려면 그 ACL이 어느 스코프인지 알아야 하는데,
--       뷰에 region이 없어서 화면에서 판단할 수 없었다.
--
-- aws-collect가 CLOUDFRONT 스코프 ACL은 region 값을 'CLOUDFRONT'로 넣어 구분한다.
-- raw_data는 계속 제외한다(관리자 전용).

-- create or replace view는 기존 컬럼의 순서/이름을 바꿀 수 없고 뒤에 추가만 가능하다.
-- 그래서 region을 마지막에 붙인다.
create or replace view aws_resource_options as
select
  resource_type,
  resource_id,
  resource_name,
  collected_at,
  raw_data ->> 'VpcId' as vpc_id,
  region
from aws_resource_snapshots;

grant select on aws_resource_options to authenticated;
