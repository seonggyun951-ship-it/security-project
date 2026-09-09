-- 신청 화면의 대상 목록에 '고르기 전에 판단할 근거'를 싣는다.
--
-- 지금은 이름과 ID만 내보내므로, 목록에서 web-sg 를 골라도 규칙이 몇 개 붙었는지
-- 몇 번째 VPC 것인지 모른 채 고르게 된다. 리소스가 열댓 개일 때는 외워서 됐지만
-- 수백 개가 되면 이름만으로는 무엇을 고르는지 알 수 없다.
--
-- 계산은 여기서 한다. 화면이 raw_data를 통째로 받아 세면 목록 한 번에
-- 수백 KB가 오간다 — 필요한 건 숫자 몇 개뿐이다.

create or replace view public.aws_resource_options as
with latest as (
  select distinct on (resource_type, resource_id)
         resource_type, resource_id, resource_name, collected_at, raw_data, region
  from public.aws_resource_snapshots
  order by resource_type, resource_id, collected_at desc
),
run as (
  select resource_type, max(last_seen_at) as run_at
  from public.aws_resource_seen
  group by 1
)
select l.resource_type,
       l.resource_id,
       l.resource_name,
       l.collected_at,
       l.raw_data ->> 'VpcId'     as vpc_id,
       l.region,
       l.raw_data ->> 'EnvGroups' as env_groups,

       -- 종류마다 '몇 개'의 뜻이 다르다. 화면이 종류를 보고 문구를 붙인다.
       case l.resource_type
         when 'security_group' then jsonb_array_length(coalesce(l.raw_data -> 'IpPermissions', '[]'::jsonb))
         when 'network_acl'    then jsonb_array_length(coalesce(l.raw_data -> 'Entries', '[]'::jsonb))
         when 'iam_user'       then (case when coalesce(l.raw_data ->> 'AttachedPolicies', '') = '' then 0
                                          else array_length(string_to_array(l.raw_data ->> 'AttachedPolicies', ','), 1) end)
         else null
       end as rule_count,

       -- 두 번째 숫자. SG는 아웃바운드, NACL은 붙은 서브넷, WAF는 용량.
       case l.resource_type
         when 'security_group' then jsonb_array_length(coalesce(l.raw_data -> 'IpPermissionsEgress', '[]'::jsonb))
         when 'network_acl'    then jsonb_array_length(coalesce(l.raw_data -> 'Associations', '[]'::jsonb))
         when 'waf_web_acl'    then (l.raw_data ->> 'Capacity')::int
         else null
       end as sub_count,

       -- 관리자 권한이 붙은 계정은 고르기 전에 보여야 한다.
       (l.raw_data ->> 'AttachedPolicies') ~* 'Administrator' as is_admin,

       -- VPC 대역. VPC 자신의 줄에서 쓰고, 다른 리소스는 vpc_id로 이어 붙인다.
       l.raw_data ->> 'CidrBlock' as cidr,

       -- 계정 번호. 따로 수집하지 않지만 ARN 한가운데에 들어 있다.
       --   arn:aws:iam::170420138507:user/deploy-bot  →  170420138507
       -- OwnerId를 주는 종류(VPC·SG)는 그걸 쓴다.
       coalesce(
         l.raw_data ->> 'OwnerId',
         substring(l.raw_data ->> 'Arn' from 'arn:aws:[a-z0-9-]+:[a-z0-9-]*:([0-9]{12}):')
       ) as account_id
from latest l
join public.aws_resource_seen s
  on s.resource_type = l.resource_type and s.resource_id = l.resource_id
join run r
  on r.resource_type = l.resource_type
where s.last_seen_at = r.run_at;

comment on view public.aws_resource_options is
  '신청 화면의 대상 목록. 마지막 수집에서 실제로 보인 것만 나오고, 고르기 전 판단 근거(rule_count·sub_count)를 함께 낸다.';
