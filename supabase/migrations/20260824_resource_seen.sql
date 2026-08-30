-- 사라진 리소스가 신청 화면 드롭다운에 계속 뜨는 문제.
--
-- aws_resource_snapshots는 덧붙이기만 하는 이력 테이블이다(변화 추적이 목적).
-- 그래서 삭제된 리소스도 마지막 스냅샷이 영원히 남고, 뷰가 그걸 그대로 내보내
-- 없는 VPC·SG를 골라 신청했다가 적용 단계에서 실패했다.
-- 실제로 VPC 대역을 바꾼 뒤 목록에 VPC 13개(실제 5개)가 떠 있었다.
--
-- 이력은 그대로 두고, "이번 수집에서 실제로 보였는가"만 따로 기록한다.

create table if not exists public.aws_resource_seen (
  resource_type text not null,
  resource_id   text not null,
  last_seen_at  timestamptz not null default now(),
  primary key (resource_type, resource_id)
);

alter table public.aws_resource_seen enable row level security;

drop policy if exists "admin can select aws_resource_seen" on public.aws_resource_seen;
create policy "admin can select aws_resource_seen"
  on public.aws_resource_seen for select to authenticated
  using (exists (select 1 from public.admins a where a.user_id = auth.uid()));

-- 기존 리소스는 일단 전부 '보임'으로 채운다. 다음 수집이 돌면 실제로 살아 있는 것만
-- 새 시각을 받고, 사라진 것은 이 시각에 머물러 목록에서 빠진다.
insert into public.aws_resource_seen (resource_type, resource_id, last_seen_at)
select distinct resource_type, resource_id, now()
from public.aws_resource_snapshots
on conflict (resource_type, resource_id) do nothing;

-- 종류별 최신 수집분만 노출한다.
--
-- 기준을 전체 최대 시각이 아니라 **종류별** 최대 시각으로 잡는 이유:
-- 수집은 종류별로 따로 돌고 하나가 실패해도 나머지는 진행한다(각 collect*가 catch로 []를 반환).
-- 전체 기준이면 IAM 수집이 한 번 실패했을 때 IAM 목록이 통째로 사라진다.
-- 종류별 기준이면 그 종류의 최대 시각도 같이 옛날에 머물러 기존 목록이 그대로 유지된다.
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
       l.raw_data ->> 'EnvGroups' as env_groups
from latest l
join public.aws_resource_seen s
  on s.resource_type = l.resource_type and s.resource_id = l.resource_id
join run r
  on r.resource_type = l.resource_type
where s.last_seen_at = r.run_at;
