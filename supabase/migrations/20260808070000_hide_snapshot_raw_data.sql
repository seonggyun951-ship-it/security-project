-- 스냅샷 원본(raw_data) 비공개 전환
--
-- 배경: aws_resource_snapshots.raw_data에는 SG 규칙 전문, IAM 역할, WAF 설정이 통째로 들어있다.
--       지금까지는 로그인한 사용자면 누구나 이 테이블을 select할 수 있었다.
--       'AWS 현황' 페이지를 관리자 전용으로 바꿔도, 테이블을 직접 조회하면 그대로 보인다.
--
-- 문제: 테이블을 그냥 잠그면 일반 사용자 기능이 깨진다.
--       - SG/WAF 신청의 대상 선택 드롭다운 (resource_id, resource_name, resource_type)
--       - 서브넷 신청의 VPC 드롭다운 (raw_data->>'VpcId')
--       - 대시보드 리소스 통계 (resource_type, resource_id, collected_at)
--
-- 조치: 위 화면들에 실제로 필요한 컬럼만 노출하는 뷰를 만들고, 원본 테이블은 관리자 전용으로 잠근다.
--       raw_data 자체는 뷰에 넣지 않고, 거기서 VpcId만 뽑아 vpc_id 컬럼으로 제공한다.

create or replace view aws_resource_options as
select
  resource_type,
  resource_id,
  resource_name,
  collected_at,
  -- 서브넷 신청 VPC 드롭다운용. raw_data 전체가 아니라 이 값 하나만 내보낸다.
  raw_data ->> 'VpcId' as vpc_id
from aws_resource_snapshots;

-- 뷰는 security_invoker를 켜지 않으므로 소유자(postgres) 권한으로 실행된다.
-- 즉 아래에서 원본 테이블을 잠가도 이 뷰를 통한 조회는 계속 동작한다. 의도된 통로다.
grant select on aws_resource_options to authenticated;

-- ---- 원본 테이블 잠금 ----
alter table aws_resource_snapshots enable row level security;

do $$
declare p record;
begin
  for p in select policyname from pg_policies
           where schemaname = 'public' and tablename = 'aws_resource_snapshots'
  loop
    execute format('drop policy if exists %I on public.aws_resource_snapshots', p.policyname);
  end loop;
end $$;

-- 관리자만 원본 조회 가능 ('AWS 현황' 페이지가 이 경로를 쓴다).
-- 쓰기 정책은 만들지 않는다 — 수집은 aws-collect가 service_role로 하므로 RLS를 우회한다.
create policy "admin can select aws_resource_snapshots"
  on aws_resource_snapshots for select to authenticated
  using (is_admin());
