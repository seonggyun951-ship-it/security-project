-- 구버전 SG 신청 경로 차단
--
-- 배경: aws-sg-apply Edge Function이 이 테이블(aws_sg_requests)을 보고 실제 AWS SG에 규칙을 반영했다.
--       그 함수에는 관리자 검사도, SG 가드레일(0.0.0.0/0 차단 등)도 없어서
--       로그인만 하면 pending 행을 넣고 호출해 승인 절차를 우회할 수 있었다.
--       (일반 계정으로 insert가 되는 것까지 실제로 확인함)
--
-- 조치: 함수는 삭제(supabase functions delete aws-sg-apply)하고,
--       이 테이블은 authenticated 권한을 모두 제거해 재사용 경로를 막는다.
--       기존 4건(전부 applied)은 이력이므로 그대로 둔다 — 정책만 바꾸고 데이터는 건드리지 않는다.

-- 기존 정책 전부 제거 (이름을 모르는 정책까지 확실히 지운다)
do $$
declare p record;
begin
  for p in select policyname from pg_policies where schemaname = 'public' and tablename = 'aws_sg_requests'
  loop
    execute format('drop policy if exists %I on public.aws_sg_requests', p.policyname);
  end loop;
end $$;

alter table aws_sg_requests enable row level security;

-- 정책을 하나도 만들지 않는다 = RLS가 켜진 상태에서 authenticated/anon은 아무것도 못 한다.
-- service_role은 RLS를 우회하므로 관리/조회가 필요하면 그쪽으로 한다.

-- 앱 역할에 남아있을 수 있는 테이블 권한도 회수
revoke all on table aws_sg_requests from anon, authenticated;
