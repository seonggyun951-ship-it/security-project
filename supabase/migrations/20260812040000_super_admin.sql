-- 최고 관리자 등급 추가
--
-- 배경: 지금까지 관리자 지정은 DB에 직접 행을 넣는 방법뿐이라, 계정을 추가할 때마다
--       수작업이 필요했다. 화면에서 관리할 수 있도록 등급을 나눈다.
--
--   일반 관리자 (is_super = false) : 신청 승인/거부
--   최고 관리자 (is_super = true)  : 위 + 계정 생성/삭제, 관리자 권한 부여/회수
--
-- 계정 생성과 권한 변경은 service_role이 필요하므로 admin-users Edge Function을 통해서만 한다.
-- (브라우저에 service key를 둘 수 없다)

alter table admins add column if not exists is_super boolean not null default false;

-- 첫 최고 관리자 지정. 이 계정이 나머지를 전부 통제한다.
update admins set is_super = true where email = 'han@g.com';

-- RLS 정책은 그대로 둔다: 본인 행만 select 가능.
-- 프론트는 이 행을 읽어 관리자/최고 관리자 여부를 판단한다.
comment on column admins.is_super is
  '최고 관리자. 계정 생성/삭제와 관리자 권한 부여/회수 가능. admin-users 함수에서 검사한다.';
