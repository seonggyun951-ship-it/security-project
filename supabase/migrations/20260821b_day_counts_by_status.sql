-- 날짜별 건수를 상태까지 나눠서 돌려준다.
--
-- 주별·월별 화면이 "이 주에 12건, 적용 8 · 거절 3 · 실패 1"을 보여주려면 상태 구분이
-- 필요하다. 그렇다고 주·월 단위 함수를 따로 만들지는 않는다 — 일 단위 하나만 있으면
-- 주·월·전체는 화면에서 묶으면 되고, 주 시작 요일 같은 규칙이 SQL과 화면 두 곳에
-- 나뉘어 어긋나는 일도 없다.
--
-- 날짜 경계는 KST. timestamptz를 그냥 ::date로 자르면 UTC 기준이라 한국 시간
-- 오전 9시 이전 건이 전날로 밀린다 (화면의 localDateKey와 어긋난다).
-- 반환 칼럼이 바뀌므로 create or replace로는 안 된다 (Postgres가 거부한다).
drop function if exists public.aws_request_day_counts();

create function public.aws_request_day_counts()
returns table (
  day date,
  n bigint,
  bad bigint,
  applied bigint,
  rejected bigint,
  failed bigint,
  cancelled bigint
)
language sql
stable
as $$
  select (requested_at at time zone 'Asia/Seoul')::date as day,
         count(*)                                          as n,
         count(*) filter (where status in ('failed', 'rejected')) as bad,
         count(*) filter (where status = 'applied')        as applied,
         count(*) filter (where status = 'rejected')       as rejected,
         count(*) filter (where status = 'failed')         as failed,
         count(*) filter (where status = 'cancelled')      as cancelled
  from public.aws_requests
  where status in ('applied', 'rejected', 'failed', 'cancelled')
  group by 1
$$;
