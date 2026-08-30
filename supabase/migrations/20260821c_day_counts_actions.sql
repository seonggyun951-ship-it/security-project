-- 날짜별 집계에 "무엇을 했는지"까지 담는다.
--
-- 상태(적용/거절/실패)만으로는 그날 무슨 일이 있었는지 알 수 없다.
-- 액션별 건수를 jsonb로 같이 내려서, 달력에서 날짜를 눌렀을 때 목록을 조회하지 않고도
-- "SG 규칙 추가 5 · IAM 계정 생성 2"까지 보여줄 수 있게 한다.
--
-- 액션 이름을 한국어로 바꾸는 건 화면(ACTION_LABEL)이 한다. 여기서 번역하면
-- 같은 표가 두 곳에 생겨 하나만 고쳐지는 일이 생긴다.
--
-- 날짜 경계는 KST. timestamptz를 그냥 ::date로 자르면 UTC 기준이라 한국 시간
-- 오전 9시 이전 건이 전날로 밀린다.

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
  cancelled bigint,
  actions jsonb
)
language sql
stable
as $$
  with done as (
    select (requested_at at time zone 'Asia/Seoul')::date as day, status, action
    from public.aws_requests
    where status in ('applied', 'rejected', 'failed', 'cancelled')
  ),
  by_action as (
    select day, action, count(*) as c from done group by 1, 2
  )
  select d.day,
         count(*)                                                as n,
         count(*) filter (where d.status in ('failed','rejected')) as bad,
         count(*) filter (where d.status = 'applied')             as applied,
         count(*) filter (where d.status = 'rejected')            as rejected,
         count(*) filter (where d.status = 'failed')              as failed,
         count(*) filter (where d.status = 'cancelled')           as cancelled,
         (select jsonb_object_agg(a.action, a.c) from by_action a where a.day = d.day) as actions
  from done d
  group by d.day
$$;
