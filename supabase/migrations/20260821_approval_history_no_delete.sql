-- 승인 이력은 감사 자료다. 앱에서 지우는 경로를 없앤다.
--
-- 화면의 삭제 버튼을 걷어내는 것만으로는 부족하다. RLS에 DELETE 정책이 남아 있으면
-- 관리자 계정으로 API를 직접 호출해 지울 수 있다. 정책 자체를 내린다.
-- (신청 취소는 status를 'cancelled'로 바꾸는 것이라 행이 남는다 — 그건 그대로 둔다)

drop policy if exists "admin can delete aws_requests" on public.aws_requests;
drop policy if exists "admin can delete gcp_requests" on public.gcp_requests;

-- 달력용 날짜별 건수.
--
-- 목록은 최근 N건만 가져오는데 달력이 그 배열을 세면, 오래된 날짜는 "그날 아무 일도
-- 없었다"처럼 비어 보인다. 건수는 목록과 무관하게 DB에서 전 기간을 세어 온다.
--
-- 날짜 경계는 KST 기준. timestamptz를 그냥 ::date로 자르면 UTC 기준이라
-- 한국 시간 오전 9시 이전 건이 전날로 밀린다 (화면의 localDateKey와 어긋난다).
create or replace function public.aws_request_day_counts()
returns table (day date, n bigint, bad bigint)
language sql
stable
as $$
  select (requested_at at time zone 'Asia/Seoul')::date as day,
         count(*) as n,
         count(*) filter (where status in ('failed', 'rejected')) as bad
  from public.aws_requests
  where status in ('applied', 'rejected', 'failed', 'cancelled')
  group by 1
$$;
