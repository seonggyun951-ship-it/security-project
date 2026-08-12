-- 신청 조회를 본인 것으로 제한
--
-- 문제: select 정책이 using (true) 라서 로그인한 사용자면 남의 신청을 전부 볼 수 있었다.
--       '내 신청 현황'이라는 이름과 달리 다른 사람의 신청 내용과 거부 사유까지 노출됐다.
--
-- 조치: 본인 신청 또는 관리자만 조회 가능하게 한다.
--       관리자는 승인 화면에서 전체를 봐야 하므로 is_admin() 조건을 함께 둔다.
--       (신청 페이지에서는 프론트가 requester_id로 한 번 더 걸러 본인 것만 보여준다)

drop policy if exists "authenticated can select aws_requests" on aws_requests;
drop policy if exists "select own or admin aws_requests" on aws_requests;
create policy "select own or admin aws_requests"
  on aws_requests for select to authenticated
  using (requester_id = auth.uid() or is_admin());

drop policy if exists "authenticated can select gcp_requests" on gcp_requests;
drop policy if exists "select own or admin gcp_requests" on gcp_requests;
create policy "select own or admin gcp_requests"
  on gcp_requests for select to authenticated
  using (requester_id = auth.uid() or is_admin());
