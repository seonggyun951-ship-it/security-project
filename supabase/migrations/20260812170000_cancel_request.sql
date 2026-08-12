-- 신청자 본인의 신청 취소
--
-- update 정책이 관리자 전용이라 신청자는 자기 신청도 손댈 수 없었다.
-- 아직 실행되지 않은 신청(pending, awaiting_super)은 본인이 거둬들일 수 있어야 한다.
--
-- 정책은 여러 개가 OR로 평가되므로 기존 관리자 정책은 그대로 두고 하나 더 추가한다.
--   using      = 바꾸기 전 행 조건 (본인 신청이고 아직 처리 전)
--   with check = 바꾼 뒤 행 조건 (cancelled 로만 바꿀 수 있음)

drop policy if exists "requester can cancel own request" on aws_requests;
create policy "requester can cancel own request"
  on aws_requests for update to authenticated
  using (requester_id = auth.uid() and status in ('pending', 'awaiting_super'))
  with check (requester_id = auth.uid() and status = 'cancelled');

drop policy if exists "requester can cancel own gcp request" on gcp_requests;
create policy "requester can cancel own gcp request"
  on gcp_requests for update to authenticated
  using (requester_id = auth.uid() and status in ('pending', 'awaiting_super'))
  with check (requester_id = auth.uid() and status = 'cancelled');

-- status: pending | awaiting_super | approved | applied | rejected | failed | cancelled
--
-- 취소된 삭제 신청은 대상을 다시 신청할 수 있어야 하므로,
-- 프론트의 중복 방지 목록(BLOCKING)에는 cancelled를 넣지 않는다.
