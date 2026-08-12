-- 삭제 신청 + 2단계 승인
--
-- 삭제는 되돌릴 수 없으므로 반드시 최고 관리자 승인을 거친다.
--
--   신청 → 일반 관리자 승인 → awaiting_super → 최고 관리자 승인 → 적용
--   신청 → 최고 관리자 승인 ─────────────────────────────────→ 적용
--
-- 일반 관리자가 승인해도 실제 AWS 작업은 일어나지 않고 상태만 넘어간다.
-- 최종 차단은 aws-request-apply Edge Function이 한다(화면만 막으면 API 직접 호출로 뚫림).

-- 1차 승인자 기록 (감사용). 누가 먼저 검토했는지 남아야 2단계 승인이 의미가 있다.
alter table aws_requests add column if not exists first_approver_id    uuid;
alter table aws_requests add column if not exists first_approver_email text;
alter table aws_requests add column if not exists first_approved_at    timestamptz;

comment on column aws_requests.first_approver_id is
  '삭제 신청의 1차 승인자(일반 관리자). 최고 관리자가 단독 승인한 경우 null.';

-- status에 'awaiting_super'가 추가된다. 기존 제약이 없으므로 별도 변경은 필요 없다.
-- pending | awaiting_super | approved | applied | rejected | failed
