-- 점검 결과 기각(mute).
--
-- 기본 VPC의 NACL처럼 바꿀 수 없거나 감수하기로 한 항목이 매일 목록에 뜨면
-- 진짜 봐야 할 것이 묻힌다. 사유를 남기고 닫아두되 목록에서 지우지는 않는다 —
-- 누가 왜 넘겼는지가 남아야 나중에 다시 판단할 수 있다.
--
-- 컬럼(muted_reason, muted_by, muted_at)은 이미 있고, 여기서는 그것을 쓰는 함수만 만든다.
-- 클라이언트가 테이블을 직접 수정하지 못하게 두고(쓰기 정책 없음) 이 함수로만 처리한다.

create or replace function mute_finding(
  finding_id uuid,
  reason text
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  is_admin boolean;
begin
  select exists (select 1 from admins a where a.user_id = auth.uid()) into is_admin;
  if not is_admin then
    raise exception '관리자만 기각할 수 있습니다';
  end if;
  if reason is null or btrim(reason) = '' then
    raise exception '기각 사유가 필요합니다';
  end if;

  update scan_findings
  set muted_reason = btrim(reason),
      muted_by = (select email from auth.users where id = auth.uid()),
      muted_at = now()
  where id = finding_id;

  return found;
end;
$$;

create or replace function unmute_finding(finding_id uuid)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  is_admin boolean;
begin
  select exists (select 1 from admins a where a.user_id = auth.uid()) into is_admin;
  if not is_admin then
    raise exception '관리자만 되돌릴 수 있습니다';
  end if;

  update scan_findings
  set muted_reason = null, muted_by = null, muted_at = null
  where id = finding_id;

  return found;
end;
$$;

grant execute on function mute_finding to authenticated;
grant execute on function unmute_finding to authenticated;

-- 기각된 것은 목록에서 아래로 내려가므로 조회 시 자주 걸린다.
create index if not exists scan_findings_muted_idx
  on scan_findings (muted_at)
  where resolved_at is null;

comment on function mute_finding is
  '점검 결과를 사유와 함께 기각한다. 목록에서 지우지 않고 흐리게 남겨 누가 왜 넘겼는지 보이게 한다.';
