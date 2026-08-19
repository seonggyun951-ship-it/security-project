-- 점검 결과를 잠시 목록에서 내리는 두 가지 방법.
--
--   보류(defer)     나중에 조치한다. 기한이 지나면 다시 조치 필요로 돌아온다.
--   예외(exception) 조치하지 않기로 한다. 바꿀 수 없거나 감수하는 항목.
--
-- 예외에도 기한을 둔다. 영구 예외는 결국 잊히고, 1년 뒤에는 상황이 달라져 있을 수 있다.
-- 최대 1년으로 제한하고 지나면 다시 목록에 올라오게 한다.
--
-- 앞서 만든 muted_* 컬럼을 이 구조로 바꾼다. 아직 기각한 항목이 없어 옮길 데이터는 없다.

alter table scan_findings
  add column if not exists hold_kind text check (hold_kind in ('defer', 'exception')),
  add column if not exists hold_until timestamptz,
  add column if not exists hold_reason text,
  add column if not exists hold_by text,
  add column if not exists hold_at timestamptz;

-- 이전 이름은 쓰지 않는다. 아직 데이터가 없으므로 그냥 지운다.
alter table scan_findings
  drop column if exists muted_reason,
  drop column if exists muted_by,
  drop column if exists muted_at;

drop index if exists scan_findings_muted_idx;

-- 목록은 "지금 유효한 보류·예외"만 걸러야 한다. 기한이 지난 것은 다시 조치 필요다.
create index if not exists scan_findings_hold_idx
  on scan_findings (hold_until)
  where resolved_at is null and hold_kind is not null;

comment on column scan_findings.hold_kind is
  'defer=나중에 조치, exception=조치하지 않음. 둘 다 hold_until이 지나면 다시 목록에 올라온다.';

/* ─── 보류·예외 처리 ─────────────────────────────── */

drop function if exists mute_finding(uuid, text);
drop function if exists unmute_finding(uuid);

create or replace function hold_finding(
  finding_id uuid,
  kind text,
  days int,
  reason text
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  is_admin boolean;
  max_days int;
begin
  select exists (select 1 from admins a where a.user_id = auth.uid()) into is_admin;
  if not is_admin then
    raise exception '관리자만 처리할 수 있습니다';
  end if;
  if kind not in ('defer', 'exception') then
    raise exception '알 수 없는 종류입니다: %', kind;
  end if;
  if reason is null or btrim(reason) = '' then
    raise exception '사유가 필요합니다';
  end if;

  -- 보류는 최대 3개월, 예외는 최대 1년.
  -- 보류가 길어지면 사실상 예외이므로 그때는 예외로 등록하게 한다.
  max_days := case when kind = 'defer' then 92 else 365 end;
  if days is null or days < 1 or days > max_days then
    raise exception '기간은 1일에서 %일 사이여야 합니다', max_days;
  end if;

  update scan_findings
  set hold_kind = kind,
      hold_until = now() + (days || ' days')::interval,
      hold_reason = btrim(reason),
      hold_by = (select email from auth.users where id = auth.uid()),
      hold_at = now()
  where id = finding_id;

  return found;
end;
$$;

create or replace function release_finding(finding_id uuid)
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
  set hold_kind = null, hold_until = null, hold_reason = null, hold_by = null, hold_at = null
  where id = finding_id;

  return found;
end;
$$;

grant execute on function hold_finding to authenticated;
grant execute on function release_finding to authenticated;

comment on function hold_finding is
  '점검 결과를 보류(defer, 최대 92일)하거나 예외(exception, 최대 365일)로 둔다. 기한이 지나면 다시 목록에 올라온다.';
