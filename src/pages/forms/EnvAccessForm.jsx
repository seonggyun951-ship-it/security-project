import { useState } from 'react'
import { ENVIRONMENTS, envMeta } from '../../lib/aws'

// 만료를 두면 배치(expire-access)가 하루 한 번 돌면서 그룹에서 빼준다.
// 쓰고 나서 회수 신청을 잊어버리는 일이 잦아, 기본값을 '1주'로 둔다.
const EXPIRY_OPTIONS = [
  { value: '1', label: '1일' },
  { value: '3', label: '3일' },
  { value: '7', label: '1주' },
  { value: '30', label: '1개월' },
  { value: '90', label: '3개월' },
  { value: '', label: '만료 없음 (영구)' },
]

// 환경 접근 권한 부여/회수.
//
// 승인되면 Edge Function이 IAM 그룹(env-dev 등)에 사용자를 넣거나 뺀다.
// 그룹에 들어가면 그 환경의 역할을 맡아 1시간짜리 임시 자격증명을 받는다.
// 영구 키를 사람마다 만들어 주지 않아도 되는 것이 이 방식의 요점이다.
//
// 대상은 수집해 둔 IAM 사용자 목록에서 고른다. 손으로 적으면 오타가 나도
// 승인이 끝난 뒤 적용 단계에서야 실패한다.
export function EnvAccessForm({ userOptions = [], optionsError, onSubmit, submitting }) {
  const [form, setForm] = useState({
    mode: 'grant',
    user_name: '',
    environment: 'dev',
    expires_in_days: '7',
    reason: '',
  })

  const reset = () => setForm({ mode: 'grant', user_name: '', environment: 'dev', expires_in_days: '7', reason: '' })

  const env = envMeta(form.environment)
  const granting = form.mode === 'grant'
  const selected = userOptions.find((u) => u.resource_name === form.user_name)
  const currentGroups = selected?.env_groups || ''
  const alreadyHas = currentGroups.split(',').map((s) => s.trim()).includes(`env-${form.environment}`)

  const submit = async () => {
    if (!form.user_name) return alert('대상 IAM 사용자를 선택해주세요')
    if (!form.reason.trim()) return alert('신청 사유는 필수입니다')

    // 회수 신청에는 만료가 의미 없다 (이미 빼는 작업이므로).
    const expiresAt = granting && form.expires_in_days
      ? new Date(Date.now() + Number(form.expires_in_days) * 86400000).toISOString()
      : null

    const ok = await onSubmit({
      resource_type: 'env_access',
      action: granting ? 'grant_env_access' : 'revoke_env_access',
      title: `${form.user_name} — ${env.label}`,
      target_id: null,
      payload: {
        user_name: form.user_name,
        environment: form.environment,
        ...(expiresAt ? { expires_at: expiresAt } : {}),
      },
      reason: form.reason.trim(),
    })
    if (ok) reset()
  }

  return (
    <>
      <p className="ac-cred-note">
        이미 있는 IAM 사용자에게 환경 권한을 주거나 회수합니다.
        승인되면 해당 환경의 역할을 맡아 1시간짜리 임시 키를 받을 수 있게 됩니다.
      </p>

      {optionsError && <div className="cc-error">{optionsError}</div>}

      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">신청 종류</label>
          <select className="ac-input" value={form.mode}
            onChange={(e) => setForm({ ...form, mode: e.target.value })}>
            <option value="grant">권한 부여</option>
            <option value="revoke">권한 회수</option>
          </select>
        </div>
        <div className="ac-field">
          <label className="ac-label">대상 IAM 사용자</label>
          <select className="ac-input" value={form.user_name}
            onChange={(e) => setForm({ ...form, user_name: e.target.value })}>
            <option value="">선택하세요</option>
            {userOptions.map((u) => (
              <option key={u.resource_id} value={u.resource_name}>
                {u.resource_name}{u.env_groups ? ` — ${u.env_groups}` : ''}
              </option>
            ))}
          </select>
          {userOptions.length === 0 && (
            <p className="ac-sub" style={{ marginTop: 6, marginBottom: 0 }}>
              목록이 비어 있습니다. 관리자가 'AWS 현황'에서 리소스를 한 번 수집하면 채워집니다.
            </p>
          )}
        </div>
      </div>

      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">환경</label>
          <select className="ac-input" value={form.environment}
            onChange={(e) => setForm({ ...form, environment: e.target.value })}>
            {ENVIRONMENTS.map((x) => <option key={x.key} value={x.key}>{x.label}</option>)}
          </select>
          <p className="ac-sub" style={{ marginTop: 6, marginBottom: 0 }}>
            이 환경에서 할 수 있는 일: <strong>{env.can}</strong>
            {env.needsSuper && granting && ' · 최고 관리자 승인까지 필요합니다'}
          </p>
          {form.user_name && (
            <p className="ac-sub" style={{ marginTop: 4, marginBottom: 0 }}>
              현재 권한: <strong>{currentGroups || '없음'}</strong>
              {granting && alreadyHas && ' — 이미 가지고 있습니다'}
              {!granting && !alreadyHas && ' — 회수할 권한이 없습니다'}
            </p>
          )}
        </div>
      </div>

      {granting && (
        <div className="ac-form-row">
          <div className="ac-field">
            <label className="ac-label">사용 기간</label>
            <select className="ac-input" value={form.expires_in_days}
              onChange={(e) => setForm({ ...form, expires_in_days: e.target.value })}>
              {EXPIRY_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
            <p className="ac-sub" style={{ marginTop: 6, marginBottom: 0 }}>
              {form.expires_in_days
                ? `${form.expires_in_days}일 뒤 자동으로 회수됩니다. 더 쓰려면 그때 다시 신청하면 됩니다.`
                : '직접 회수 신청을 하기 전까지 계속 유지됩니다.'}
            </p>
          </div>
        </div>
      )}

      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">신청 사유</label>
          <input className="ac-input"
            placeholder={granting ? '예: 개발 환경에서 테스트 서버 구성 필요' : '예: 프로젝트 종료로 권한 정리'}
            value={form.reason}
            onChange={(e) => setForm({ ...form, reason: e.target.value })} />
        </div>
      </div>

      <button className="ac-btn" onClick={submit} disabled={submitting}>
        {submitting ? '신청 중...' : granting ? '권한 부여 신청' : '권한 회수 신청'}
      </button>
    </>
  )
}
