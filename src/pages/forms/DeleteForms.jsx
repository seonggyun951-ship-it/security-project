import { useState, useEffect } from 'react'
import { supabase } from '../../lib/supabase'
import { fetchRows } from '../../lib/db'
import { sgRuleLabel, wafRuleLabel } from '../../lib/aws'

// 삭제 신청 폼.
//
// 신청 대상은 "이 앱으로 적용했던 신청"에서 고른다. 직접 리소스를 훑어 고르는 방식이 아니다.
//   - 무엇을 지울지가 원본 payload로 정확히 특정된다 (규칙 내용까지 그대로)
//   - raw_data(관리자 전용 스냅샷)를 신청자에게 열지 않아도 된다
//   - 원본 신청과 이어져 감사 추적이 된다
// RLS상 신청자는 본인 신청만, 관리자는 전체가 보인다.

// 이미 삭제가 진행 중이거나 끝난 대상은 다시 신청할 수 없어야 한다.
// 실패·거부된 삭제 신청은 다시 시도할 수 있어야 하므로 여기 포함하지 않는다.
const BLOCKING = ['pending', 'awaiting_super', 'approved', 'applied']

// 삭제 신청 대상 목록 = 적용 완료된 생성 신청 중, 아직 삭제가 걸려 있지 않은 것
function useDeletableRequests(resourceType, createActions, deleteAction) {
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const key = createActions.join(',')

  const load = async () => {
    setLoading(true)
    const [applied, deletes] = await Promise.all([
      fetchRows(
        supabase.from('aws_requests')
          .select('id, title, action, payload, result, requested_at, requester_email')
          .eq('resource_type', resourceType)
          .in('action', createActions)
          .eq('status', 'applied')
          .order('requested_at', { ascending: false }).limit(100),
        '적용된 신청 목록'),
      fetchRows(
        supabase.from('aws_requests')
          .select('payload, status')
          .eq('action', deleteAction)
          .in('status', BLOCKING).limit(200),
        '삭제 신청 목록'),
    ])

    // 이미 삭제 신청이 걸린 원본은 후보에서 뺀다 (중복 신청 방지)
    const taken = new Set(
      deletes.rows.map((d) => d.payload?.source_request_id).filter(Boolean)
    )
    setRows(applied.rows.filter((r) => !taken.has(r.id)))
    setError(applied.error || deletes.error)
    setLoading(false)
  }

  useEffect(() => {
    let alive = true
    load().catch(() => { if (alive) setLoading(false) })
    return () => { alive = false }
  }, [resourceType, key, deleteAction])

  return { rows, loading, error, reload: load }
}

const whenLabel = (r) =>
  `${new Date(r.requested_at).toLocaleDateString('ko-KR')}${r.requester_email ? ` · ${r.requester_email}` : ''}`

// ---- IAM 계정 삭제 ----
export function IamDeleteForm({ onSubmit, submitting }) {
  const { rows, loading, error, reload } = useDeletableRequests('iam_user', ['create_readonly_user'], 'delete_iam_user')
  const [targetId, setTargetId] = useState('')
  const [reason, setReason] = useState('')

  const target = rows.find((r) => r.id === targetId)

  const submit = async () => {
    if (!target) return alert('삭제할 계정을 선택해주세요')
    if (!reason.trim()) return alert('삭제 사유는 필수입니다')
    const userName = target.payload?.user_name
    if (!userName) return alert('원본 신청에 계정 이름이 없습니다')
    if (!confirm(`${userName} 계정을 삭제 신청합니다.\n액세스 키와 정책도 함께 제거됩니다.\n\n계속할까요?`)) return

    const ok = await onSubmit({
      resource_type: 'iam_user', action: 'delete_iam_user',
      title: userName, target_id: null,
      payload: { user_name: userName, source_request_id: target.id },
      reason: reason.trim(),
    })
    if (ok) { setTargetId(''); setReason(''); await reload() }
  }

  return (
    <>
      <p className="ac-cred-note">
        이 앱으로 발급했던 읽기 전용 계정을 삭제 신청합니다.
        연결된 액세스 키와 정책이 함께 제거되며, <b>최고 관리자 승인이 있어야 실제로 삭제됩니다.</b>
      </p>
      {error && <div className="ac-req-error">{error}</div>}
      {!loading && rows.length === 0 && <div className="ac-empty">삭제할 수 있는 계정이 없습니다.</div>}

      {rows.length > 0 && (
        <>
          <div className="ac-form-row">
            <div className="ac-field">
              <label className="ac-label">삭제할 계정</label>
              <select className="ac-input" value={targetId} onChange={(e) => setTargetId(e.target.value)}>
                <option value="">선택...</option>
                {rows.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.payload?.user_name} — {whenLabel(r)}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="ac-form-row">
            <div className="ac-field">
              <label className="ac-label">삭제 사유 (필수)</label>
              <input className="ac-input" placeholder="예: 프로젝트 종료로 계정 회수" value={reason} onChange={(e) => setReason(e.target.value)} />
            </div>
          </div>
          <button className="ac-btn ac-btn-danger" onClick={submit} disabled={submitting}>
            {submitting ? '신청 중...' : '삭제 신청'}
          </button>
        </>
      )}
    </>
  )
}

// ---- SG 규칙 삭제 ----
export function SgDeleteForm({ onSubmit, submitting }) {
  const { rows, loading, error, reload } = useDeletableRequests('security_group', ['create_sg', 'add_rules'], 'delete_sg_rules')
  const [targetId, setTargetId] = useState('')
  const [picked, setPicked] = useState([]) // 선택된 규칙 index
  const [reason, setReason] = useState('')

  const target = rows.find((r) => r.id === targetId)
  const rules = target?.payload?.rules || []

  const toggle = (i) => setPicked((prev) => prev.includes(i) ? prev.filter((x) => x !== i) : [...prev, i])
  const chooseTarget = (id) => { setTargetId(id); setPicked([]) }

  const submit = async () => {
    if (!target) return alert('대상 신청을 선택해주세요')
    if (picked.length === 0) return alert('삭제할 규칙을 최소 1개 선택해주세요')
    if (!reason.trim()) return alert('삭제 사유는 필수입니다')

    // 원본 신청에 기록된 SG를 그대로 쓴다. 신청 종류마다 저장 위치가 다르다.
    //   add_rules  → target_id (기존 SG를 고른 것)
    //   create_sg  → result.created_id (새로 만들어진 SG)
    // payload.sg_id는 예전 형식이라 마지막에 본다.
    const sgId = target.target_id || target.result?.created_id || target.payload?.sg_id
    if (!sgId) return alert('원본 신청에서 대상 SG를 찾을 수 없습니다')

    const chosen = picked.map((i) => rules[i]).filter(Boolean)
    const ok = await onSubmit({
      resource_type: 'security_group', action: 'delete_sg_rules',
      title: target.payload?.sg_name || sgId,
      target_id: sgId,
      payload: {
        sg_id: sgId, sg_name: target.payload?.sg_name || null,
        rules: chosen, source_request_id: target.id,
      },
      reason: reason.trim(),
    })
    if (ok) { setTargetId(''); setPicked([]); setReason(''); await reload() }
  }

  return (
    <>
      <p className="ac-cred-note">
        이 앱으로 추가했던 SG 규칙을 제거 신청합니다. 규칙을 빼는 것은 접근을 좁히는 방향이지만,
        <b> 최고 관리자 승인이 있어야 실제로 적용됩니다.</b>
      </p>
      {error && <div className="ac-req-error">{error}</div>}
      {!loading && rows.length === 0 && <div className="ac-empty">제거할 수 있는 규칙이 없습니다.</div>}

      {rows.length > 0 && (
        <>
          <div className="ac-form-row">
            <div className="ac-field">
              <label className="ac-label">대상 신청</label>
              <select className="ac-input" value={targetId} onChange={(e) => chooseTarget(e.target.value)}>
                <option value="">선택...</option>
                {rows.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.title || r.payload?.sg_name || r.payload?.sg_id} — {whenLabel(r)}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {target && (
            <>
              <div className="ac-card-title" style={{ fontSize: 13, marginTop: 16 }}>제거할 규칙 선택</div>
              {rules.length === 0 && <div className="ac-empty">이 신청에는 규칙이 없습니다.</div>}
              <div className="ac-check-list">
                {rules.map((rule, i) => (
                  <label key={i} className={`ac-check ${picked.includes(i) ? 'active' : ''}`}>
                    <input type="checkbox" checked={picked.includes(i)} onChange={() => toggle(i)} />
                    <span>{sgRuleLabel(rule)}</span>
                  </label>
                ))}
              </div>
            </>
          )}

          <div className="ac-form-row" style={{ marginTop: 12 }}>
            <div className="ac-field">
              <label className="ac-label">삭제 사유 (필수)</label>
              <input className="ac-input" placeholder="예: 임시 개방 기간 종료" value={reason} onChange={(e) => setReason(e.target.value)} />
            </div>
          </div>
          <button className="ac-btn ac-btn-danger" onClick={submit} disabled={submitting}>
            {submitting ? '신청 중...' : '삭제 신청'}
          </button>
        </>
      )}
    </>
  )
}

// ---- WAF 규칙 삭제 ----
export function WafDeleteForm({ onSubmit, submitting }) {
  const { rows, loading, error, reload } = useDeletableRequests('waf_web_acl', ['add_waf_rules'], 'delete_waf_rules')
  const [targetId, setTargetId] = useState('')
  const [picked, setPicked] = useState([]) // 선택된 규칙 이름
  const [reason, setReason] = useState('')

  const target = rows.find((r) => r.id === targetId)
  const rules = target?.payload?.rules || []

  const toggle = (name) => setPicked((prev) => prev.includes(name) ? prev.filter((n) => n !== name) : [...prev, name])
  const chooseTarget = (id) => { setTargetId(id); setPicked([]) }

  const submit = async () => {
    if (!target) return alert('대상 신청을 선택해주세요')
    if (picked.length === 0) return alert('삭제할 규칙을 최소 1개 선택해주세요')
    if (!reason.trim()) return alert('삭제 사유는 필수입니다')

    const aclId = target.result?.web_acl_id || target.target_id
    const aclName = target.payload?.web_acl_name || target.title
    if (!aclId || !aclName) return alert('원본 신청에서 대상 Web ACL을 찾을 수 없습니다')

    if (!confirm(`차단 규칙 ${picked.length}개를 제거합니다.\n해당 요청이 더 이상 차단되지 않습니다.\n\n계속할까요?`)) return

    const ok = await onSubmit({
      resource_type: 'waf_web_acl', action: 'delete_waf_rules',
      title: aclName,
      target_id: aclId,
      payload: {
        web_acl_id: aclId, web_acl_name: aclName,
        scope: target.payload?.scope || 'REGIONAL',
        rule_names: picked, source_request_id: target.id,
      },
      reason: reason.trim(),
    })
    if (ok) { setTargetId(''); setPicked([]); setReason(''); await reload() }
  }

  return (
    <>
      <p className="ac-cred-note">
        이 앱으로 추가했던 WAF 차단 규칙을 제거 신청합니다.
        <b> 차단을 푸는 방향이라 보안이 느슨해지며, 최고 관리자 승인이 있어야 적용됩니다.</b>
      </p>
      {error && <div className="ac-req-error">{error}</div>}
      {!loading && rows.length === 0 && <div className="ac-empty">제거할 수 있는 규칙이 없습니다.</div>}

      {rows.length > 0 && (
        <>
          <div className="ac-form-row">
            <div className="ac-field">
              <label className="ac-label">대상 신청</label>
              <select className="ac-input" value={targetId} onChange={(e) => chooseTarget(e.target.value)}>
                <option value="">선택...</option>
                {rows.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.payload?.web_acl_name || r.title} — {whenLabel(r)}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {target && (
            <>
              <div className="ac-card-title" style={{ fontSize: 13, marginTop: 16 }}>제거할 규칙 선택</div>
              {rules.length === 0 && <div className="ac-empty">이 신청에는 규칙이 없습니다.</div>}
              <div className="ac-check-list">
                {rules.map((rule) => (
                  <label key={rule.name} className={`ac-check ${picked.includes(rule.name) ? 'active' : ''}`}>
                    <input type="checkbox" checked={picked.includes(rule.name)} onChange={() => toggle(rule.name)} />
                    <span>{wafRuleLabel(rule)}</span>
                  </label>
                ))}
              </div>
            </>
          )}

          <div className="ac-form-row" style={{ marginTop: 12 }}>
            <div className="ac-field">
              <label className="ac-label">삭제 사유 (필수)</label>
              <input className="ac-input" placeholder="예: 오탐으로 정상 트래픽이 차단됨" value={reason} onChange={(e) => setReason(e.target.value)} />
            </div>
          </div>
          <button className="ac-btn ac-btn-danger" onClick={submit} disabled={submitting}>
            {submitting ? '신청 중...' : '삭제 신청'}
          </button>
        </>
      )}
    </>
  )
}
