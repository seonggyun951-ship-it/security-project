import { useState, useEffect } from 'react'
import { supabase } from '../../lib/supabase'
import { fetchRows } from '../../lib/db'
import { sgRuleLabel, wafRuleLabel } from '../../lib/aws'
import ResourcePicker from '../../components/ResourcePicker'

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
          // target_id는 add_rules 신청의 대상 SG, add_waf_rules의 대상 ACL이 들어있다.
          // 빠뜨리면 삭제 신청이 대상을 못 찾는다.
          .select('id, title, action, target_id, payload, result, requested_at, requester_email')
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

    // 이미 삭제 신청이 걸린 원본은 후보에서 뺀다 (중복 신청 방지).
    // 대상으로 묶어 고르게 되면서 삭제 신청 하나가 원본 여러 건을 가리킬 수 있다.
    // 예전 형식(단수)도 함께 본다 — 그때 만들어진 행이 남아 있다.
    const taken = new Set(
      deletes.rows.flatMap((d) => [
        ...(d.payload?.source_request_ids || []),
        d.payload?.source_request_id,
      ]).filter(Boolean)
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

/**
 * 신청들을 '대상 리소스' 기준으로 묶는다.
 *
 * 원래는 신청 하나가 곧 한 줄이었다. 같은 SG에 세 번 신청했으면 세 줄이 뜨고,
 * 신청자는 어느 줄에 무슨 규칙이 들었는지 기억해야 골랐다.
 * 실제로 고르고 싶은 것은 "이 SG의 이 규칙"이지 "몇 월 며칠 신청"이 아니다.
 *
 * 그래서 대상으로 묶고, 그 안에 여러 신청의 규칙을 모두 늘어놓는다.
 * 규칙마다 어느 신청에서 왔는지는 들고 다닌다 — 지울 때 원본을 되짚어야 한다.
 */
function groupByTarget(rows, { idOf, nameOf, rulesOf }) {
  const map = new Map()
  for (const r of rows) {
    const id = idOf(r)
    if (!id) continue
    if (!map.has(id)) map.set(id, { id, name: nameOf(r) || id, items: [] })
    const g = map.get(id)
    if (!g.name || g.name === id) g.name = nameOf(r) || g.name
    for (const rule of rulesOf(r)) {
      g.items.push({ rule, from: r })
    }
  }
  return [...map.values()].filter((g) => g.items.length > 0)
}

/** 묶음을 ResourcePicker가 받는 모양으로 */
const toPickerRows = (groups, unit) => groups.map((g) => ({
  resource_id: g.id,
  resource_name: g.name,
  // 대상 식별자를 아래 줄에 보여준다. 이름이 겹칠 때 이걸로 가른다.
  env_groups: g.id !== g.name ? g.id : '',
  meta: `${unit} ${g.items.length}개`,
}))

// ---- IAM 계정 삭제 ----
export function IamDeleteForm({ accountId = '', onSubmit, submitting }) {
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
              {/* IAM 계정은 하나가 곧 하나라 묶을 게 없다. 신청 그대로 목록에 낸다. */}
              <ResourcePicker label="계정" accountId={accountId}
                options={rows.map((r) => ({
                  resource_id: r.id,
                  resource_name: r.payload?.user_name || r.title,
                  env_groups: whenLabel(r),
                }))}
                value={targetId} onChange={(id) => setTargetId(id)}
                emptyHint="삭제할 수 있는 계정이 없습니다." />
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
export function SgDeleteForm({ prefill, accountId = '', onSubmit, submitting }) {
  const { rows, loading, error, reload } = useDeletableRequests('security_group', ['create_sg', 'add_rules'], 'delete_sg_rules')
  const [targetId, setTargetId] = useState('')
  const [picked, setPicked] = useState([]) // 선택된 규칙 index
  const [reason, setReason] = useState(prefill?.reason || '')

  // 점검 결과에서 넘어온 경우는 다른 길로 간다.
  //
  // 평소에는 "이 앱으로 신청했던 규칙"만 고를 수 있다. 무엇을 지우는지가 원본 신청에
  // 기록돼 있어 확실하기 때문이다. 그런데 점검에 걸리는 SG는 콘솔에서 직접 만든 것이
  // 대부분이라 원본 신청이 없다 — 그러면 고칠 방법이 아예 없어진다.
  // 이 경우에만 대상과 규칙을 직접 지정해 신청한다. Edge Function은 sg_id와 규칙만
  // 있으면 처리하므로 뒤쪽은 손댈 게 없다.
  const fromScan = prefill?.check_id ? prefill : null

  const submitFromScan = async () => {
    if (!reason.trim()) return alert('삭제 사유는 필수입니다')
    const ok = await onSubmit({
      resource_type: 'security_group', action: 'delete_sg_rules',
      title: fromScan.sg_id,
      target_id: fromScan.sg_id,
      payload: {
        sg_id: fromScan.sg_id,
        rules: fromScan.rules,
        // 어느 점검에서 온 신청인지 남긴다. 승인자가 근거를 확인할 수 있어야 한다.
        source_check_id: fromScan.check_id,
      },
      reason: reason.trim(),
    })
    if (ok) setReason('')
  }

  // 신청 단위가 아니라 SG 단위로 묶는다. 같은 SG에 세 번 신청했으면
  // 세 줄이 아니라 한 줄이고, 그 안에 규칙이 다 모여 있다.
  //
  // SG를 어디서 읽는지는 신청 종류마다 다르다.
  //   add_rules  → target_id (기존 SG를 고른 것)
  //   create_sg  → result.created_id (새로 만들어진 SG)
  // payload.sg_id는 예전 형식이라 마지막에 본다.
  const groups = groupByTarget(rows, {
    idOf: (r) => r.target_id || r.result?.created_id || r.payload?.sg_id,
    nameOf: (r) => r.payload?.sg_name,
    rulesOf: (r) => r.payload?.rules || [],
  })
  const target = groups.find((g) => g.id === targetId)
  const rules = target?.items || []

  const toggle = (i) => setPicked((prev) => prev.includes(i) ? prev.filter((x) => x !== i) : [...prev, i])
  const chooseTarget = (id) => { setTargetId(id); setPicked([]) }

  const submit = async () => {
    if (!target) return alert('대상 Security Group을 선택해주세요')
    if (picked.length === 0) return alert('삭제할 규칙을 최소 1개 선택해주세요')
    if (!reason.trim()) return alert('삭제 사유는 필수입니다')

    const chosen = picked.map((i) => rules[i]).filter(Boolean)
    // 고른 규칙이 여러 신청에 걸쳐 있을 수 있다. 원본을 모두 남긴다 —
    // 중복 신청을 막는 데 쓰이고, 나중에 감사할 때 근거가 된다.
    const sources = [...new Set(chosen.map((c) => c.from.id))]
    const ok = await onSubmit({
      resource_type: 'security_group', action: 'delete_sg_rules',
      title: target.name,
      target_id: target.id,
      payload: {
        sg_id: target.id, sg_name: target.name,
        rules: chosen.map((c) => c.rule),
        source_request_ids: sources,
        // 예전 형식도 함께 남긴다. 이 값만 보는 코드가 아직 있다.
        source_request_id: sources[0],
      },
      reason: reason.trim(),
    })
    if (ok) { setTargetId(''); setPicked([]); setReason(''); await reload() }
  }

  if (fromScan) {
    return (
      <>
        <div className="ac-note ac-note-warn">
          보안 점검 <b>{fromScan.check_id}</b>에서 걸린 규칙을 제거하는 신청입니다.
          규칙을 빼는 것은 접근을 좁히는 방향이지만 <b>최고 관리자 승인이 있어야 실제로 적용됩니다.</b>
        </div>

        <div className="ac-form-row">
          <div className="ac-field">
            <label className="ac-label">대상 Security Group</label>
            <input className="ac-input" value={fromScan.sg_id} readOnly />
          </div>
        </div>

        <div className="ac-card-title" style={{ fontSize: 13, marginTop: 16 }}>제거할 규칙</div>
        <div className="ac-check-list">
          {fromScan.rules.map((rule, i) => (
            <span key={i} className="ac-check active"><span>{sgRuleLabel(rule)}</span></span>
          ))}
        </div>

        <div className="ac-note">
          이 규칙이 실제로 그 SG에 있는지는 적용 단계에서 확인됩니다.
          이미 없는 규칙이면 실패로 보지 않고 넘어갑니다.
        </div>

        <div className="ac-form-row" style={{ marginTop: 12 }}>
          <div className="ac-field">
            <label className="ac-label">삭제 사유 (필수)</label>
            <input className="ac-input" value={reason} onChange={(e) => setReason(e.target.value)} />
          </div>
        </div>

        <button className="ac-btn ac-btn-danger" onClick={submitFromScan} disabled={submitting}>
          {submitting ? '신청 중...' : '삭제 신청'}
        </button>
      </>
    )
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
              <label className="ac-label">대상 Security Group</label>
              <ResourcePicker label="Security Group" accountId={accountId}
                options={toPickerRows(groups, '규칙')}
                value={targetId} onChange={(id) => chooseTarget(id)}
                emptyHint="제거할 수 있는 규칙이 없습니다." />
            </div>
          </div>

          {target && (
            <>
              <div className="ac-card-title" style={{ fontSize: 13, marginTop: 16 }}>
                제거할 규칙 선택
                <span className="ac-tag">{rules.length}개</span>
              </div>
              {rules.length === 0 && <div className="ac-empty">이 SG에 제거할 규칙이 없습니다.</div>}
              {/* 규칙마다 어느 신청에서 온 것인지 적는다. 여러 신청의 규칙이
                  한 자리에 모이므로, 언제 넣은 것인지가 판단 근거가 된다. */}
              <div className="ac-check-list">
                {rules.map((it, i) => (
                  <label key={i} className={`ac-check ${picked.includes(i) ? 'active' : ''}`}>
                    <input type="checkbox" checked={picked.includes(i)} onChange={() => toggle(i)} />
                    <span>
                      {sgRuleLabel(it.rule)}
                      <span className="ac-check-from">{whenLabel(it.from)}</span>
                    </span>
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
export function WafDeleteForm({ accountId = '', onSubmit, submitting }) {
  const { rows, loading, error, reload } = useDeletableRequests('waf_web_acl', ['add_waf_rules'], 'delete_waf_rules')
  const [targetId, setTargetId] = useState('')
  const [picked, setPicked] = useState([]) // 선택된 규칙 이름
  const [reason, setReason] = useState('')

  // 신청 단위가 아니라 Web ACL 단위로 묶는다. 같은 ACL에 여러 번 규칙을
  // 넣었으면 그 규칙들이 한 자리에 모여야 무엇을 뺄지 고를 수 있다.
  const groups = groupByTarget(rows, {
    idOf: (r) => r.result?.web_acl_id || r.target_id,
    nameOf: (r) => r.payload?.web_acl_name || r.title,
    rulesOf: (r) => r.payload?.rules || [],
  })
  const target = groups.find((g) => g.id === targetId)
  const rules = target?.items || []

  const toggle = (name) => setPicked((prev) => prev.includes(name) ? prev.filter((n) => n !== name) : [...prev, name])
  const chooseTarget = (id) => { setTargetId(id); setPicked([]) }

  const submit = async () => {
    if (!target) return alert('대상 Web ACL을 선택해주세요')
    if (picked.length === 0) return alert('삭제할 규칙을 최소 1개 선택해주세요')
    if (!reason.trim()) return alert('삭제 사유는 필수입니다')

    if (!confirm(`차단 규칙 ${picked.length}개를 제거합니다.\n해당 요청이 더 이상 차단되지 않습니다.\n\n계속할까요?`)) return

    // 고른 규칙이 여러 신청에 걸쳐 있을 수 있다. 원본을 모두 남긴다.
    const chosen = rules.filter((it) => picked.includes(it.rule.name))
    const sources = [...new Set(chosen.map((c) => c.from.id))]
    // scope는 신청마다 같아야 정상이지만, 첫 것을 기준으로 삼는다.
    const scope = chosen[0]?.from?.payload?.scope || 'REGIONAL'

    const ok = await onSubmit({
      resource_type: 'waf_web_acl', action: 'delete_waf_rules',
      title: target.name,
      target_id: target.id,
      payload: {
        web_acl_id: target.id, web_acl_name: target.name,
        scope,
        rule_names: picked,
        source_request_ids: sources,
        source_request_id: sources[0],
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
              <label className="ac-label">대상 Web ACL</label>
              <ResourcePicker label="Web ACL" accountId={accountId}
                options={toPickerRows(groups, '규칙')}
                value={targetId} onChange={(id) => chooseTarget(id)}
                emptyHint="제거할 수 있는 규칙이 없습니다." />
            </div>
          </div>

          {target && (
            <>
              <div className="ac-card-title" style={{ fontSize: 13, marginTop: 16 }}>
                제거할 규칙 선택
                <span className="ac-tag">{rules.length}개</span>
              </div>
              {rules.length === 0 && <div className="ac-empty">이 Web ACL에 제거할 규칙이 없습니다.</div>}
              <div className="ac-check-list">
                {rules.map((it, i) => (
                  <label key={`${it.rule.name}-${i}`} className={`ac-check ${picked.includes(it.rule.name) ? 'active' : ''}`}>
                    <input type="checkbox" checked={picked.includes(it.rule.name)} onChange={() => toggle(it.rule.name)} />
                    <span>
                      {wafRuleLabel(it.rule)}
                      <span className="ac-check-from">{whenLabel(it.from)}</span>
                    </span>
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
