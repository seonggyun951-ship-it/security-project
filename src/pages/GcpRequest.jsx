import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'
import {
  GCP_PROTOCOLS, GCP_ARMOR_RULE_TYPES, GCP_IAM_ROLES,
  gcpReqTitle, gcpReqDetailLines,
  emptyFirewallRule, emptyArmorRule,
} from '../lib/gcp'
import { notify, summarizePayload } from '../lib/discord'
import { requireUser, currentUserId } from '../lib/auth'
import { pendingChanged } from '../lib/pending'
import { fetchRows } from '../lib/db'
import ErrorBanner from '../components/ErrorBanner'

function FirewallForm({ onSubmit, submitting }) {
  const [form, setForm] = useState({ name: '', network: 'default', reason: '' })
  const [rules, setRules] = useState([emptyFirewallRule()])

  const updateRule = (i, patch) => setRules((prev) => prev.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  const addRule = () => setRules((prev) => [...prev, emptyFirewallRule()])
  const removeRule = (i) => setRules((prev) => prev.filter((_, idx) => idx !== i))

  const reset = () => { setForm({ name: '', network: 'default', reason: '' }); setRules([emptyFirewallRule()]) }

  const submit = async () => {
    if (!form.name.trim()) return alert('규칙 이름은 필수입니다')
    const clean = rules.filter((r) => r.cidr.trim()).map((r) => ({
      direction: r.direction, protocol: r.protocol,
      port: r.port.trim() || null, cidr: r.cidr.trim(), priority: Number(r.priority) || 1000,
    }))
    if (clean.length === 0) return alert('규칙을 최소 1개 이상 입력해주세요')

    const ok = await onSubmit({
      resource_type: 'firewall_rule', action: 'create_firewall',
      title: form.name.trim(), target_id: null,
      payload: { name: form.name.trim(), network: form.network.trim(), rules: clean },
      reason: form.reason.trim() || null,
    })
    if (ok) reset()
  }

  return (
    <>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">규칙 이름</label>
          <input className="ac-input" placeholder="예: allow-internal-ssh" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </div>
        <div className="ac-field">
          <label className="ac-label">네트워크</label>
          <input className="ac-input" placeholder="default" value={form.network} onChange={(e) => setForm({ ...form, network: e.target.value })} />
        </div>
      </div>

      <div className="ac-card-title" style={{ fontSize: 13, marginTop: 16 }}>규칙</div>
      <div className="ac-rule-table">
        <div className="ac-rule-row ac-rule-head">
          <span>방향</span><span>프로토콜</span><span>포트</span><span>소스/대상 CIDR</span><span>우선순위</span><span></span>
        </div>
        {rules.map((r, i) => (
          <div key={i} className="ac-rule-row">
            <select className="ac-input" value={r.direction} onChange={(e) => updateRule(i, { direction: e.target.value })}>
              <option value="ingress">인바운드</option>
              <option value="egress">아웃바운드</option>
            </select>
            <select className="ac-input" value={r.protocol} onChange={(e) => updateRule(i, { protocol: e.target.value })}>
              {GCP_PROTOCOLS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
            </select>
            <input className="ac-input" placeholder="22 또는 8080-8090" value={r.port} onChange={(e) => updateRule(i, { port: e.target.value })} />
            <input className="ac-input" placeholder="10.0.0.0/8" value={r.cidr} onChange={(e) => updateRule(i, { cidr: e.target.value })} />
            <input className="ac-input" placeholder="1000" value={r.priority} onChange={(e) => updateRule(i, { priority: e.target.value })} style={{ width: 70 }} />
            {rules.length > 1
              ? <button className="ac-btn ac-btn-secondary ac-rule-del" onClick={() => removeRule(i)}>삭제</button>
              : <span />}
          </div>
        ))}
      </div>
      <button className="ac-btn ac-btn-secondary" onClick={addRule} style={{ marginTop: 8, marginBottom: 16 }}>+ 규칙 추가</button>

      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">신청 사유</label>
          <input className="ac-input" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} />
        </div>
      </div>
      <button className="ac-btn" onClick={submit} disabled={submitting}>{submitting ? '신청 중...' : '신청하기'}</button>
    </>
  )
}

function ArmorForm({ onSubmit, submitting }) {
  const [action, setAction] = useState('create_armor_policy')
  const [form, setForm] = useState({ policy_name: '', default_action: 'allow', target_id: '', reason: '' })
  const [rules, setRules] = useState([emptyArmorRule()])

  const updateRule = (i, patch) => setRules((prev) => prev.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  const addRule = () => setRules((prev) => [...prev, emptyArmorRule()])
  const removeRule = (i) => setRules((prev) => prev.filter((_, idx) => idx !== i))

  const reset = () => { setForm({ policy_name: '', default_action: 'allow', target_id: '', reason: '' }); setRules([emptyArmorRule()]) }

  const submit = async () => {
    if (action === 'create_armor_policy') {
      if (!form.policy_name.trim()) return alert('정책 이름은 필수입니다')
      const ok = await onSubmit({
        resource_type: 'cloud_armor', action: 'create_armor_policy',
        title: form.policy_name.trim(), target_id: null,
        payload: { policy_name: form.policy_name.trim(), default_action: form.default_action },
        reason: form.reason.trim() || null,
      })
      if (ok) reset()
      return
    }
    if (!form.target_id.trim()) return alert('대상 정책을 입력해주세요')
    const clean = rules.map((r) => ({
      type: r.type, cidrs: r.cidrs.trim() || null,
      expression: r.expression.trim() || null,
      priority: Number(r.priority) || 1000,
      rate_limit: r.type === 'rate_limit' ? (Number(r.rate_limit) || 500) : null,
    }))
    const ok = await onSubmit({
      resource_type: 'cloud_armor', action: 'add_armor_rules',
      title: form.target_id.trim(), target_id: form.target_id.trim(),
      payload: { rules: clean },
      reason: form.reason.trim() || null,
    })
    if (ok) reset()
  }

  return (
    <>
      <div className="ac-filter-row">
        <button className={`ac-filter-btn ${action === 'create_armor_policy' ? 'active' : ''}`} onClick={() => setAction('create_armor_policy')}>신규 정책 생성</button>
        <button className={`ac-filter-btn ${action === 'add_armor_rules' ? 'active' : ''}`} onClick={() => setAction('add_armor_rules')}>기존 정책에 규칙 추가</button>
      </div>

      {action === 'create_armor_policy' ? (
        <div className="ac-form-row">
          <div className="ac-field">
            <label className="ac-label">정책 이름</label>
            <input className="ac-input" placeholder="예: my-armor-policy" value={form.policy_name} onChange={(e) => setForm({ ...form, policy_name: e.target.value })} />
          </div>
          <div className="ac-field">
            <label className="ac-label">기본 액션</label>
            <select className="ac-input" value={form.default_action} onChange={(e) => setForm({ ...form, default_action: e.target.value })}>
              <option value="allow">허용</option>
              <option value="deny">차단</option>
            </select>
          </div>
        </div>
      ) : (
        <>
          <div className="ac-form-row">
            <div className="ac-field">
              <label className="ac-label">대상 정책 이름</label>
              <input className="ac-input" placeholder="예: my-armor-policy" value={form.target_id} onChange={(e) => setForm({ ...form, target_id: e.target.value })} />
            </div>
          </div>
          <div className="ac-card-title" style={{ fontSize: 13, marginTop: 16 }}>규칙</div>
          <div className="ac-waf-rules">
            {rules.map((r, i) => (
              <div key={i} className="ac-waf-rule">
                <div className="ac-form-row">
                  <div className="ac-field">
                    <label className="ac-label">유형</label>
                    <select className="ac-input" value={r.type} onChange={(e) => updateRule(i, { type: e.target.value })}>
                      {GCP_ARMOR_RULE_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
                    </select>
                  </div>
                  <div className="ac-field">
                    <label className="ac-label">우선순위</label>
                    <input className="ac-input" placeholder="1000" value={r.priority} onChange={(e) => updateRule(i, { priority: e.target.value })} />
                  </div>
                </div>
                {(r.type === 'ip_deny' || r.type === 'ip_allow') && (
                  <div className="ac-form-row">
                    <div className="ac-field">
                      <label className="ac-label">CIDR (쉼표 구분)</label>
                      <input className="ac-input" placeholder="1.2.3.4/32, 10.0.0.0/8" value={r.cidrs} onChange={(e) => updateRule(i, { cidrs: e.target.value })} />
                    </div>
                  </div>
                )}
                {r.type === 'rate_limit' && (
                  <div className="ac-form-row">
                    <div className="ac-field">
                      <label className="ac-label">분당 요청 한도</label>
                      <input className="ac-input" type="number" placeholder="500" value={r.rate_limit} onChange={(e) => updateRule(i, { rate_limit: e.target.value })} />
                    </div>
                  </div>
                )}
                {r.type === 'expression' && (
                  <div className="ac-form-row">
                    <div className="ac-field">
                      <label className="ac-label">CEL 표현식</label>
                      <input className="ac-input" placeholder='예: origin.region_code == "KR"' value={r.expression} onChange={(e) => updateRule(i, { expression: e.target.value })} />
                    </div>
                  </div>
                )}
                {rules.length > 1 && <button className="ac-btn ac-btn-secondary" onClick={() => removeRule(i)}>이 규칙 삭제</button>}
              </div>
            ))}
          </div>
          <button className="ac-btn ac-btn-secondary" onClick={addRule} style={{ marginTop: 8, marginBottom: 16 }}>+ 규칙 추가</button>
        </>
      )}

      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">신청 사유</label>
          <input className="ac-input" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} />
        </div>
      </div>
      <button className="ac-btn" onClick={submit} disabled={submitting}>{submitting ? '신청 중...' : '신청하기'}</button>
    </>
  )
}

function IamForm({ onSubmit, submitting }) {
  const [form, setForm] = useState({ account_id: '', display_name: '', role: GCP_IAM_ROLES[0].value, reason: '' })

  const reset = () => setForm({ account_id: '', display_name: '', role: GCP_IAM_ROLES[0].value, reason: '' })

  const submit = async () => {
    if (!form.account_id.trim()) return alert('계정 ID는 필수입니다')
    if (!/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(form.account_id.trim())) return alert('계정 ID: 소문자/숫자/하이픈, 6~30자')
    if (!form.reason.trim()) return alert('신청 사유는 필수입니다')

    const ok = await onSubmit({
      resource_type: 'service_account', action: 'create_service_account',
      title: form.account_id.trim(), target_id: null,
      payload: { account_id: form.account_id.trim(), display_name: form.display_name.trim() || form.account_id.trim(), role: form.role },
      reason: form.reason.trim(),
    })
    if (ok) reset()
  }

  return (
    <>
      <p className="ac-cred-note">GCP 서비스 계정을 신청합니다. 승인자가 사유를 보고 키 발급 여부를 결정합니다.</p>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">계정 ID</label>
          <input className="ac-input" placeholder="예: readonly-logs" value={form.account_id} onChange={(e) => setForm({ ...form, account_id: e.target.value })} />
        </div>
        <div className="ac-field">
          <label className="ac-label">표시 이름 (선택)</label>
          <input className="ac-input" placeholder="예: 로그 조회용" value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
        </div>
      </div>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">역할</label>
          <select className="ac-input" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            {GCP_IAM_ROLES.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
          </select>
        </div>
      </div>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">신청 사유 (필수)</label>
          <input className="ac-input" placeholder="예: 로그 분석용 3일간 필요" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} />
        </div>
      </div>
      <button className="ac-btn" onClick={submit} disabled={submitting}>{submitting ? '신청 중...' : '신청하기'}</button>
    </>
  )
}

function MyReqRow({ r }) {
  const [open, setOpen] = useState(false)
  const detail = gcpReqDetailLines(r)
  const d = new Date(r.requested_at)
  const shortDate = `${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`

  return (
    <div className="ac-myreq">
      <div className="ac-myreq-top" onClick={() => setOpen((v) => !v)}>
        <span className="ac-myreq-title">{gcpReqTitle(r)}</span>
        <span className="ac-myreq-date">{shortDate}</span>
        <span className="ac-expand-icon">{open ? '▲' : '▼'}</span>
      </div>
      {open && (
        <div className="ac-myreq-body">
          {detail.map((line, i) => <div key={i} className="ac-req-reason">{line}</div>)}
          {r.reason && <div className="ac-req-reason">사유: {r.reason}</div>}
          {r.error_message && <div className="ac-req-error">{r.error_message}</div>}
          <div className="ac-req-meta">{d.toLocaleString('ko-KR')}</div>
        </div>
      )}
    </div>
  )
}

const PAGE_META = {
  firewall_rule:   { title: 'GCP Firewall 신청', sub: 'VPC 방화벽 규칙 생성을 신청합니다.' },
  cloud_armor:     { title: 'GCP Cloud Armor 신청', sub: 'Cloud Armor 보안 정책 생성 또는 규칙 추가를 신청합니다.' },
  service_account: { title: 'GCP IAM 서비스 계정 신청', sub: '서비스 계정 발급을 신청합니다.' },
}

export default function GcpRequest({ resourceType = 'firewall_rule' }) {
  const [myRequests, setMyRequests] = useState([])
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [loadError, setLoadError] = useState(null)

  const fetchMyRequests = async () => {
    setLoading(true)
    // 본인이 낸 신청만 보여준다. 관리자는 RLS상 전체가 보이므로 여기서 걸러야 한다.
    const uid = await currentUserId()
    if (!uid) { setMyRequests([]); setLoading(false); return }
    const { rows, error } = await fetchRows(
      supabase.from('gcp_requests').select('*')
        .eq('resource_type', resourceType).eq('requester_id', uid)
        .order('requested_at', { ascending: false }).limit(50),
      'GCP 신청 현황')
    setMyRequests(rows)
    setLoadError(error)
    setLoading(false)
  }

  useEffect(() => {
    fetchMyRequests()
  }, [resourceType])

  const submitRequest = async (req) => {
    setSubmitting(true)
    let me
    try {
      me = await requireUser()
    } catch (e) {
      setSubmitting(false); alert(e.message); return false
    }
    const { error } = await supabase.from('gcp_requests').insert({
      ...req,
      status: 'pending',
      requester_id: me.id,
      requester_email: me.email,
    })
    setSubmitting(false)
    if (error) { alert('신청 실패: ' + error.message); return false }
    await fetchMyRequests()
    const GCP_ACTION_LABEL = { create_firewall: 'Firewall 규칙 생성', create_armor_policy: 'Cloud Armor 정책 생성', add_armor_rules: 'Cloud Armor 규칙 추가', create_service_account: '서비스 계정 생성' }
    const actionLabel = GCP_ACTION_LABEL[req.action] || req.action
    const detail = summarizePayload(req.action, req.payload)
    notify(`📋 **새 GCP 신청**\n${actionLabel}: ${req.title || ''}\n신청자: ${me.email}${detail ? `\n내용: ${detail}` : ''}${req.reason ? `\n사유: ${req.reason}` : ''}`)
    pendingChanged() // 관리자 화면의 대기 배지 반영
    alert('신청되었습니다. 승인자 검토 후 반영됩니다.')
    return true
  }

  const meta = PAGE_META[resourceType] || PAGE_META.firewall_rule

  return (
    <div className="ac-page">
      <h2 className="ac-title">{meta.title}</h2>
      <p className="ac-sub">{meta.sub} 승인자 검토 후 실제 GCP에 반영됩니다.</p>

      <ErrorBanner message={loadError} onRetry={fetchMyRequests} />

      <div className="ac-grid">
        <div className="ac-card ac-card-wide">
          <div className="ac-card-title">신청서 작성</div>
          {resourceType === 'firewall_rule' && <FirewallForm onSubmit={submitRequest} submitting={submitting} />}
          {resourceType === 'cloud_armor' && <ArmorForm onSubmit={submitRequest} submitting={submitting} />}
          {resourceType === 'service_account' && <IamForm onSubmit={submitRequest} submitting={submitting} />}
        </div>

        <div className="ac-card ac-card-wide ac-card-muted">
          <div className="ac-card-title">내 신청 현황</div>
          {loading && <div className="ac-empty">불러오는 중...</div>}
          {!loading && myRequests.length === 0 && <div className="ac-empty">아직 신청 내역이 없습니다.</div>}
          <div className="ac-snapshot-list">
            {myRequests.map((r) => <MyReqRow key={r.id} r={r} />)}
          </div>
        </div>
      </div>
    </div>
  )
}
