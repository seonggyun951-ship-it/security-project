import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'

const AWS_COLLECT_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/aws-collect'
const AWS_SG_APPLY_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/aws-sg-apply'

const RESOURCE_META = {
  security_group: { icon: '🛡️', label: 'Security Group' },
  waf_web_acl:    { icon: '🧱', label: 'WAF Web ACL' },
  iam_role:       { icon: '👤', label: 'IAM Role' },
  iam_policy:     { icon: '📜', label: 'IAM Policy' },
}

const REQ_STATUS_META = {
  pending:  { label: '대기중', color: '#f59e0b' },
  approved: { label: '승인 처리중', color: '#38bdf8' },
  applied:  { label: '적용 완료', color: '#10b981' },
  rejected: { label: '거절됨', color: '#64748b' },
  failed:   { label: '적용 실패', color: '#ef4444' },
}

const emptyRule = () => ({ direction: 'ingress', protocol: 'tcp', port: '', cidr: '' })

// "22" -> {from:22, to:22} / "1000-2000" -> {from:1000, to:2000} / "" -> {from:null, to:null}(전체)
function parsePortRange(str) {
  const s = (str || '').trim()
  if (!s) return { from_port: null, to_port: null }
  const [a, b] = s.split('-').map((v) => v.trim())
  const from = Number(a)
  const to = b ? Number(b) : from
  return { from_port: from, to_port: to }
}

// CIDR에 서브넷 마스크(/)가 없으면 단일 IP로 간주해 /32를 붙여줌. 이미 있으면 그대로 둠.
function normalizeCidr(str) {
  const s = (str || '').trim()
  if (!s || s.includes('/')) return s
  return `${s}/32`
}

function ruleLabel(r) {
  const port = r.from_port ? `${r.from_port}${r.to_port && r.to_port != r.from_port ? '-' + r.to_port : ''}` : '전체'
  const dir = r.direction === 'ingress' ? '인바운드' : '아웃바운드'
  return `${dir} ${r.protocol}:${port} ↔ ${r.cidr}`
}

function ReqRow({ r, busyId, approve, reject, removeRequest }) {
  const meta = REQ_STATUS_META[r.status] || { label: r.status, color: '#94a3b8' }
  return (
    <div className="ac-req">
      <div className="ac-req-top">
        <span className="ac-req-status" style={{ background: meta.color }}>{meta.label}</span>
        <span className="ac-req-title">
          {r.request_type === 'create_sg' ? `신규 생성: ${r.sg_name}` : `규칙 추가: ${r.sg_name || r.sg_id}`}
          {r.created_sg_id ? ` (${r.created_sg_id})` : ''}
        </span>
      </div>
      <div className="ac-req-reason">{(r.rules || []).map(ruleLabel).join(', ')}</div>
      {r.reason && <div className="ac-req-reason">사유: {r.reason}</div>}
      {r.error_message && <div className="ac-req-error">⚠️ {r.error_message}</div>}
      <div className="ac-req-meta">{new Date(r.requested_at).toLocaleString('ko-KR')}</div>
      {r.status === 'pending' && (
        <div className="ac-req-actions">
          <button className="ac-btn" disabled={busyId === r.id} onClick={() => approve(r.id)}>{busyId === r.id ? '처리 중...' : '승인'}</button>
          <button className="ac-btn ac-btn-secondary" disabled={busyId === r.id} onClick={() => reject(r.id)}>거절</button>
        </div>
      )}
      {(r.status === 'failed' || r.status === 'rejected') && (
        <div className="ac-req-actions">
          <button className="ac-btn ac-btn-secondary" disabled={busyId === r.id} onClick={() => removeRequest(r.id)}>{busyId === r.id ? '삭제 중...' : '목록에서 삭제'}</button>
        </div>
      )}
    </div>
  )
}

function SgRequestSection() {
  const [requestType, setRequestType] = useState('add_rules') // 'add_rules' | 'create_sg'
  const [form, setForm] = useState({ sg_id: '', sg_name: '', vpc_id: '', description: '', reason: '' })
  const [rules, setRules] = useState([emptyRule()])
  const [sgOptions, setSgOptions] = useState([])
  const [requests, setRequests] = useState([])
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [busyId, setBusyId] = useState(null)

  const pendingRequests = requests.filter((r) => r.status === 'pending')
  const historyRequests = requests.filter((r) => r.status !== 'pending')

  const fetchRequests = async () => {
    setLoading(true)
    const { data } = await supabase.from('aws_sg_requests').select('*').order('requested_at', { ascending: false }).limit(50)
    setRequests(data || [])
    setLoading(false)
  }

  const fetchSgOptions = async () => {
    const { data } = await supabase.from('aws_resource_snapshots').select('resource_id, resource_name').eq('resource_type', 'security_group').order('collected_at', { ascending: false }).limit(200)
    const seen = new Set()
    setSgOptions((data || []).filter((s) => (seen.has(s.resource_id) ? false : (seen.add(s.resource_id), true))))
  }

  useEffect(() => { fetchRequests(); fetchSgOptions() }, [])

  const updateRule = (i, patch) => setRules((prev) => prev.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  const addRule = () => setRules((prev) => [...prev, emptyRule()])
  const removeRule = (i) => setRules((prev) => prev.filter((_, idx) => idx !== i))

  const resetForm = () => {
    setForm({ sg_id: '', sg_name: '', vpc_id: '', description: '', reason: '' })
    setRules([emptyRule()])
  }

  const submit = async () => {
    if (requestType === 'add_rules' && !form.sg_id.trim()) return alert('SG ID는 필수입니다')
    if (requestType === 'create_sg' && (!form.sg_name.trim() || !form.vpc_id.trim())) return alert('SG 이름과 VPC ID는 필수입니다')
    const cleanRules = rules.filter((r) => r.cidr.trim()).map((r) => ({
      direction: r.direction,
      protocol: r.protocol,
      ...parsePortRange(r.port),
      cidr: normalizeCidr(r.cidr),
    }))
    if (cleanRules.length === 0) return alert('규칙을 최소 1개 이상 입력해주세요 (CIDR 필수)')

    setSubmitting(true)
    const { error } = await supabase.from('aws_sg_requests').insert({
      request_type: requestType,
      sg_id: requestType === 'add_rules' ? form.sg_id.trim() : null,
      sg_name: form.sg_name.trim() || null,
      vpc_id: requestType === 'create_sg' ? form.vpc_id.trim() : null,
      description: form.description.trim() || null,
      rules: cleanRules,
      reason: form.reason.trim() || null,
    })
    setSubmitting(false)
    if (error) return alert('신청 실패: ' + error.message)
    resetForm()
    await fetchRequests()
  }

  const approve = async (id) => {
    setBusyId(id)
    try {
      const { data: { session } } = await supabase.auth.getSession()
      const res = await fetch(AWS_SG_APPLY_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${session?.access_token}` },
        body: JSON.stringify({ request_id: id }),
      })
      const data = await res.json()
      if (!data.ok) alert('적용 실패: ' + data.error)
    } catch (e) {
      alert('적용 실패: ' + String(e))
    }
    await fetchRequests()
    setBusyId(null)
  }

  const reject = async (id) => {
    setBusyId(id)
    await supabase.from('aws_sg_requests').update({ status: 'rejected', reviewed_at: new Date().toISOString() }).eq('id', id).eq('status', 'pending')
    await fetchRequests()
    setBusyId(null)
  }

  const removeRequest = async (id) => {
    if (!confirm('이 신청을 목록에서 삭제할까요?')) return
    setBusyId(id)
    const { error } = await supabase.from('aws_sg_requests').delete().eq('id', id)
    setBusyId(null)
    if (error) return alert('삭제 실패: ' + error.message)
    alert('삭제되었습니다.')
    await fetchRequests()
  }

  return (
    <>
      <div className="ac-card ac-card-wide">
        <div className="ac-card-title">Security Group 신청</div>
        <p className="ac-cred-note">신규 SG 생성 또는 기존 SG에 인바운드/아웃바운드 규칙 추가를 신청합니다. 관리자 승인 후 실제 AWS에 반영됩니다. (삭제 기능 없음)</p>

        <div className="ac-filter-row">
          <button className={`ac-filter-btn ${requestType === 'add_rules' ? 'active' : ''}`} onClick={() => setRequestType('add_rules')}>기존 SG에 규칙 추가</button>
          <button className={`ac-filter-btn ${requestType === 'create_sg' ? 'active' : ''}`} onClick={() => setRequestType('create_sg')}>신규 SG 생성</button>
        </div>

        {requestType === 'add_rules' ? (
          <div className="ac-form-row">
            <div className="ac-field">
              <label className="ac-label">SG ID</label>
              <input className="ac-input" list="sg-options" placeholder="예: sg-0123abcd" value={form.sg_id} onChange={(e) => setForm({ ...form, sg_id: e.target.value })} />
              <datalist id="sg-options">
                {sgOptions.map((s) => <option key={s.resource_id} value={s.resource_id}>{s.resource_name}</option>)}
              </datalist>
            </div>
          </div>
        ) : (
          <>
            <div className="ac-form-row">
              <div className="ac-field">
                <label className="ac-label">새 SG 이름</label>
                <input className="ac-input" value={form.sg_name} onChange={(e) => setForm({ ...form, sg_name: e.target.value })} />
              </div>
              <div className="ac-field">
                <label className="ac-label">VPC ID</label>
                <input className="ac-input" placeholder="예: vpc-0123abcd" value={form.vpc_id} onChange={(e) => setForm({ ...form, vpc_id: e.target.value })} />
              </div>
            </div>
            <div className="ac-form-row">
              <div className="ac-field">
                <label className="ac-label">설명 (선택)</label>
                <input className="ac-input" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
              </div>
            </div>
          </>
        )}

        <div className="ac-card-title" style={{ fontSize: 13, marginTop: 16 }}>규칙</div>
        <div className="ac-rule-table">
          <div className="ac-rule-row ac-rule-head">
            <span>방향</span><span>프로토콜</span><span>포트</span><span>CIDR</span><span></span>
          </div>
          {rules.map((r, i) => (
            <div key={i} className="ac-rule-row">
              <select className="ac-input" value={r.direction} onChange={(e) => updateRule(i, { direction: e.target.value })}>
                <option value="ingress">인바운드</option>
                <option value="egress">아웃바운드</option>
              </select>
              <select className="ac-input" value={r.protocol} onChange={(e) => updateRule(i, { protocol: e.target.value })}>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
                <option value="-1">전체</option>
              </select>
              <input className="ac-input" placeholder="22 또는 1000-2000" value={r.port} onChange={(e) => updateRule(i, { port: e.target.value })} />
              <input className="ac-input" placeholder="1.2.3.4/32" value={r.cidr} onChange={(e) => updateRule(i, { cidr: e.target.value })} />
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
      </div>

      <div className="ac-card">
        <div className="ac-card-title">처리 대기중</div>
        {loading && <div className="ac-empty">불러오는 중...</div>}
        {!loading && pendingRequests.length === 0 && <div className="ac-empty">대기중인 신청이 없습니다.</div>}
        <div className="ac-snapshot-list">
          {pendingRequests.map((r) => (
            <ReqRow key={r.id} r={r} busyId={busyId} approve={approve} reject={reject} removeRequest={removeRequest} />
          ))}
        </div>
      </div>

      <div className="ac-card">
        <div className="ac-card-title">처리 이력</div>
        {!loading && historyRequests.length === 0 && <div className="ac-empty">이력이 없습니다.</div>}
        <div className="ac-snapshot-list">
          {historyRequests.map((r) => (
            <ReqRow key={r.id} r={r} busyId={busyId} approve={approve} reject={reject} removeRequest={removeRequest} />
          ))}
        </div>
      </div>
    </>
  )
}

export default function CloudAutomation() {
  const [cred, setCred] = useState({ accessKeyId: '', secretAccessKey: '', region: 'ap-northeast-2' })
  const [collecting, setCollecting] = useState(false)
  const [collectResult, setCollectResult] = useState(null)
  const [snapshots, setSnapshots] = useState([])
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState(() => new Set())
  const [filter, setFilter] = useState('all')

  const fetchSnapshots = async () => {
    setLoading(true)
    const { data } = await supabase.from('aws_resource_snapshots').select('*').order('collected_at', { ascending: false }).limit(100)
    setSnapshots(data || [])
    setLoading(false)
  }

  useEffect(() => { fetchSnapshots() }, [])

  const runCollect = async () => {
    setCollecting(true)
    setCollectResult(null)
    try {
      const { data: { session } } = await supabase.auth.getSession()
      const res = await fetch(AWS_COLLECT_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${session?.access_token}` },
        body: JSON.stringify({}),
      })
      const data = await res.json()
      setCollectResult(data)
      if (data.ok) await fetchSnapshots()
    } catch (e) {
      setCollectResult({ ok: false, error: String(e) })
    }
    setCollecting(false)
  }

  const toggle = (id) => setExpanded((prev) => {
    const next = new Set(prev)
    next.has(id) ? next.delete(id) : next.add(id)
    return next
  })

  const visible = filter === 'all' ? snapshots : snapshots.filter((s) => s.resource_type === filter)
  const counts = Object.keys(RESOURCE_META).reduce((acc, k) => {
    acc[k] = snapshots.filter((s) => s.resource_type === k).length
    return acc
  }, {})

  return (
    <div className="ac-page">
      <h2 className="ac-title">⚙️ AWS 자동화</h2>
      <p className="ac-sub">Security Group 신청/승인 자동화 + AWS 설정 자동 수집.</p>

      <div className="ac-grid">
      <SgRequestSection />

      <div className="ac-card">
        <div className="ac-card-title">AWS 자격증명</div>
        <p className="ac-cred-note">⚠️ 실제 운영 키는 여기 저장되지 않습니다. Supabase Edge Function 시크릿으로 별도 설정합니다. 이 폼은 아직 스켈레톤 단계입니다.</p>
        <div className="ac-form-row">
          <input
            className="ac-input"
            type="password"
            placeholder="Access Key ID"
            value={cred.accessKeyId}
            onChange={(e) => setCred({ ...cred, accessKeyId: e.target.value })}
            autoComplete="off"
          />
          <input
            className="ac-input"
            type="password"
            placeholder="Secret Access Key"
            value={cred.secretAccessKey}
            onChange={(e) => setCred({ ...cred, secretAccessKey: e.target.value })}
            autoComplete="off"
          />
          <input
            className="ac-input"
            placeholder="Region"
            value={cred.region}
            onChange={(e) => setCred({ ...cred, region: e.target.value })}
          />
        </div>
        <button className="ac-btn ac-btn-secondary" disabled>저장 (준비 중)</button>
      </div>

      <div className="ac-card">
        <div className="ac-card-title">수동 수집</div>
        <p className="ac-cred-note">자격증명이 설정되면 여기서 바로 수집을 실행할 수 있습니다.</p>
        <button className="ac-btn" onClick={runCollect} disabled={collecting}>
          {collecting ? '수집 중...' : '지금 수집하기'}
        </button>
        {collectResult && (
          collectResult.ok ? (
            <div className="ac-result ac-result-ok">
              ✅ 수집 완료 — 조회 SG {collectResult.counts.security_group}/IAM Role {collectResult.counts.iam_role}/
              IAM Policy {collectResult.counts.iam_policy}/WAF {collectResult.counts.waf_web_acl}개, 그중 변경 {collectResult.changed}건 기록됨
            </div>
          ) : (
            <div className="ac-result ac-result-error">⚠️ {collectResult.error}</div>
          )
        )}
      </div>

      <div className="ac-card ac-card-wide">
        <div className="ac-card-title">수집 이력</div>
        <div className="ac-filter-row">
          <button className={`ac-filter-btn ${filter === 'all' ? 'active' : ''}`} onClick={() => setFilter('all')}>
            전체 {snapshots.length}
          </button>
          {Object.entries(RESOURCE_META).map(([key, meta]) => counts[key] > 0 && (
            <button key={key} className={`ac-filter-btn ${filter === key ? 'active' : ''}`} onClick={() => setFilter(filter === key ? 'all' : key)}>
              {meta.icon} {meta.label} {counts[key]}
            </button>
          ))}
        </div>

        {loading && <div className="ac-empty">불러오는 중...</div>}
        {!loading && visible.length === 0 && <div className="ac-empty">아직 수집된 데이터가 없습니다. 자격증명 설정 후 "지금 수집하기"를 눌러보세요.</div>}

        <div className="ac-snapshot-list">
          {visible.map((s) => {
            const meta = RESOURCE_META[s.resource_type] || { icon: '📦', label: s.resource_type }
            const isOpen = expanded.has(s.id)
            return (
              <div key={s.id} className="ac-snapshot">
                <div className="ac-snapshot-top" onClick={() => toggle(s.id)}>
                  <span className="ac-snapshot-icon">{meta.icon}</span>
                  <span className="ac-snapshot-name">{s.resource_name || s.resource_id}</span>
                  <span className="ac-snapshot-type">{meta.label}</span>
                  <span className="ac-snapshot-time">{new Date(s.collected_at).toLocaleString('ko-KR')}</span>
                  <span className="ac-expand-icon">{isOpen ? '▲' : '▼'}</span>
                </div>
                {isOpen && (
                  <pre className="ac-snapshot-json">{JSON.stringify(s.raw_data, null, 2)}</pre>
                )}
              </div>
            )
          })}
        </div>
      </div>
      </div>
    </div>
  )
}
