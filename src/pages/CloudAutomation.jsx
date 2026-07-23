import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'

const AWS_COLLECT_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/aws-collect'
const AWS_SG_APPLY_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/aws-sg-apply'

// 두 줄 배열의 LCS 기반 라인 diff
function diffLines(oldLines, newLines) {
  const m = oldLines.length, n = newLines.length
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0))
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      dp[i][j] = oldLines[i] === newLines[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1])
    }
  }
  const result = []
  let i = 0, j = 0
  while (i < m && j < n) {
    if (oldLines[i] === newLines[j]) { result.push({ type: 'same', text: oldLines[i] }); i++; j++ }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { result.push({ type: 'removed', text: oldLines[i] }); i++ }
    else { result.push({ type: 'added', text: newLines[j] }); j++ }
  }
  while (i < m) { result.push({ type: 'removed', text: oldLines[i] }); i++ }
  while (j < n) { result.push({ type: 'added', text: newLines[j] }); j++ }
  return result
}

function DiffView({ oldData, newData }) {
  if (!oldData) return <pre className="ac-snapshot-json">{JSON.stringify(newData, null, 2)}</pre>
  const oldLines = JSON.stringify(oldData, null, 2).split('\n')
  const newLines = JSON.stringify(newData, null, 2).split('\n')
  const lines = diffLines(oldLines, newLines)
  return (
    <pre className="ac-snapshot-json ac-diff">
      {lines.map((l, i) => (
        <div key={i} className={`ac-diff-line ac-diff-${l.type}`}>
          {l.type === 'added' ? '+ ' : l.type === 'removed' ? '- ' : '  '}{l.text}
        </div>
      ))}
    </pre>
  )
}

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

const pad = (n) => String(n).padStart(2, '0')
const dateKey = (y, m, d) => `${y}-${pad(m + 1)}-${pad(d)}`
const WEEKDAYS = ['일', '월', '화', '수', '목', '금', '토']

function DatePickerPopup({ countsByDate, selected, onSelect, onViewAll, onClose }) {
  const today = new Date()
  const base = selected ? new Date(selected + 'T00:00:00') : today
  const [viewDate, setViewDate] = useState(new Date(base.getFullYear(), base.getMonth(), 1))

  const year = viewDate.getFullYear()
  const month = viewDate.getMonth()
  const firstDayOfWeek = new Date(year, month, 1).getDay()
  const daysInMonth = new Date(year, month + 1, 0).getDate()
  const todayKey = dateKey(today.getFullYear(), today.getMonth(), today.getDate())

  const cells = []
  for (let i = 0; i < firstDayOfWeek; i++) cells.push(null)
  for (let d = 1; d <= daysInMonth; d++) cells.push(d)

  return (
    <div className="ac-datepop-backdrop" onClick={onClose}>
      <div className="ac-datepop" onClick={(e) => e.stopPropagation()}>
        <div className="ac-cal-header">
          <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => setViewDate(new Date(year, month - 1, 1))}>‹</button>
          <span className="ac-cal-title">{year}년 {month + 1}월</span>
          <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => setViewDate(new Date(year, month + 1, 1))}>›</button>
        </div>
        <div className="ac-cal-grid">
          {WEEKDAYS.map((w) => <div key={w} className="ac-cal-weekday">{w}</div>)}
          {cells.map((d, i) => {
            if (d === null) return <div key={i} className="ac-cal-cell ac-cal-empty" />
            const key = dateKey(year, month, d)
            const count = countsByDate[key] || 0
            const isToday = key === todayKey
            const isSelected = key === selected
            return (
              <div
                key={i}
                className={`ac-cal-cell ${count > 0 ? 'has-data' : ''} ${isToday ? 'is-today' : ''} ${isSelected ? 'is-selected' : ''}`}
                onClick={() => onSelect(key)}
              >
                <span className="ac-cal-day">{d}</span>
                <span className="ac-cal-count">{count > 0 ? count : ''}</span>
              </div>
            )
          })}
        </div>
        <div className="ac-datepop-actions">
          <button className="ac-btn" onClick={onViewAll}>전체 이력 보기</button>
          <button className="ac-btn ac-btn-secondary" onClick={onClose}>닫기</button>
        </div>
      </div>
    </div>
  )
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

function groupByDate(items) {
  const groups = {}
  for (const item of items) {
    const date = item.requested_at.slice(0, 10)
    if (!groups[date]) groups[date] = []
    groups[date].push(item)
  }
  return Object.entries(groups).sort((a, b) => b[0].localeCompare(a[0]))
}

const HISTORY_CATEGORIES = [
  { key: 'all', label: '전체' },
  { key: 'create_sg', label: '신규 SG 생성 이력' },
  { key: 'add_rules', label: 'SG 규칙 추가 이력' },
]

function HistoryList({ historyRequests, busyId, approve, reject, removeRequest }) {
  const today = new Date()
  const todayKey = dateKey(today.getFullYear(), today.getMonth(), today.getDate())

  const [category, setCategory] = useState('all')
  const [dateFilter, setDateFilter] = useState(todayKey)
  const [pickerOpen, setPickerOpen] = useState(false)
  const [expandedDates, setExpandedDates] = useState(() => new Set())
  const toggleDate = (date) => setExpandedDates((prev) => {
    const next = new Set(prev)
    next.has(date) ? next.delete(date) : next.add(date)
    return next
  })

  const countsByDate = {}
  for (const r of historyRequests) {
    const key = r.requested_at.slice(0, 10)
    countsByDate[key] = (countsByDate[key] || 0) + 1
  }

  const dateFiltered = dateFilter ? historyRequests.filter((r) => r.requested_at.slice(0, 10) === dateFilter) : historyRequests
  const filtered = category === 'all' ? dateFiltered : dateFiltered.filter((r) => r.request_type === category)
  const grouped = groupByDate(filtered)
  const counts = { all: dateFiltered.length, create_sg: 0, add_rules: 0 }
  for (const r of dateFiltered) counts[r.request_type] = (counts[r.request_type] || 0) + 1

  return (
    <div>
      <div className="ac-filter-row">
        <div className="ac-date-picker">
          <button className="ac-date-trigger" onClick={() => setPickerOpen(true)}>
            📅 {dateFilter || '전체'}
          </button>
        </div>
        {pickerOpen && (
          <DatePickerPopup
            countsByDate={countsByDate}
            selected={dateFilter}
            onSelect={(key) => { setDateFilter(key); setPickerOpen(false) }}
            onViewAll={() => { setDateFilter(''); setPickerOpen(false) }}
            onClose={() => setPickerOpen(false)}
          />
        )}
        {HISTORY_CATEGORIES.map((c) => (
          <button key={c.key} className={`ac-filter-btn ${category === c.key ? 'active' : ''}`} onClick={() => setCategory(c.key)}>
            {c.label} {counts[c.key] || 0}
          </button>
        ))}
      </div>
      {grouped.length === 0 && <div className="ac-empty">해당 항목이 없습니다.</div>}
      <div className="ac-date-groups">
        {grouped.map(([date, items]) => (
          <div key={date} className="ac-date-group">
            <div className="ac-date-header" onClick={() => toggleDate(date)}>
              <span className="ac-date-label">{date}</span>
              <span className="ac-date-count">{items.length}건</span>
              <span className="ac-expand-icon">{expandedDates.has(date) ? '▲' : '▼'}</span>
            </div>
            {expandedDates.has(date) && (
              <div className="ac-snapshot-list">
                {items.map((r) => (
                  <ReqRow key={r.id} r={r} busyId={busyId} approve={approve} reject={reject} removeRequest={removeRequest} />
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
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
        {!loading && historyRequests.length > 0 && (
          <HistoryList historyRequests={historyRequests} busyId={busyId} approve={approve} reject={reject} removeRequest={removeRequest} />
        )}
      </div>
    </>
  )
}

function groupSnapshotsByResource(snapshots) {
  const groups = {}
  for (const s of snapshots) {
    const key = `${s.resource_type}:${s.resource_id}`
    if (!groups[key]) groups[key] = []
    groups[key].push(s)
  }
  return Object.entries(groups).map(([key, list]) => {
    const sorted = [...list].sort((a, b) => new Date(a.collected_at) - new Date(b.collected_at))
    return { key, sorted, latest: sorted[sorted.length - 1], history: sorted.slice(0, -1).reverse() }
  }).sort((a, b) => new Date(b.latest.collected_at) - new Date(a.latest.collected_at))
}

export default function CloudAutomation() {
  const [cred, setCred] = useState({ accessKeyId: '', secretAccessKey: '', region: 'ap-northeast-2' })
  const [collecting, setCollecting] = useState(false)
  const [collectResult, setCollectResult] = useState(null)
  const [snapshots, setSnapshots] = useState([])
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState(() => new Set())
  const [expandedHistory, setExpandedHistory] = useState(() => new Set())
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

  const toggleHistory = (key) => setExpandedHistory((prev) => {
    const next = new Set(prev)
    next.has(key) ? next.delete(key) : next.add(key)
    return next
  })

  const visible = filter === 'all' ? snapshots : snapshots.filter((s) => s.resource_type === filter)
  const counts = Object.keys(RESOURCE_META).reduce((acc, k) => {
    acc[k] = new Set(snapshots.filter((s) => s.resource_type === k).map((s) => s.resource_id)).size
    return acc
  }, {})
  const totalResources = new Set(snapshots.map((s) => `${s.resource_type}:${s.resource_id}`)).size
  const resourceGroups = groupSnapshotsByResource(visible)

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
            전체 {totalResources}
          </button>
          {Object.entries(RESOURCE_META).map(([key, meta]) => counts[key] > 0 && (
            <button key={key} className={`ac-filter-btn ${filter === key ? 'active' : ''}`} onClick={() => setFilter(filter === key ? 'all' : key)}>
              {meta.icon} {meta.label} {counts[key]}
            </button>
          ))}
        </div>

        {loading && <div className="ac-empty">불러오는 중...</div>}
        {!loading && resourceGroups.length === 0 && <div className="ac-empty">아직 수집된 데이터가 없습니다. 자격증명 설정 후 "지금 수집하기"를 눌러보세요.</div>}

        <div className="ac-snapshot-list">
          {resourceGroups.map(({ key, sorted, latest, history }) => {
            const meta = RESOURCE_META[latest.resource_type] || { icon: '📦', label: latest.resource_type }
            const isOpen = expanded.has(latest.id)
            const historyOpen = expandedHistory.has(key)
            const prevOf = (item) => {
              const idx = sorted.findIndex((s) => s.id === item.id)
              return idx > 0 ? sorted[idx - 1] : null
            }
            return (
              <div key={key} className={`ac-snapshot ${history.length > 0 ? 'has-changes' : ''}`}>
                <div className="ac-snapshot-top" onClick={() => toggle(latest.id)}>
                  <span className="ac-snapshot-icon">{meta.icon}</span>
                  <span className="ac-snapshot-name">{latest.resource_name || latest.resource_id}</span>
                  <span className="ac-snapshot-type">{meta.label}</span>
                  <span className="ac-snapshot-time">{new Date(latest.collected_at).toLocaleString('ko-KR')}</span>
                  <span className="ac-expand-icon">{isOpen ? '▲' : '▼'}</span>
                </div>
                {isOpen && (
                  <DiffView oldData={prevOf(latest)?.raw_data} newData={latest.raw_data} />
                )}
                {history.length > 0 && (
                  <div className="ac-snapshot-history">
                    <div className="ac-snapshot-history-toggle" onClick={() => toggleHistory(key)}>
                      변경 이력 {history.length}건 {historyOpen ? '▲' : '▼'}
                    </div>
                    {historyOpen && history.map((h) => {
                      const hOpen = expanded.has(h.id)
                      return (
                        <div key={h.id} className="ac-snapshot-history-item">
                          <div className="ac-snapshot-history-top" onClick={() => toggle(h.id)}>
                            <span className="ac-snapshot-time">{new Date(h.collected_at).toLocaleString('ko-KR')}</span>
                            <span className="ac-expand-icon">{hOpen ? '▲' : '▼'}</span>
                          </div>
                          {hOpen && <DiffView oldData={prevOf(h)?.raw_data} newData={h.raw_data} />}
                        </div>
                      )
                    })}
                  </div>
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
