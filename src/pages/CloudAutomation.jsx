import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'
import { RESOURCE_META, ReqCard } from '../lib/aws'

const AWS_COLLECT_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/aws-collect'
const AWS_REQUEST_APPLY_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/aws-request-apply'

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
  { key: 'security_group', label: '🛡️ SG' },
  { key: 'waf_web_acl', label: '🧱 WAF' },
]

function HistoryList({ historyRequests, busyId, onRemove }) {
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
  const filtered = category === 'all' ? dateFiltered : dateFiltered.filter((r) => r.resource_type === category)
  const grouped = groupByDate(filtered)
  const counts = { all: dateFiltered.length }
  for (const r of dateFiltered) counts[r.resource_type] = (counts[r.resource_type] || 0) + 1

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
                  <ReqCard key={r.id} r={r} busyId={busyId} onRemove={onRemove} />
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
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

// 신청 대기/이력 관리 (통합 큐)
function RequestQueue() {
  const [requests, setRequests] = useState([])
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState(null)

  const pendingRequests = requests.filter((r) => r.status === 'pending')
  const historyRequests = requests.filter((r) => r.status !== 'pending')

  const fetchRequests = async () => {
    setLoading(true)
    const { data } = await supabase.from('aws_requests').select('*').order('requested_at', { ascending: false }).limit(100)
    setRequests(data || [])
    setLoading(false)
  }

  useEffect(() => { fetchRequests() }, [])

  const approve = async (id) => {
    setBusyId(id)
    try {
      const { data: { session } } = await supabase.auth.getSession()
      const res = await fetch(AWS_REQUEST_APPLY_URL, {
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
    await supabase.from('aws_requests').update({ status: 'rejected', reviewed_at: new Date().toISOString() }).eq('id', id).eq('status', 'pending')
    await fetchRequests()
    setBusyId(null)
  }

  const removeRequest = async (id) => {
    if (!confirm('이 신청을 목록에서 삭제할까요?')) return
    setBusyId(id)
    const { error } = await supabase.from('aws_requests').delete().eq('id', id)
    setBusyId(null)
    if (error) return alert('삭제 실패: ' + error.message)
    await fetchRequests()
  }

  return (
    <>
      <div className="ac-card ac-card-wide">
        <div className="ac-card-title">처리 대기중 {pendingRequests.length > 0 && `(${pendingRequests.length})`}</div>
        {loading && <div className="ac-empty">불러오는 중...</div>}
        {!loading && pendingRequests.length === 0 && <div className="ac-empty">대기중인 신청이 없습니다.</div>}
        <div className="ac-snapshot-list">
          {pendingRequests.map((r) => (
            <ReqCard key={r.id} r={r} busyId={busyId} onApprove={approve} onReject={reject} onRemove={removeRequest} />
          ))}
        </div>
      </div>

      <div className="ac-card ac-card-wide">
        <div className="ac-card-title">처리 이력</div>
        {!loading && historyRequests.length === 0 && <div className="ac-empty">이력이 없습니다.</div>}
        {!loading && historyRequests.length > 0 && (
          <HistoryList historyRequests={historyRequests} busyId={busyId} onRemove={removeRequest} />
        )}
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
      <h2 className="ac-title">⚙️ AWS 자동화 (승인/관리)</h2>
      <p className="ac-sub">신청 승인·AWS 반영 + 설정 자동 수집. 신청은 "AWS 리소스 신청" 페이지에서 합니다.</p>

      <div className="ac-grid">
      <RequestQueue />

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
