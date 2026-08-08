import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'
import { ReqCard, REQ_STATUS_META, ACTION_LABEL } from '../lib/aws'
import { notify } from '../lib/discord'
import { fetchRows, runWrite, callFunction } from '../lib/db'
import ErrorBanner from '../components/ErrorBanner'

const pad = (n) => String(n).padStart(2, '0')
const dateKey = (y, m, d) => `${y}-${pad(m + 1)}-${pad(d)}`
const WEEKDAYS = ['일', '월', '화', '수', '목', '금', '토']

// DB의 timestamptz는 UTC라, 문자열을 그냥 자르면 한국 시간과 날짜가 어긋난다(UTC+9).
// 반드시 로컬 시간으로 변환한 뒤 날짜를 뽑을 것.
function localDateKey(ts) {
  const d = new Date(ts)
  return dateKey(d.getFullYear(), d.getMonth(), d.getDate())
}

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
          <button className="ac-btn ac-btn-secondary" onClick={onClose}>닫기</button>
        </div>
      </div>
    </div>
  )
}

function groupByDate(items) {
  const groups = {}
  for (const item of items) {
    const date = localDateKey(item.requested_at)
    if (!groups[date]) groups[date] = []
    groups[date].push(item)
  }
  return Object.entries(groups).sort((a, b) => b[0].localeCompare(a[0]))
}

const HISTORY_CATEGORIES = [
  { key: 'all', label: '전체' },
  { key: 'security_group', label: ' SG' },
  { key: 'waf_web_acl', label: ' WAF' },
  { key: 'iam_user', label: ' IAM' },
  { key: 'vpc', label: ' VPC' },
  { key: 'subnet', label: ' 서브넷' },
  { key: 'ec2_instance', label: ' EC2' },
  { key: 'internet_gateway', label: ' IGW' },
  { key: 'route_table', label: ' RT' },
]

// 날짜 요약 줄에 표시할 상태 순서
const STATUS_ORDER = ['applied', 'rejected', 'failed', 'approved']

function statusSummary(items) {
  const c = {}
  for (const r of items) c[r.status] = (c[r.status] || 0) + 1
  return STATUS_ORDER.filter((s) => c[s]).map((s) => ({ status: s, count: c[s], meta: REQ_STATUS_META[s] }))
}

// 하루치 처리 내역을 새 창(모달)으로 — 목록을 화면에 펼치지 않기 위해
function DayDetailModal({ date, items, busyId, onRemove, onClose }) {
  return (
    <div className="ac-datepop-backdrop" onClick={onClose}>
      <div className="ac-modal" onClick={(e) => e.stopPropagation()}>
        <div className="ac-modal-head">
          <span className="ac-modal-title">{date} 처리 내역 <b>{items.length}</b>건</span>
          <button className="ac-btn ac-btn-secondary" onClick={onClose}>닫기</button>
        </div>
        <div className="ac-modal-body">
          <div className="ac-snapshot-list">
            {items.map((r) => <ReqCard key={r.id} r={r} busyId={busyId} onRemove={onRemove} />)}
          </div>
        </div>
      </div>
    </div>
  )
}

const PERIOD_OPTIONS = [
  { key: 'day', label: '일별' },
  { key: 'week', label: '주별' },
  { key: 'month', label: '월별' },
  { key: 'all', label: '전체' },
]

function periodRange(mode, offset) {
  const now = new Date()
  if (mode === 'month') {
    const s = new Date(now.getFullYear(), now.getMonth() + offset, 1)
    const e = new Date(s.getFullYear(), s.getMonth() + 1, 0)
    return { start: s, end: e, label: `${s.getFullYear()}년 ${s.getMonth() + 1}월` }
  }
  if (mode === 'week') {
    const d = new Date(now)
    d.setDate(d.getDate() + offset * 7)
    const day = d.getDay()
    const s = new Date(d); s.setDate(d.getDate() - day)
    const e = new Date(s); e.setDate(s.getDate() + 6)
    const fmt = (dt) => `${dt.getMonth() + 1}/${dt.getDate()}`
    return { start: s, end: e, label: `${fmt(s)} ~ ${fmt(e)}` }
  }
  return null
}

function inRange(ts, range) {
  if (!range) return true
  const d = new Date(ts)
  const dk = new Date(d.getFullYear(), d.getMonth(), d.getDate())
  const sk = new Date(range.start.getFullYear(), range.start.getMonth(), range.start.getDate())
  const ek = new Date(range.end.getFullYear(), range.end.getMonth(), range.end.getDate())
  return dk >= sk && dk <= ek
}

function HistoryList({ historyRequests, busyId, onRemove }) {
  const today = new Date()
  const todayKey = dateKey(today.getFullYear(), today.getMonth(), today.getDate())

  const [category, setCategory] = useState('all')
  const [period, setPeriod] = useState('day')
  const [periodOffset, setPeriodOffset] = useState(0)
  const [dateFilter, setDateFilter] = useState(todayKey)
  const [pickerOpen, setPickerOpen] = useState(false)
  const [openDate, setOpenDate] = useState(null)

  const range = (period === 'month' || period === 'week') ? periodRange(period, periodOffset) : null

  const countsByDate = {}
  for (const r of historyRequests) {
    const key = localDateKey(r.requested_at)
    countsByDate[key] = (countsByDate[key] || 0) + 1
  }

  const periodFiltered = period === 'day' && dateFilter
    ? historyRequests.filter((r) => localDateKey(r.requested_at) === dateFilter)
    : period === 'all'
      ? historyRequests
      : historyRequests.filter((r) => inRange(r.requested_at, range))
  const filtered = category === 'all' ? periodFiltered : periodFiltered.filter((r) => r.resource_type === category)
  const grouped = groupByDate(filtered)
  const counts = { all: periodFiltered.length }
  for (const r of periodFiltered) counts[r.resource_type] = (counts[r.resource_type] || 0) + 1

  const changePeriod = (p) => { setPeriod(p); setPeriodOffset(0); setDateFilter(p === 'day' ? todayKey : '') }

  return (
    <div>
      <div className="ac-filter-row">
        {PERIOD_OPTIONS.map((p) => (
          <button key={p.key} className={`ac-filter-btn ${period === p.key ? 'active' : ''}`} onClick={() => changePeriod(p.key)}>
            {p.label}
          </button>
        ))}
      </div>
      <div className="ac-filter-row">
        {(period === 'month' || period === 'week') && range && (
          <div className="ac-period-nav">
            <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => setPeriodOffset(periodOffset - 1)}>‹</button>
            <span className="ac-period-label">{range.label}</span>
            <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => setPeriodOffset(periodOffset + 1)}>›</button>
          </div>
        )}
        {period === 'day' && (
          <div className="ac-date-picker">
            <button className="ac-date-trigger" onClick={() => setPickerOpen(true)}>
              {dateFilter || '날짜 선택'}
            </button>
          </div>
        )}
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
      {/* 날짜당 한 줄만 — 건수가 늘어도 화면 길이가 날짜 수만큼만 늘어남 */}
      <div className="ac-daylist">
        {grouped.map(([date, items]) => (
          <div key={date} className="ac-dayrow" onClick={() => setOpenDate(date)}>
            <span className="ac-dayrow-date">{date}</span>
            <span className="ac-dayrow-total">{items.length}건</span>
            <span className="ac-dayrow-breakdown">
              {statusSummary(items).map(({ status, count, meta }) => (
                <span key={status} className="ac-dayrow-stat">
                  <i className="ac-dayrow-dot" style={{ background: meta.color }} />
                  {meta.label} {count}
                </span>
              ))}
            </span>
            <span className="ac-dayrow-open">보기</span>
          </div>
        ))}
      </div>

      {openDate && (
        <DayDetailModal
          date={openDate}
          items={grouped.find(([d]) => d === openDate)?.[1] || []}
          busyId={busyId}
          onRemove={onRemove}
          onClose={() => setOpenDate(null)}
        />
      )}
    </div>
  )
}

// 발급된 액세스키를 한 번만 보여주는 팝업 (DB에는 저장하지 않음 — 닫으면 다시 못 봄)
function RevealKeyPopup({ result, onClose }) {
  const copy = (text) => navigator.clipboard?.writeText(text)
  return (
    <div className="ac-datepop-backdrop" onClick={onClose}>
      <div className="ac-datepop" onClick={(e) => e.stopPropagation()}>
        <div className="ac-cal-title">{result.user_name} 액세스키 발급됨</div>
        <p className="ac-cred-note">이 화면을 닫으면 Secret Key는 다시 조회할 수 없습니다. 지금 바로 복사해두세요.</p>
        <div className="ac-form-row">
          <div className="ac-field">
            <label className="ac-label">Access Key ID</label>
            <input className="ac-input" readOnly value={result.access_key_id} onFocus={(e) => e.target.select()} />
          </div>
          <button className="ac-btn ac-btn-secondary" onClick={() => copy(result.access_key_id)}>복사</button>
        </div>
        <div className="ac-form-row">
          <div className="ac-field">
            <label className="ac-label">Secret Access Key</label>
            <input className="ac-input" readOnly value={result.secret_access_key} onFocus={(e) => e.target.select()} />
          </div>
          <button className="ac-btn ac-btn-secondary" onClick={() => copy(result.secret_access_key)}>복사</button>
        </div>
        <div className="ac-datepop-actions">
          <button className="ac-btn" onClick={onClose}>확인했습니다, 닫기</button>
        </div>
      </div>
    </div>
  )
}

// 신청 대기/이력 관리 (통합 큐)
function RequestQueue() {
  const [requests, setRequests] = useState([])
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState(null)
  const [revealKey, setRevealKey] = useState(null)
  const [loadError, setLoadError] = useState(null)

  const pendingRequests = requests.filter((r) => r.status === 'pending')
  const historyRequests = requests.filter((r) => r.status !== 'pending')

  const fetchRequests = async () => {
    setLoading(true)
    const { rows, error } = await fetchRows(
      supabase.from('aws_requests').select('*').order('requested_at', { ascending: false }).limit(100),
      '신청 목록')
    setRequests(rows)
    setLoadError(error)
    setLoading(false)
  }

  useEffect(() => { fetchRequests() }, [])

  // Terraform 에이전트가 처리할 리소스 타입 — Edge Function 대신 DB 상태만 변경
  const TERRAFORM_TYPES = ['vpc', 'subnet', 'ec2_instance', 'internet_gateway', 'route_table']

  const approve = async (id, opts) => {
    setBusyId(id)
    const req = requests.find((r) => r.id === id)

    const actionLabel = ACTION_LABEL[req?.action] || req?.action || ''
    const reqName = req?.title || req?.target_id || ''

    if (req && TERRAFORM_TYPES.includes(req.resource_type)) {
      // Terraform 대상: DB 상태만 approved로 변경 → 로컬 에이전트가 처리.
      // RLS로 관리자만 update 가능하므로 실패할 수 있다. 조용히 넘기면 승인된 줄 착각한다.
      const { ok, error } = await runWrite(
        supabase.from('aws_requests')
          .update({ status: 'approved', reviewed_at: new Date().toISOString() })
          .eq('id', id).eq('status', 'pending').select(),
        '승인')
      if (!ok) {
        alert(error)
      } else {
        notify(`✅ **승인 (Terraform 대기)**\n${actionLabel}: ${reqName}\n→ 로컬 에이전트가 자동 적용 예정`)
      }
    } else {
      // SG/WAF/IAM: Edge Function으로 즉시 적용
      const data = await callFunction('aws-request-apply', { request_id: id, issue_key: !!opts?.issueKey })
      if (!data.ok) {
        alert('적용 실패: ' + data.error)
        notify(`❌ **적용 실패**\n${actionLabel}: ${reqName}\n오류: ${data.error}`)
      } else {
        notify(`✅ **승인 + 적용 완료**\n${actionLabel}: ${reqName}`)
        if (data.result?.access_key_id && data.result?.secret_access_key) setRevealKey(data.result)
      }
    }
    await fetchRequests()
    setBusyId(null)
  }

  const reject = async (id) => {
    const reason = prompt('거부 사유를 입력해주세요.')
    if (reason === null) return
    setBusyId(id)
    const req = requests.find((r) => r.id === id)
    const actionLabel = ACTION_LABEL[req?.action] || req?.action || ''
    const reqName = req?.title || req?.target_id || ''
    const { ok, error } = await runWrite(
      supabase.from('aws_requests').update({
        status: 'rejected',
        reviewed_at: new Date().toISOString(),
        error_message: reason.trim() || null,
      }).eq('id', id).eq('status', 'pending').select(),
      '거부')
    if (!ok) {
      alert(error)
    } else {
      notify(`🚫 **신청 거부**\n${actionLabel}: ${reqName}${reason.trim() ? `\n사유: ${reason.trim()}` : ''}`)
    }
    await fetchRequests()
    setBusyId(null)
  }

  const removeRequest = async (id) => {
    if (!confirm('이 신청을 목록에서 삭제할까요?')) return
    setBusyId(id)
    const { ok, error } = await runWrite(
      supabase.from('aws_requests').delete().eq('id', id).select(), '삭제')
    setBusyId(null)
    if (!ok) return alert(error)
    await fetchRequests()
  }

  return (
    <>
      {revealKey && <RevealKeyPopup result={revealKey} onClose={() => setRevealKey(null)} />}
      <ErrorBanner message={loadError} onRetry={fetchRequests} />
      <div className={`ac-card ac-card-wide ${pendingRequests.length > 0 ? 'ac-card-alert' : ''}`}>
        <div className="ac-card-title">
          처리 대기중
          {pendingRequests.length > 0 && <span className="ac-count-badge">{pendingRequests.length}</span>}
        </div>
        {loading && <div className="ac-empty">불러오는 중...</div>}
        {!loading && pendingRequests.length === 0 && <div className="ac-empty">대기중인 신청이 없습니다.</div>}
        <div className="ac-snapshot-list">
          {pendingRequests.map((r) => (
            <ReqCard key={r.id} r={r} busyId={busyId} onApprove={approve} onReject={reject} onRemove={removeRequest} />
          ))}
        </div>
      </div>

      <div className="ac-card ac-card-wide ac-card-muted">
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
  return (
    <div className="ac-page">
      <h2 className="ac-title">관리자 승인</h2>
      <p className="ac-sub">신청을 검토해 승인하면 실제 AWS에 반영됩니다. 적용 결과 확인은 "AWS 현황" 페이지에서 합니다.</p>

      <div className="ac-grid">
        <RequestQueue />
      </div>
    </div>
  )
}
