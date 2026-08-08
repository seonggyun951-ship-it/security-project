import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'
import { GcpReqCard, GCP_REQ_STATUS_META } from '../lib/gcp'
import { notify } from '../lib/discord'
import { fetchRows, runWrite } from '../lib/db'
import ErrorBanner from '../components/ErrorBanner'
import {
  WEEKDAYS, dateKey, localDateKey, todayKey, monthCells,
  groupByDate, countsByDate, PERIOD_OPTIONS, periodRange, inRange,
} from '../lib/date'

function DatePickerPopup({ countsByDate, selected, onSelect, onClose }) {
  const today = new Date()
  const base = selected ? new Date(selected + 'T00:00:00') : today
  const [viewDate, setViewDate] = useState(new Date(base.getFullYear(), base.getMonth(), 1))

  const year = viewDate.getFullYear()
  const month = viewDate.getMonth()
  const cells = monthCells(year, month)
  const tKey = todayKey()

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
            const isToday = key === tKey
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

const GCP_CATEGORIES = [
  { key: 'all', label: '전체' },
  { key: 'firewall_rule', label: 'Firewall' },
  { key: 'cloud_armor', label: 'Cloud Armor' },
  { key: 'service_account', label: 'IAM' },
]

const STATUS_ORDER = ['applied', 'rejected', 'failed', 'approved']

function statusSummary(items) {
  const c = {}
  for (const r of items) c[r.status] = (c[r.status] || 0) + 1
  return STATUS_ORDER.filter((s) => c[s]).map((s) => ({ status: s, count: c[s], meta: GCP_REQ_STATUS_META[s] }))
}

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
            {items.map((r) => <GcpReqCard key={r.id} r={r} busyId={busyId} onRemove={onRemove} />)}
          </div>
        </div>
      </div>
    </div>
  )
}

function HistoryList({ historyRequests, busyId, onRemove }) {
  const tKey = todayKey()

  const [category, setCategory] = useState('all')
  const [period, setPeriod] = useState('day')
  const [periodOffset, setPeriodOffset] = useState(0)
  const [dateFilter, setDateFilter] = useState(tKey)
  const [pickerOpen, setPickerOpen] = useState(false)
  const [openDate, setOpenDate] = useState(null)

  const range = (period === 'month' || period === 'week') ? periodRange(period, periodOffset) : null
  const dayCounts = countsByDate(historyRequests)

  const periodFiltered = period === 'day' && dateFilter
    ? historyRequests.filter((r) => localDateKey(r.requested_at) === dateFilter)
    : period === 'all'
      ? historyRequests
      : historyRequests.filter((r) => inRange(r.requested_at, range))
  const filtered = category === 'all' ? periodFiltered : periodFiltered.filter((r) => r.resource_type === category)
  const grouped = groupByDate(filtered)
  const counts = { all: periodFiltered.length }
  for (const r of periodFiltered) counts[r.resource_type] = (counts[r.resource_type] || 0) + 1

  const changePeriod = (p) => { setPeriod(p); setPeriodOffset(0); setDateFilter(p === 'day' ? tKey : '') }

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
            countsByDate={dayCounts}
            selected={dateFilter}
            onSelect={(key) => { setDateFilter(key); setPickerOpen(false) }}
            onClose={() => setPickerOpen(false)}
          />
        )}
        {GCP_CATEGORIES.map((c) => (
          <button key={c.key} className={`ac-filter-btn ${category === c.key ? 'active' : ''}`} onClick={() => setCategory(c.key)}>
            {c.label} {counts[c.key] || 0}
          </button>
        ))}
      </div>
      {grouped.length === 0 && <div className="ac-empty">해당 항목이 없습니다.</div>}
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

function RequestQueue() {
  const [requests, setRequests] = useState([])
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState(null)
  const [loadError, setLoadError] = useState(null)

  const pendingRequests = requests.filter((r) => r.status === 'pending')
  const historyRequests = requests.filter((r) => r.status !== 'pending')

  const fetchRequests = async () => {
    setLoading(true)
    const { rows, error } = await fetchRows(
      supabase.from('gcp_requests').select('*').order('requested_at', { ascending: false }).limit(100),
      'GCP 신청 목록')
    setRequests(rows)
    setLoadError(error)
    setLoading(false)
  }

  useEffect(() => { fetchRequests() }, [])

  const approve = async (id) => {
    setBusyId(id)
    const req = requests.find((r) => r.id === id)
    const reqName = req?.title || req?.target_id || ''
    const { ok, error } = await runWrite(
      supabase.from('gcp_requests')
        .update({ status: 'approved', reviewed_at: new Date().toISOString() })
        .eq('id', id).eq('status', 'pending').select(),
      'GCP 승인')
    if (!ok) {
      alert(error)
    } else {
      notify(`✅ **GCP 신청 승인**\n${req?.action || ''}: ${reqName}`)
    }
    await fetchRequests()
    setBusyId(null)
  }

  const reject = async (id) => {
    const reason = prompt('거부 사유를 입력해주세요.')
    if (reason === null) return
    setBusyId(id)
    const req = requests.find((r) => r.id === id)
    const reqName = req?.title || req?.target_id || ''
    const { ok, error } = await runWrite(
      supabase.from('gcp_requests').update({
        status: 'rejected',
        reviewed_at: new Date().toISOString(),
        error_message: reason.trim() || null,
      }).eq('id', id).eq('status', 'pending').select(),
      'GCP 거부')
    if (!ok) {
      alert(error)
    } else {
      notify(`🚫 **GCP 신청 거부**\n${req?.action || ''}: ${reqName}${reason.trim() ? `\n사유: ${reason.trim()}` : ''}`)
    }
    await fetchRequests()
    setBusyId(null)
  }

  const removeRequest = async (id) => {
    if (!confirm('이 신청을 목록에서 삭제할까요?')) return
    setBusyId(id)
    const { ok, error } = await runWrite(
      supabase.from('gcp_requests').delete().eq('id', id).select(), 'GCP 삭제')
    setBusyId(null)
    if (!ok) return alert(error)
    await fetchRequests()
  }

  return (
    <>
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
            <GcpApprovalCard key={r.id} r={r} busyId={busyId} onApprove={approve} onReject={reject} onRemove={removeRequest} />
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

function GcpApprovalCard({ r, busyId, onApprove, onReject, onRemove }) {
  const meta = GCP_REQ_STATUS_META[r.status] || { label: r.status, color: '#94a3b8' }
  const detail = (() => {
    const p = r.payload || {}
    if (r.action === 'create_firewall') {
      return (p.rules || []).map((rule) => {
        const dir = rule.direction === 'ingress' ? 'IN' : 'OUT'
        return `${dir} ${rule.protocol} ${rule.port || '*'} ${rule.cidr}`
      })
    }
    if (r.action === 'create_armor_policy') return [`기본 액션: ${p.default_action === 'deny' ? '차단' : '허용'}`]
    if (r.action === 'add_armor_rules') return (p.rules || []).map((rule) => `${rule.type}: ${rule.cidrs || rule.expression || ''}`)
    if (r.action === 'create_service_account') return [`계정: ${p.account_id}`, `역할: ${p.role}`]
    return []
  })()
  const busy = busyId === r.id

  return (
    <div className="ac-req">
      <div className="ac-req-top">
        <span className="ac-req-status" style={{ background: meta.color }}>{meta.label}</span>
        <span className="ac-req-title">{r.action}: {r.title || r.target_id || ''}</span>
      </div>
      {detail.map((line, i) => <div key={i} className="ac-req-reason">{line}</div>)}
      {r.reason && <div className="ac-req-reason">사유: {r.reason}</div>}
      {r.requester_email && <div className="ac-req-meta">신청자: {r.requester_email}</div>}
      {r.error_message && <div className="ac-req-error">{r.error_message}</div>}
      <div className="ac-req-meta">{new Date(r.requested_at).toLocaleString('ko-KR')}</div>
      {r.status === 'pending' && onApprove && (
        <div className="ac-req-actions">
          <button className="ac-btn" disabled={busy} onClick={() => onApprove(r.id)}>{busy ? '처리 중...' : '승인'}</button>
          <button className="ac-btn ac-btn-secondary" disabled={busy} onClick={() => onReject(r.id)}>거절</button>
        </div>
      )}
      {(r.status === 'failed' || r.status === 'rejected') && onRemove && (
        <div className="ac-req-actions">
          <button className="ac-btn ac-btn-secondary" disabled={busy} onClick={() => onRemove(r.id)}>{busy ? '삭제 중...' : '목록에서 삭제'}</button>
        </div>
      )}
    </div>
  )
}

export default function GcpApproval() {
  return (
    <div className="ac-page">
      <h2 className="ac-title">GCP 관리자 승인</h2>
      <p className="ac-sub">GCP 리소스 신청을 검토하고 승인합니다. GCP 자동화 연동 시 실제 반영됩니다.</p>

      <div className="ac-grid">
        <RequestQueue />
      </div>
    </div>
  )
}
