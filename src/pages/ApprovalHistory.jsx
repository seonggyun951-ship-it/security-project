import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'
import { ReqDrawer, ReqTable } from '../lib/aws'
import { fetchRows, runWrite } from '../lib/db'
import ErrorBanner from '../components/ErrorBanner'
import {
  WEEKDAYS, dateKey, localDateKey, todayKey, monthCells,
  countsByDate, PERIOD_OPTIONS, periodRange, inRange,
} from '../lib/date'

// 처리가 끝난 신청만 본다. 대기중인 건은 '관리자 승인' 화면이 다룬다.
const DONE = ['applied', 'rejected', 'failed', 'cancelled']

const CATEGORIES = [
  { key: 'all', label: '전체' },
  { key: 'security_group', label: 'SG' },
  { key: 'waf_web_acl', label: 'WAF' },
  { key: 'iam_user', label: 'IAM' },
  { key: 'vpc', label: 'VPC' },
  { key: 'subnet', label: '서브넷' },
  { key: 'ec2_instance', label: 'EC2' },
  { key: 'internet_gateway', label: 'IGW' },
  { key: 'route_table', label: 'RT' },
]

// 상태별 건수를 한 줄로 — 달력 칸과 목록 머리에서 같이 쓴다
function statusCounts(items) {
  const c = {}
  for (const r of items) c[r.status] = (c[r.status] || 0) + 1
  return c
}

// 달 전체를 한눈에. 날짜를 누르면 그날 것만 목록에 남는다.
function MonthCalendar({ items, selected, onSelect }) {
  const today = new Date()
  const base = selected ? new Date(selected + 'T00:00:00') : today
  const [view, setView] = useState(new Date(base.getFullYear(), base.getMonth(), 1))

  const year = view.getFullYear()
  const month = view.getMonth()
  const cells = monthCells(year, month)
  const tKey = todayKey()
  const counts = countsByDate(items)

  // 그날 처리 결과에 실패·거절이 있으면 칸에 표시해 눈에 걸리게 한다
  const byDate = {}
  for (const r of items) {
    const k = localDateKey(r.requested_at)
    ;(byDate[k] ||= []).push(r)
  }

  return (
    <div className="hc">
      <div className="hc-head">
        <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => setView(new Date(year, month - 1, 1))}>‹</button>
        <span className="hc-title">{year}년 {month + 1}월</span>
        <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => setView(new Date(year, month + 1, 1))}>›</button>
        {selected && <button className="ac-btn ac-btn-secondary hc-clear" onClick={() => onSelect('')}>날짜 해제</button>}
      </div>
      <div className="hc-grid">
        {WEEKDAYS.map((w) => <div key={w} className="hc-wday">{w}</div>)}
        {cells.map((d, i) => {
          if (d === null) return <div key={i} className="hc-cell is-empty" />
          const key = dateKey(year, month, d)
          const dayItems = byDate[key] || []
          const n = counts[key] || 0
          const bad = dayItems.filter((r) => r.status === 'failed' || r.status === 'rejected').length
          return (
            <button key={i}
              className={`hc-cell ${n > 0 ? 'has-data' : ''} ${key === tKey ? 'is-today' : ''} ${key === selected ? 'is-selected' : ''}`}
              onClick={() => n > 0 && onSelect(key === selected ? '' : key)}
              disabled={n === 0}
            >
              <span className="hc-day">{d}</span>
              {n > 0 && (
                <span className="hc-marks">
                  <span className="hc-n">{n}</span>
                  {bad > 0 && <i className="hc-dot" />}
                </span>
              )}
            </button>
          )
        })}
      </div>
    </div>
  )
}

export default function ApprovalHistory() {
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(null)
  const [busyId, setBusyId] = useState(null)
  const [openReq, setOpenReq] = useState(null)

  const [period, setPeriod] = useState('all')   // 기본을 전체(달력)로 — 이력은 훑어보는 화면이다
  const [periodOffset, setPeriodOffset] = useState(0)
  const [dateFilter, setDateFilter] = useState('')
  const [category, setCategory] = useState('all')

  const fetchAll = async () => {
    setLoading(true)
    const { rows: r, error } = await fetchRows(
      supabase.from('aws_requests').select('*')
        .in('status', DONE)
        .order('requested_at', { ascending: false }).limit(300),
      '처리 이력')
    setRows(r)
    setLoadError(error)
    setLoading(false)
  }

  useEffect(() => { fetchAll() }, [])

  const removeRequest = async (id) => {
    if (!confirm('이 신청을 목록에서 삭제할까요?')) return
    setBusyId(id)
    const { ok, error } = await runWrite(
      supabase.from('aws_requests').delete().eq('id', id).select(), '삭제')
    setBusyId(null)
    if (!ok) return alert(error)
    setOpenReq(null)
    await fetchAll()
  }

  const range = (period === 'month' || period === 'week') ? periodRange(period, periodOffset) : null

  // 기간 → 날짜 → 종류 순으로 좁힌다
  const byPeriod = period === 'all' ? rows : rows.filter((r) => inRange(r.requested_at, range))
  const byDate = dateFilter ? byPeriod.filter((r) => localDateKey(r.requested_at) === dateFilter) : byPeriod
  const shown = category === 'all' ? byDate : byDate.filter((r) => r.resource_type === category)

  const counts = { all: byDate.length }
  for (const r of byDate) counts[r.resource_type] = (counts[r.resource_type] || 0) + 1
  const st = statusCounts(shown)

  const changePeriod = (p) => { setPeriod(p); setPeriodOffset(0); setDateFilter('') }

  return (
    <div className="ap-page">
      <div className="ap">
        <section className="ap-col">
          <div className="ap-head">
            <div className="ap-h1">승인 이력</div>
            <div className="ap-h2">
              {shown.length}건
              {st.applied > 0 && ` · 적용 ${st.applied}`}
              {st.rejected > 0 && ` · 거절 ${st.rejected}`}
              {st.failed > 0 && ` · 실패 ${st.failed}`}
              {st.cancelled > 0 && ` · 취소 ${st.cancelled}`}
            </div>
          </div>

          <div className="ap-chips">
            {PERIOD_OPTIONS.map((p) => (
              <button key={p.key} className={`ap-chip ${period === p.key ? 'on' : ''}`} onClick={() => changePeriod(p.key)}>
                {p.label}
              </button>
            ))}
            {range && (
              <span className="hc-nav">
                <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => setPeriodOffset(periodOffset - 1)}>‹</button>
                <span className="hc-nav-label">{range.label}</span>
                <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => setPeriodOffset(periodOffset + 1)}>›</button>
              </span>
            )}
          </div>

          <div className="ap-chips">
            {CATEGORIES.map((c) => (
              <button key={c.key} className={`ap-chip ${category === c.key ? 'on' : ''}`} onClick={() => setCategory(c.key)}>
                {c.label} {counts[c.key] || 0}
              </button>
            ))}
          </div>

          <div className="ap-body">
            <ErrorBanner message={loadError} onRetry={fetchAll} />
            {loading && <div className="ac-empty">불러오는 중...</div>}

            {/* 전체 기간일 때만 달력 — 일·주·월은 이미 기간이 좁아 달력이 의미가 없다 */}
            {!loading && period === 'all' && (
              <MonthCalendar items={rows} selected={dateFilter} onSelect={setDateFilter} />
            )}

            {!loading && shown.length === 0 && <div className="ac-empty">해당 기간에 처리 내역이 없습니다.</div>}
            {!loading && shown.length > 0 && (
              <ReqTable requests={shown} selectedId={openReq?.id} onOpen={setOpenReq} />
            )}
          </div>
        </section>

        <ReqDrawer r={openReq} busyId={busyId}
          onClose={() => setOpenReq(null)} onRemove={removeRequest} />
      </div>
    </div>
  )
}
