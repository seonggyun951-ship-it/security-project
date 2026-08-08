import { useState } from 'react'
import { REQ_STATUS_META, reqTitle, reqDetailLines } from '../lib/aws'
import { WEEKDAYS, dateKey, localDateKey, todayKey, monthCells, groupByDate } from '../lib/date'

// AWS 신청 페이지(SG/WAF/IAM)와 인프라 신청 페이지(VPC/서브넷/EC2)가 함께 쓰는 "내 신청 현황" 컴포넌트.
// 이전에는 두 페이지에 거의 같은 코드가 각각 복사돼 있었다.

// 'approved'는 Terraform 대상만 머무르는 상태다. SG/WAF/IAM은 이 상태를 거치지 않지만
// 빈 그룹은 아래에서 걸러지므로 순서 목록을 공유해도 문제없다.
const STATUS_GROUP_ORDER = ['pending', 'approved', 'failed', 'applied', 'rejected']

// showResult: Terraform으로 만든 리소스는 생성된 AWS ID를 따로 보여준다.
// SG/WAF는 reqTitle에 이미 생성 ID가 붙어서 중복이라 끈다.
export function MyReqRow({ r, showResult = false }) {
  const [open, setOpen] = useState(false)
  const detail = reqDetailLines(r)
  const d = new Date(r.requested_at)
  const shortDate = `${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`

  return (
    <div className={`ac-myreq ${r.status === 'rejected' ? 'ac-myreq-rejected' : ''}`}>
      <div className="ac-myreq-top" onClick={() => setOpen((v) => !v)}>
        <span className="ac-myreq-title">{reqTitle(r)}</span>
        <span className="ac-myreq-date">{shortDate}</span>
        <span className="ac-expand-icon">{open ? '▲' : '▼'}</span>
      </div>
      {open && (
        <div className="ac-myreq-body">
          {detail.map((line, i) => <div key={i} className="ac-req-reason">{line}</div>)}
          {r.reason && <div className="ac-req-reason">사유: {r.reason}</div>}
          {showResult && r.result?.created_id && (
            <div className="ac-req-meta">생성 ID: {r.result.created_id}</div>
          )}
          {showResult && r.result?.terraform && (
            <div className="ac-req-meta">🔧 Terraform으로 적용됨</div>
          )}
          {r.status === 'rejected' && r.error_message && (
            <div className="ac-reject-box">거부 사유: {r.error_message}</div>
          )}
          {r.status !== 'rejected' && r.error_message && <div className="ac-req-error">{r.error_message}</div>}
          <div className="ac-req-meta">{d.toLocaleString('ko-KR')}</div>
        </div>
      )}
    </div>
  )
}

// 상태별로 묶고, 그 안에서 다시 날짜별로 묶는다. 건수가 늘어도 화면이 길어지지 않게 접어둔다.
export function MyReqGrouped({ requests, showResult = false }) {
  const [openGroup, setOpenGroup] = useState('pending')

  const groups = STATUS_GROUP_ORDER.map((status) => {
    const meta = REQ_STATUS_META[status] || { label: status, color: '#94a3b8' }
    const items = requests.filter((r) => r.status === status)
    return { status, meta, items, dates: groupByDate(items) }
  }).filter((g) => g.items.length > 0)

  return (
    <div className="ac-status-groups">
      {groups.map((g) => (
        <div key={g.status} className="ac-sgroup">
          <div
            className={`ac-sgroup-head ${openGroup === g.status ? 'is-open' : ''}`}
            onClick={() => setOpenGroup(openGroup === g.status ? null : g.status)}
          >
            <i className="ac-sgroup-dot" style={{ background: g.meta.color }} />
            <span className="ac-sgroup-label">{g.meta.label}</span>
            <span className="ac-sgroup-count">{g.items.length}건</span>
            <span className="ac-expand-icon">{openGroup === g.status ? '▲' : '▼'}</span>
          </div>
          {openGroup === g.status && (
            <div className="ac-sgroup-body">
              {g.dates.map(([date, items]) => (
                <div key={date} className="ac-sgroup-date">
                  <div className="ac-sgroup-date-label">{date}</div>
                  {items.map((r) => <MyReqRow key={r.id} r={r} showResult={showResult} />)}
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

// 신청이 있는 날짜만 선택 가능한 작은 달력
export function MiniCal({ requests, selected, onSelect }) {
  const today = new Date()
  const base = selected ? new Date(selected + 'T00:00:00') : today
  const [viewDate, setViewDate] = useState(new Date(base.getFullYear(), base.getMonth(), 1))

  const year = viewDate.getFullYear()
  const month = viewDate.getMonth()
  const cells = monthCells(year, month)
  const tKey = todayKey()

  const hasData = new Set()
  for (const r of requests) hasData.add(localDateKey(r.requested_at))

  return (
    <div className="ac-minical">
      <div className="ac-minical-head">
        <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => setViewDate(new Date(year, month - 1, 1))}>‹</button>
        <span className="ac-minical-title">{year}년 {month + 1}월</span>
        <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => setViewDate(new Date(year, month + 1, 1))}>›</button>
      </div>
      <div className="ac-minical-grid">
        {WEEKDAYS.map((w) => <div key={w} className="ac-minical-wday">{w}</div>)}
        {cells.map((d, i) => {
          if (d === null) return <div key={i} className="ac-minical-cell ac-minical-empty" />
          const key = dateKey(year, month, d)
          const has = hasData.has(key)
          const isToday = key === tKey
          const isSel = key === selected
          return (
            <div
              key={i}
              className={`ac-minical-cell ${has ? 'has-data' : ''} ${isToday ? 'is-today' : ''} ${isSel ? 'is-selected' : ''}`}
              onClick={() => has && onSelect(key)}
            >
              {d}
            </div>
          )
        })}
      </div>
    </div>
  )
}
