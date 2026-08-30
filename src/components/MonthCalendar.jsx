import { useState } from 'react'
import { WEEKDAYS, dateKey, localDateKey, todayKey, monthCells } from '../lib/date'

// 달 전체를 한눈에. 날짜를 누르면 그날 것만 목록에 남는다.
//
// 승인 이력과 점검 이력이 같은 달력을 쓴다. 다른 것은 어느 시각 칼럼을 보느냐(tsKey)와
// 무엇을 '눈에 걸려야 하는 것'으로 볼 것이냐(isBad)뿐이라 그 둘만 밖에서 받는다.
//
// counts를 넘기면 items 대신 그걸 쓴다: { '2026-08-21': { n, bad } }.
// 목록이 최근 N건만 불러오는 화면에서는 items를 세면 안 된다 — 그 N건 밖의 날짜가
// "아무 일도 없던 날"로 보인다. 건수는 DB에서 전 기간을 세어 넘겨준다.
export default function MonthCalendar({
  items = [],
  counts = null,
  selected,
  onSelect,
  tsKey = 'requested_at',
  isBad = () => false,
}) {
  const today = new Date()
  const base = selected ? new Date(selected + 'T00:00:00') : today
  const [view, setView] = useState(new Date(base.getFullYear(), base.getMonth(), 1))

  const year = view.getFullYear()
  const month = view.getMonth()
  const cells = monthCells(year, month)
  const tKey = todayKey()

  const byDate = {}
  for (const r of items) {
    const k = localDateKey(r[tsKey])
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
          const n = counts ? (counts[key]?.n || 0) : dayItems.length
          const bad = counts ? (counts[key]?.bad || 0) : dayItems.filter(isBad).length
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
