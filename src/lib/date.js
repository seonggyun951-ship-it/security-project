// 날짜/기간 공통 헬퍼.
// 이전에는 localDateKey가 5개 파일, WEEKDAYS가 4개 파일에 각각 복사돼 있었다.

export const WEEKDAYS = ['일', '월', '화', '수', '목', '금', '토']

export const pad = (n) => String(n).padStart(2, '0')

// month는 0-based (Date와 동일)
export const dateKey = (y, month, d) => `${y}-${pad(month + 1)}-${pad(d)}`

// DB의 timestamptz는 UTC라, 문자열을 그냥 자르면 한국 시간과 날짜가 어긋난다(UTC+9).
// 반드시 로컬 시간으로 변환한 뒤 날짜를 뽑을 것.
export function localDateKey(ts) {
  const d = new Date(ts)
  return dateKey(d.getFullYear(), d.getMonth(), d.getDate())
}

export const todayKey = () => localDateKey(new Date())

// 달력 그리드 셀. 1일이 시작되는 요일만큼 앞을 null로 채운다.
export function monthCells(year, month) {
  const firstDayOfWeek = new Date(year, month, 1).getDay()
  const daysInMonth = new Date(year, month + 1, 0).getDate()
  const cells = []
  for (let i = 0; i < firstDayOfWeek; i++) cells.push(null)
  for (let d = 1; d <= daysInMonth; d++) cells.push(d)
  return cells
}

// 신청 목록을 날짜별로 묶어 [날짜, 항목[]] 배열로 (최신 날짜 먼저)
export function groupByDate(items, tsKey = 'requested_at') {
  const groups = {}
  for (const item of items) {
    const date = localDateKey(item[tsKey])
    if (!groups[date]) groups[date] = []
    groups[date].push(item)
  }
  return Object.entries(groups).sort((a, b) => b[0].localeCompare(a[0]))
}

// 날짜별 건수 { '2026-08-08': 3, ... }
export function countsByDate(items, tsKey = 'requested_at') {
  const counts = {}
  for (const item of items) {
    const key = localDateKey(item[tsKey])
    counts[key] = (counts[key] || 0) + 1
  }
  return counts
}

export const PERIOD_OPTIONS = [
  { key: 'day', label: '일별' },
  { key: 'week', label: '주별' },
  { key: 'month', label: '월별' },
  { key: 'all', label: '전체' },
]

// offset은 현재 기준 상대 위치 (-1 = 지난달/지난주)
export function periodRange(mode, offset) {
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

// 시각이 아니라 날짜 단위로 비교한다 (시분초 때문에 경계일이 빠지지 않도록)
export function inRange(ts, range) {
  if (!range) return true
  const d = new Date(ts)
  const dk = new Date(d.getFullYear(), d.getMonth(), d.getDate())
  const sk = new Date(range.start.getFullYear(), range.start.getMonth(), range.start.getDate())
  const ek = new Date(range.end.getFullYear(), range.end.getMonth(), range.end.getDate())
  return dk >= sk && dk <= ek
}
