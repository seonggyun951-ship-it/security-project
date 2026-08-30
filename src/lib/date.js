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

// "3일" "6시간" "12분" — 승인 대기가 얼마나 묵었는지.
// 관리자가 목록에서 가장 먼저 묻는 질문이라 절대 시각보다 이게 앞에 온다.
export function elapsedLabel(ts) {
  const ms = Date.now() - new Date(ts).getTime()
  if (ms < 0) return '방금'
  const min = Math.floor(ms / 60000)
  if (min < 1) return '방금'
  if (min < 60) return `${min}분`
  const hr = Math.floor(min / 60)
  if (hr < 24) return `${hr}시간`
  const day = Math.floor(hr / 24)
  if (day < 30) return `${day}일`
  return `${Math.floor(day / 30)}개월`
}

// 오래 묵은 신청은 눈에 띄어야 한다 (기본 2일)
export function isAged(ts, days = 2) {
  return Date.now() - new Date(ts).getTime() > days * 86400000
}

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

// offset은 현재 기준 상대 위치 (-1 = 어제/지난주/지난달)
export function periodRange(mode, offset) {
  const now = new Date()
  if (mode === 'day') {
    const d = new Date(now)
    d.setDate(d.getDate() + offset)
    const label = offset === 0 ? '오늘'
      : `${d.getFullYear()}년 ${d.getMonth() + 1}월 ${d.getDate()}일`
    return { start: d, end: d, label }
  }
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

// 기간을 DB 조회 조건으로 쓸 때. 시작일 00:00:00 ~ 종료일 23:59:59.999를
// ISO로 만든다. 날짜만 넘기면 종료일 당일 건이 통째로 빠진다.
export function rangeToIso(range) {
  if (!range) return null
  const s = new Date(range.start.getFullYear(), range.start.getMonth(), range.start.getDate(), 0, 0, 0, 0)
  const e = new Date(range.end.getFullYear(), range.end.getMonth(), range.end.getDate(), 23, 59, 59, 999)
  return { from: s.toISOString(), to: e.toISOString() }
}

// 'YYYY-MM-DD' 문자열 하루짜리 기간
export function dayRange(key) {
  const d = new Date(key + 'T00:00:00')
  return { start: d, end: d, label: key }
}

// 'YYYY-MM-DD'가 속한 주의 시작일(일요일). 주 시작 규칙은 여기 한 곳에만 둔다 —
// periodRange('week')와 다르게 잡으면 주별 목록과 기간 이동이 어긋난다.
export function weekStartKey(key) {
  const d = new Date(key + 'T00:00:00')
  d.setDate(d.getDate() - d.getDay())
  return localDateKey(d)
}

// 날짜별 집계를 주 또는 월 단위로 묶는다.
// [{ key, label, range, n, bad, applied, rejected, failed, cancelled }] — 최신 먼저.
//
// 주·월 함수를 DB에 따로 만들지 않고 일 단위 집계를 화면에서 묶는 이유:
// 주 시작 요일 같은 규칙이 SQL과 화면 양쪽에 생기면 반드시 어긋난다.
export function rollup(dayCounts, mode) {
  const acc = {}
  for (const [day, c] of Object.entries(dayCounts || {})) {
    const key = mode === 'week' ? weekStartKey(day) : day.slice(0, 7)
    if (!acc[key]) acc[key] = { key, n: 0, bad: 0, applied: 0, rejected: 0, failed: 0, cancelled: 0 }
    for (const f of ['n', 'bad', 'applied', 'rejected', 'failed', 'cancelled']) {
      acc[key][f] += c[f] || 0
    }
  }
  return Object.values(acc)
    .sort((a, b) => b.key.localeCompare(a.key))
    .map((b) => {
      if (mode === 'week') {
        const s = new Date(b.key + 'T00:00:00')
        const e = new Date(s); e.setDate(s.getDate() + 6)
        const fmt = (d) => `${d.getMonth() + 1}/${d.getDate()}`
        return { ...b, label: `${fmt(s)} ~ ${fmt(e)}`, sub: `${s.getFullYear()}년`, range: { start: s, end: e } }
      }
      const [y, m] = b.key.split('-').map(Number)
      const s = new Date(y, m - 1, 1)
      const e = new Date(y, m, 0)
      return { ...b, label: `${y}년 ${m}월`, sub: `${e.getDate()}일`, range: { start: s, end: e } }
    })
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
