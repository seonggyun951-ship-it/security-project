import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'
import { ACTION_LABEL, ReqDrawer, ReqTable } from '../lib/aws'
import { fetchPage } from '../lib/db'
import ErrorBanner from '../components/ErrorBanner'
import MonthCalendar from '../components/MonthCalendar'
import {
  PERIOD_OPTIONS, periodRange, rangeToIso, dayRange, rollup, todayKey, localDateKey,
} from '../lib/date'

// 처리가 끝난 신청만 본다. 대기중인 건은 '관리자 승인' 화면이 다룬다.
const DONE = ['applied', 'rejected', 'failed', 'cancelled']

// 기간 칩이 곧 보는 단위다:
//   일별 — 하루를 골라 그날 처리 내역을 본다 (‹ ›로 이동, 날짜 직접 선택)
//   주별 — 한 주를 ‹ ›로 넘기며 그 주 내역을 본다. 주는 수가 많아 훑기보다
//          최근 몇 주를 오가는 일이 대부분이라 일별과 같은 방식이 낫다
//   월별 — 월은 개수가 적어 한눈에 훑는 게 낫다. 월 목록에서 골라 들어간다
//   전체 — 목록이 아니라 달력과 요약. 어느 날로 들어갈지 고르는 자리다
//
// 날짜 선택 입력은 일별에만 둔다. 주·월에 붙어 있으면 무엇을 보는 단위인지 흐려진다.

const CATEGORIES = [
  { key: 'all', label: '전체' },
  { key: 'security_group', label: 'SG' },
  { key: 'waf_web_acl', label: 'WAF' },
  { key: 'iam_user', label: 'IAM' },
  { key: 'network_acl', label: 'NACL' },
  { key: 'vpc', label: 'VPC' },
  { key: 'subnet', label: '서브넷' },
  { key: 'ec2_instance', label: 'EC2' },
  { key: 'internet_gateway', label: 'IGW' },
  { key: 'route_table', label: 'RT' },
]

// 한 번에 받아올 건수. 상한이 있는 건 수만 건을 한꺼번에 그리면 화면이 멈추기
// 때문이지 이력을 감추려는 게 아니다. 모자라면 '더 보기'로 이어서 받고,
// 전체가 몇 건인지는 항상 같이 보여준다.
const PAGE_SIZE = 200

// 이력은 지우지 않는다. 감사 자료라 남아 있어야 하고, RLS의 DELETE 정책도 내려서
// API를 직접 불러도 지워지지 않는다 (migrations/20260821_approval_history_no_delete.sql).

function statusCounts(items) {
  const c = {}
  for (const r of items) c[r.status] = (c[r.status] || 0) + 1
  return c
}

// 그날 처리 결과에 실패·거절이 있으면 달력 칸에 점을 찍어 눈에 걸리게 한다
const isBadRequest = (r) => r.status === 'failed' || r.status === 'rejected'

const shiftDay = (key, days) => {
  const d = new Date(key + 'T00:00:00')
  d.setDate(d.getDate() + days)
  return localDateKey(d)
}

const dayLabel = (key) => {
  const d = new Date(key + 'T00:00:00')
  const base = `${d.getFullYear()}년 ${d.getMonth() + 1}월 ${d.getDate()}일`
  return key === todayKey() ? `${base} (오늘)` : base
}

// 상태별 건수 한 줄. 0인 상태는 적지 않는다 — 다 적으면 무엇이 많은지가 안 보인다.
function StatusLine({ c }) {
  const parts = [
    c.applied > 0 && <span key="a" className="ah-ok">적용 {c.applied}</span>,
    c.rejected > 0 && <span key="r" className="ah-bad">거절 {c.rejected}</span>,
    c.failed > 0 && <span key="f" className="ah-bad">실패 {c.failed}</span>,
    c.cancelled > 0 && <span key="c">취소 {c.cancelled}</span>,
  ].filter(Boolean)
  if (parts.length === 0) return null
  return <span className="ah-stat">{parts}</span>
}

// 달력에서 날짜를 누르면 오른쪽에 뜨는 그날 요약.
//
// 곧바로 일별 화면으로 넘기지 않는다 — 훑어보는 중에 날짜를 눌렀을 뿐인데 화면이
// 바뀌면 달력으로 다시 돌아와야 한다. 몇 건인지 먼저 보여주고, 볼 값어치가 있으면
// 그때 들어가게 한다. 숫자는 이미 받아둔 집계라 이 단계에서 조회가 없다.
function DaySummary({ dateKey, counts, onOpen, onClose }) {
  const c = counts || { n: 0, bad: 0, applied: 0, rejected: 0, failed: 0, cancelled: 0 }
  const rows = [
    { label: '적용', v: c.applied, cls: 'ah-ok' },
    { label: '거절', v: c.rejected, cls: 'ah-bad' },
    { label: '실패', v: c.failed, cls: 'ah-bad' },
    { label: '취소', v: c.cancelled, cls: '' },
  ]
  // 많이 한 것부터. 액션 이름은 화면 표(ACTION_LABEL)로만 옮긴다 — DB에서 번역하면
  // 같은 표가 두 곳에 생겨 한쪽만 고쳐진다.
  const actions = Object.entries(c.actions || {}).sort((a, b) => b[1] - a[1])
  return (
    <aside className="rv">
      <div className="rd-head">
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="rd-title">{dayLabel(dateKey)}</div>
          <div className="rd-sub">처리 내역 {c.n}건</div>
        </div>
        <button className="rd-x" onClick={onClose} aria-label="선택 해제">✕</button>
      </div>

      <div className="rd-body">
        {c.n === 0 ? (
          <div className="ac-empty">이 날에는 처리 내역이 없습니다.</div>
        ) : (
          <>
            {/* 무엇을 신청한 날이었는지가 먼저다. 상태는 그다음. */}
            {actions.length > 0 && (
              <>
                <div className="rd-label">신청 내용</div>
                <div className="ah-daysum">
                  {actions.map(([action, n]) => (
                    <div key={action} className="ah-dayrow">
                      <span>{ACTION_LABEL[action] || action}</span>
                      <b>{n}</b>
                    </div>
                  ))}
                </div>
              </>
            )}

            <div className="rd-label">처리 결과</div>
            <div className="ah-daysum">
              {rows.map((r) => (
                <div key={r.label} className={`ah-dayrow ${r.v > 0 ? r.cls : 'is-zero'}`}>
                  <span>{r.label}</span>
                  <b>{r.v}</b>
                </div>
              ))}
            </div>

            {c.bad > 0 && (
              <div className="ac-req-warn">⚠️ 거절·실패가 {c.bad}건 있습니다.</div>
            )}
          </>
        )}
      </div>

      {c.n > 0 && (
        <div className="rd-foot">
          <button className="ac-btn" style={{ flex: 1 }} onClick={() => onOpen(dateKey)}>
            상세 현황 보기
          </button>
        </div>
      )}
    </aside>
  )
}

export default function ApprovalHistory() {
  const [rows, setRows] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [dayCounts, setDayCounts] = useState({})
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState(null)
  const [openReq, setOpenReq] = useState(null)

  const [period, setPeriod] = useState('all')   // 기본은 전체(달력+요약) — 훑어보는 화면이다
  const [dayKey, setDayKey] = useState(todayKey())
  const [weekOffset, setWeekOffset] = useState(0)   // 0 = 이번 주
  const [bucketKey, setBucketKey] = useState(null)  // 펼친 월
  const [pickedDay, setPickedDay] = useState('')    // 달력에서 고른 날 (요약만 띄운다)
  const [category, setCategory] = useState('all')

  // 월 묶음은 DB 집계를 화면에서 굴린 것이다. 목록을 받아오지 않아도 건수가 나온다.
  const buckets = period === 'month' ? rollup(dayCounts, 'month') : []
  const bucket = bucketKey ? buckets.find((b) => b.key === bucketKey) : null
  const weekRange = period === 'week' ? periodRange('week', weekOffset) : null

  // 목록을 띄울 기간. 전체와, 월에서 아직 아무것도 안 펼친 상태에서는 목록이 없다.
  const range = period === 'day' ? dayRange(dayKey)
    : period === 'week' ? weekRange
      : (bucket ? bucket.range : null)

  const fetchAll = async () => {
    const iso = rangeToIso(range)
    if (!iso) { setRows([]); setTotal(0); setLoadError(null); return }

    setLoading(true)
    const { rows: r, total: t, error } = await fetchPage(
      supabase.from('aws_requests').select('*', { count: 'exact' })
        .in('status', DONE)
        .gte('requested_at', iso.from).lte('requested_at', iso.to)
        .order('requested_at', { ascending: false })
        .range(0, page * PAGE_SIZE - 1),
      '처리 이력')
    setRows(r)
    setTotal(t)
    setLoadError(error)
    setLoading(false)
  }

  // 달력·요약 숫자는 목록과 별개로 전 기간을 DB에서 센다 (페이지에 잘리면 안 되므로).
  const fetchDayCounts = async () => {
    const { data, error } = await supabase.rpc('aws_request_day_counts')
    if (error) return // 숫자가 없을 뿐이라 목록 조회까지 막지는 않는다
    setDayCounts(Object.fromEntries((data || []).map(({ day, ...c }) => [day, c])))
  }

  useEffect(() => { fetchAll() }, [period, dayKey, weekOffset, bucketKey, page])
  useEffect(() => { fetchDayCounts() }, [])

  // 기간은 이미 DB에서 걸러져 왔다. 여기서는 종류만 좁힌다.
  const shown = category === 'all' ? rows : rows.filter((r) => r.resource_type === category)
  const counts = { all: rows.length }
  for (const r of rows) counts[r.resource_type] = (counts[r.resource_type] || 0) + 1
  const st = statusCounts(shown)
  const more = total - rows.length

  // 전체 요약 — 전 기간 집계를 그대로 합친다
  const days = Object.entries(dayCounts).sort((a, b) => a[0].localeCompare(b[0]))
  const grand = days.reduce((acc, [, c]) => {
    for (const f of ['n', 'bad', 'applied', 'rejected', 'failed', 'cancelled']) acc[f] += c[f] || 0
    return acc
  }, { n: 0, bad: 0, applied: 0, rejected: 0, failed: 0, cancelled: 0 })

  const changePeriod = (p) => {
    setPeriod(p); setBucketKey(null); setWeekOffset(0); setPage(1)
    setOpenReq(null); setPickedDay('')
  }
  const changeDay = (key) => { setDayKey(key); setPage(1); setOpenReq(null) }
  const changeWeek = (o) => { setWeekOffset(o); setPage(1); setOpenReq(null) }
  const openBucket = (key) => { setBucketKey(key); setPage(1); setOpenReq(null) }

  // 달력에서 날짜를 누르면 오른쪽에 요약만 띄운다. 화면은 그대로 달력이다.
  // '상세 현황 보기'를 눌렀을 때 비로소 일별로 넘어간다.
  const openDayDetail = (key) => {
    setPeriod('day'); setDayKey(key); setBucketKey(null); setPage(1)
    setOpenReq(null); setPickedDay('')
  }

  const showList = !!range
  const listable = showList && !loading

  return (
    <div className="ap-page">
      <div className="ap">
        <section className="ap-col">
          <div className="ap-head">
            <div className="ap-h1">승인 이력</div>
            <div className="ap-h2">
              {period === 'all'
                ? `전체 ${grand.n}건${days.length > 0 ? ` · ${days[0][0]} ~ ${days[days.length - 1][0]}` : ''}`
                : !showList
                  ? `${buckets.length}개월`
                  : <>
                      {shown.length}건
                      {st.applied > 0 && ` · 적용 ${st.applied}`}
                      {st.rejected > 0 && ` · 거절 ${st.rejected}`}
                      {st.failed > 0 && ` · 실패 ${st.failed}`}
                      {st.cancelled > 0 && ` · 취소 ${st.cancelled}`}
                      {/* 몇 건이 떠 있고 원래 몇 건인지 항상 같이 적는다 */}
                      {more > 0 && ` · 전체 ${total}건 중 ${rows.length}건 표시`}
                    </>}
            </div>
          </div>

          <div className="ap-chips">
            {PERIOD_OPTIONS.map((p) => (
              <button key={p.key} className={`ap-chip ${period === p.key ? 'on' : ''}`} onClick={() => changePeriod(p.key)}>
                {p.label}
              </button>
            ))}

            {/* 일별 — ‹ ›로 하루씩, 날짜 입력으로 바로 점프.
                날짜 선택 입력은 여기에만 둔다. */}
            {period === 'day' && (
              <>
                <span className="hc-nav">
                  <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => changeDay(shiftDay(dayKey, -1))}>‹</button>
                  <span className="hc-nav-label">{dayLabel(dayKey)}</span>
                  <button className="ac-btn ac-btn-secondary ac-cal-nav"
                    disabled={dayKey >= todayKey()}
                    onClick={() => changeDay(shiftDay(dayKey, 1))}>›</button>
                </span>
                <input type="date" className="sf-select" value={dayKey} max={todayKey()}
                  onChange={(e) => e.target.value && changeDay(e.target.value)} />
              </>
            )}

            {/* 주별 — 일별과 같은 방식으로 한 주씩 넘긴다 */}
            {period === 'week' && weekRange && (
              <span className="hc-nav">
                <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => changeWeek(weekOffset - 1)}>‹</button>
                <span className="hc-nav-label">
                  {weekRange.label}{weekOffset === 0 ? ' (이번 주)' : ''}
                </span>
                <button className="ac-btn ac-btn-secondary ac-cal-nav"
                  disabled={weekOffset >= 0}
                  onClick={() => changeWeek(weekOffset + 1)}>›</button>
              </span>
            )}

            {/* 월을 펼친 상태 — 어느 달을 보는 중인지와 돌아가는 길 */}
            {bucket && (
              <span className="hc-nav">
                <button className="ac-btn ac-btn-secondary" onClick={() => openBucket(null)}>← 목록</button>
                <span className="hc-nav-label">{bucket.label}</span>
              </span>
            )}
          </div>

          {/* 종류 칩은 목록이 있을 때만. 묶음 목록·요약 화면에서는 거를 대상이 없다. */}
          {showList && (
            <div className="ap-chips">
              {CATEGORIES.map((c) => (
                <button key={c.key} className={`ap-chip ${category === c.key ? 'on' : ''}`} onClick={() => setCategory(c.key)}>
                  {c.label} {counts[c.key] || 0}
                </button>
              ))}
            </div>
          )}

          <div className="ap-body">
            <ErrorBanner message={loadError} onRetry={fetchAll} />

            {/* ── 전체: 달력 + 요약 ───────────────────────── */}
            {period === 'all' && (
              <>
                <MonthCalendar counts={dayCounts} selected={pickedDay} onSelect={setPickedDay}
                  tsKey="requested_at" isBad={isBadRequest} />

                <div className="ah-sum">
                  <div className="ah-sum-tiles">
                    <div className="ah-tile"><b>{grand.n}</b><span>전체</span></div>
                    <div className="ah-tile ah-t-ok"><b>{grand.applied}</b><span>적용</span></div>
                    <div className="ah-tile ah-t-bad"><b>{grand.rejected}</b><span>거절</span></div>
                    <div className="ah-tile ah-t-bad"><b>{grand.failed}</b><span>실패</span></div>
                    <div className="ah-tile"><b>{grand.cancelled}</b><span>취소</span></div>
                  </div>
                  <div className="ah-sum-note">
                    달력의 날짜를 누르면 오른쪽에 그날 요약이 뜨고, 거기서 상세로 들어갑니다.
                    주는 <b>주별</b>에서 한 주씩 넘겨 보고, 달은 <b>월별</b>에서 골라 들어갑니다.
                  </div>
                </div>
              </>
            )}

            {/* ── 월별: 달 목록 ──────────────────────────── */}
            {period === 'month' && !bucket && (
              buckets.length === 0
                ? <div className="ac-empty">처리 내역이 없습니다.</div>
                : (
                  <div className="ah-buckets">
                    {buckets.map((b) => (
                      <button key={b.key} className="ah-bucket" onClick={() => openBucket(b.key)}>
                        <span className="ah-b-label">
                          <b>{b.label}</b>
                          <span>{b.sub}</span>
                        </span>
                        <StatusLine c={b} />
                        <span className="ah-b-n">{b.n}건</span>
                        {b.bad > 0 && <i className="hc-dot" />}
                        <span className="sf-caret">›</span>
                      </button>
                    ))}
                  </div>
                )
            )}

            {/* ── 목록 ────────────────────────────────────── */}
            {loading && <div className="ac-empty">불러오는 중...</div>}
            {listable && shown.length === 0 && (
              <div className="ac-empty">
                {period === 'day' ? `${dayLabel(dayKey)}에는 처리 내역이 없습니다.`
                  : period === 'week' ? `${weekRange?.label} 주에는 처리 내역이 없습니다.`
                    : '해당 기간에 처리 내역이 없습니다.'}
              </div>
            )}
            {listable && shown.length > 0 && (
              <ReqTable requests={shown} selectedId={openReq?.id} onOpen={setOpenReq} />
            )}

            {listable && more > 0 && (
              <div className="ap-more">
                <button className="ac-btn ac-btn-secondary" onClick={() => setPage(page + 1)}>
                  {Math.min(more, PAGE_SIZE)}건 더 보기 <span>(남은 {more}건)</span>
                </button>
              </div>
            )}
          </div>
        </section>

        {/* 오른쪽 패널은 하나다. 전체 화면에서 날짜를 고른 동안에는 그날 요약이,
            목록에서 신청을 고르면 그 신청 상세가 자리를 쓴다. */}
        {period === 'all' && pickedDay ? (
          <DaySummary dateKey={pickedDay} counts={dayCounts[pickedDay]}
            onOpen={openDayDetail} onClose={() => setPickedDay('')} />
        ) : (
          <ReqDrawer r={openReq} onClose={() => setOpenReq(null)} />
        )}
      </div>
    </div>
  )
}
