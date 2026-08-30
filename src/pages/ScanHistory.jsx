import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'
import { fetchRows } from '../lib/db'
import { localDateKey, PERIOD_OPTIONS, periodRange, inRange } from '../lib/date'
import ErrorBanner from '../components/ErrorBanner'
import MonthCalendar from '../components/MonthCalendar'
import { checkLabel, checkKind } from '../lib/scan'

// 점검이 언제 몇 번 돌았고 그때마다 무엇이 늘고 줄었는지.
//
// '보안 점검 결과' 화면은 지금 상태만 보여준다(마지막 실행 1건 + 직전 1건).
// 조치가 실제로 먹혔는지는 여러 번의 실행을 나란히 놓고 봐야 알 수 있어 화면을 나눴다.
//
// 실행별 결과를 따로 저장하지 않으므로(발견 1건 = 1행, 계속 갱신됨) 그 실행에서
// 무엇이 걸렸는지는 last_seen_at이 실행 구간 안에 드는 것으로 되짚는다.

const RUNNING_MS = 15 * 60 * 1000   // 이보다 오래 안 끝났으면 중단된 것으로 본다

const STATUS = {
  done:    { label: '완료',   cls: 'ok' },
  failed:  { label: '실패',   cls: 'bad' },
  running: { label: '진행 중', cls: 'run' },
  aborted: { label: '중단됨', cls: 'bad' },
}

function runStatus(r) {
  if (r.error) return 'failed'
  if (r.finished_at) return 'done'
  return Date.now() - new Date(r.started_at) < RUNNING_MS ? 'running' : 'aborted'
}

const isBadRun = (r) => {
  const s = runStatus(r)
  return s === 'failed' || s === 'aborted'
}

const hhmm = (iso) => new Date(iso).toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit' })
const mmddw = (iso) => new Date(iso).toLocaleDateString('ko-KR', { month: 'long', day: 'numeric', weekday: 'short' })

function durationLabel(r) {
  if (!r.finished_at) return '—'
  const sec = Math.round((new Date(r.finished_at) - new Date(r.started_at)) / 1000)
  if (sec < 60) return `${sec}초`
  return `${Math.floor(sec / 60)}분 ${sec % 60}초`
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }
const SEV_CLS = { critical: 'crit', high: 'high', medium: 'med', low: 'low' }

export default function ScanHistory() {
  const [runs, setRuns] = useState([])
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const [period, setPeriod] = useState('all')
  const [periodOffset, setPeriodOffset] = useState(0)
  const [dateFilter, setDateFilter] = useState('')
  const [open, setOpen] = useState(null)   // 펼친 실행 id

  const fetchAll = async () => {
    setLoading(true)
    const [r, f] = await Promise.all([
      fetchRows(
        supabase.from('scan_runs').select('*')
          .order('started_at', { ascending: false }).limit(200),
        '점검 이력'),
      fetchRows(
        supabase.from('scan_findings').select('check_id,resource_id,severity,environment,last_seen_at')
          .order('last_seen_at', { ascending: false }).limit(1000),
        '점검 결과'),
    ])
    setRuns(r.rows)
    setFindings(f.rows)
    setError(r.error || f.error)
    setLoading(false)
  }

  useEffect(() => { fetchAll() }, [])

  const range = (period === 'month' || period === 'week') ? periodRange(period, periodOffset) : null

  const byPeriod = period === 'all' ? runs : runs.filter((r) => inRange(r.started_at, range))
  const shown = dateFilter ? byPeriod.filter((r) => localDateKey(r.started_at) === dateFilter) : byPeriod

  // 요약은 화면에 보이는 범위 기준. 끝난 실행만 위반 수를 갖는다.
  const done = shown.filter((r) => runStatus(r) === 'done')
  const summary = {
    runs: shown.length,
    bad: shown.filter(isBadRun).length,
    added: done.reduce((s, r) => s + (r.new_findings || 0), 0),
    closed: done.reduce((s, r) => s + (r.resolved_findings || 0), 0),
  }

  // 위반 추이 — 오래된 것이 왼쪽. 끝난 실행만 값이 있다.
  const trend = [...done].reverse()
  const trendMax = Math.max(1, ...trend.map((r) => r.failed || 0))

  // 그 실행에서 실제로 보인 발견. 구간 밖의 것은 그때 없었거나 이미 해결된 것이다.
  const findingsOf = (r) => {
    if (!r.finished_at) return []
    const s = new Date(r.started_at).getTime()
    const e = new Date(r.finished_at).getTime()
    return findings.filter((f) => {
      const t = new Date(f.last_seen_at).getTime()
      return t >= s && t <= e
    })
  }

  const groupFindings = (items) => {
    const g = {}
    for (const f of items) {
      if (!g[f.check_id]) g[f.check_id] = { check_id: f.check_id, severity: f.severity, n: 0 }
      g[f.check_id].n += 1
    }
    return Object.values(g).sort((a, b) => {
      const d = (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
      return d !== 0 ? d : b.n - a.n
    })
  }

  const changePeriod = (p) => { setPeriod(p); setPeriodOffset(0); setDateFilter(''); setOpen(null) }

  return (
    <div className="ap-page">
      <div className="sf">
        <div className="ap-head">
          <div className="ap-h1">점검 이력</div>
          <div className="ap-h2">
            {summary.runs}회 실행
            {summary.added > 0 && ` · 새로 발견 ${summary.added}`}
            {summary.closed > 0 && ` · 해결 ${summary.closed}`}
            {summary.bad > 0 && ` · 실패·중단 ${summary.bad}`}
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

        <div className="ap-body">
          <ErrorBanner message={error} onRetry={fetchAll} />
          {loading && <div className="ac-empty">불러오는 중...</div>}

          {/* 전체 기간일 때만 달력 — 일·주·월은 이미 기간이 좁아 달력이 의미가 없다 */}
          {!loading && period === 'all' && (
            <MonthCalendar items={runs} selected={dateFilter} onSelect={setDateFilter}
              tsKey="started_at" isBad={isBadRun} />
          )}

          {!loading && trend.length > 1 && (
            <div className="sh-trend">
              <div className="sh-trend-label">위반 추이 <span>{trend.length}회 · 최대 {trendMax}</span></div>
              <div className="sh-bars">
                {trend.map((r) => (
                  <div key={r.id} className="sh-bar-wrap"
                    title={`${mmddw(r.started_at)} ${hhmm(r.started_at)} · 위반 ${r.failed}`}>
                    <div className="sh-bar" style={{ height: `${Math.max(4, ((r.failed || 0) / trendMax) * 100)}%` }} />
                    <span className="sh-bar-n">{r.failed}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {!loading && shown.length === 0 && (
            <div className="ac-empty">해당 기간에 점검 기록이 없습니다.</div>
          )}

          {!loading && shown.map((r) => {
            const st = runStatus(r)
            const meta = STATUS[st]
            const isOpen = open === r.id
            const items = isOpen ? findingsOf(r) : []
            const groups = isOpen ? groupFindings(items) : []

            return (
              <div key={r.id} className="sf-row">
                <button className="sh-rowhead" onClick={() => setOpen(isOpen ? null : r.id)}>
                  <span className={`sh-st sh-st-${meta.cls}`}><i />{meta.label}</span>
                  <span className="sh-when">
                    <b>{mmddw(r.started_at)} {hhmm(r.started_at)}</b>
                    <span>{(r.services?.length ? r.services.join(' · ') : '전체 서비스')} · {durationLabel(r)}</span>
                  </span>
                  {st === 'done' ? (
                    <>
                      <span className="sh-num">위반 <b className="sh-fail">{r.failed}</b></span>
                      <span className="sh-num">통과 {r.passed}</span>
                      <span className="sh-delta">
                        {r.new_findings > 0 && <span className="sf-up">+{r.new_findings}</span>}
                        {r.resolved_findings > 0 && <span className="sf-down">−{r.resolved_findings}</span>}
                        {!r.new_findings && !r.resolved_findings && <span className="sh-same">변화 없음</span>}
                      </span>
                    </>
                  ) : (
                    <span className="sh-note">{r.error ? r.error.slice(0, 80) : '결과가 기록되지 않음'}</span>
                  )}
                  <span className="sf-caret">{isOpen ? '−' : '+'}</span>
                </button>

                {isOpen && (
                  <div className="sf-body2">
                    {st !== 'done' && (
                      <div className="sf-why">
                        {r.error
                          ? `점검이 실패했습니다: ${r.error}`
                          : '결과가 기록되기 전에 끝났습니다. 에이전트 로그를 확인하세요.'}
                      </div>
                    )}
                    {st === 'done' && groups.length === 0 && (
                      <div className="sf-why">이 실행에서는 위반이 없었습니다.</div>
                    )}
                    {groups.length > 0 && (
                      <div className="sf-tblwrap">
                        <table className="sf-tbl">
                          <thead>
                            <tr>
                              <th>심각도</th>
                              <th>점검 항목</th>
                              <th>종류</th>
                              <th>건수</th>
                            </tr>
                          </thead>
                          <tbody>
                            {groups.map((g) => (
                              <tr key={g.check_id}>
                                <td>
                                  <span className={`sf-sev sf-s-${SEV_CLS[g.severity] || 'low'}`}>
                                    <i />{g.severity}
                                  </span>
                                </td>
                                <td>{checkLabel(g.check_id)}</td>
                                <td className="sf-c-env">{checkKind(g.check_id)}</td>
                                <td className="sf-c-num">{g.n}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
