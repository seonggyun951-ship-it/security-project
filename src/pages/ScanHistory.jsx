import { useState, useEffect, useRef } from 'react'
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
  // 아코디언을 접었다. 고른 회차 하나를 오른쪽 패널에 띄운다 —
  // 펼치면 아래 목록이 통째로 밀려 회차끼리 비교할 수가 없었다.
  const [selected, setSelected] = useState(null)
  // 결과(완료·실패)와 변화(새 위반·해결·변화 없음)로도 거를 수 있어야 한다.
  // 30회를 훑으며 "실패한 날이 언제였지"를 눈으로 찾고 있었다.
  const [results, setResults] = useState([])
  const [changes, setChanges] = useState([])
  const [page, setPage] = useState(0)

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

  const changePeriod = (p) => { setPeriod(p); setPeriodOffset(0); setDateFilter(''); setSelected(null) }

  // 한 회차의 변화 성격. 패싯과 표에서 같은 기준을 쓴다.
  const changeOf = (r) => {
    if (runStatus(r) !== 'done') return null
    if (r.new_findings > 0) return 'added'
    if (r.resolved_findings > 0) return 'closed'
    return 'same'
  }

  const resultCounts = {
    done: byPeriod.filter((r) => runStatus(r) === 'done').length,
    bad: byPeriod.filter(isBadRun).length,
  }
  const changeCounts = {
    added: byPeriod.filter((r) => changeOf(r) === 'added').length,
    closed: byPeriod.filter((r) => changeOf(r) === 'closed').length,
    same: byPeriod.filter((r) => changeOf(r) === 'same').length,
  }

  const filtered = shown.filter((r) => {
    if (results.length) {
      const k = isBadRun(r) ? 'bad' : 'done'
      if (!results.includes(k)) return false
    }
    if (changes.length && !changes.includes(changeOf(r))) return false
    return true
  })

  useEffect(() => { setPage(0) }, [period, periodOffset, dateFilter, results, changes])

  const PER_PAGE = 25
  const pageCount = Math.max(1, Math.ceil(filtered.length / PER_PAGE))
  const pageRuns = filtered.slice(page * PER_PAGE, (page + 1) * PER_PAGE)

  const toggleIn = (list, set, v) => set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v])
  const RESULT_LABEL = { done: '완료', bad: '실패 · 중단' }
  const CHANGE_LABEL = { added: '새 위반 있음', closed: '해결 있음', same: '변화 없음' }
  const chips = [
    ...results.map((k) => ({ k: `r:${k}`, label: `결과 : ${RESULT_LABEL[k]}`, off: () => toggleIn(results, setResults, k) })),
    ...changes.map((k) => ({ k: `c:${k}`, label: `변화 : ${CHANGE_LABEL[k]}`, off: () => toggleIn(changes, setChanges, k) })),
    ...(dateFilter ? [{ k: 'd', label: `날짜 : ${dateFilter}`, off: () => setDateFilter('') }] : []),
  ]
  const clearAll = () => { setResults([]); setChanges([]); setDateFilter('') }

  const sel = filtered.find((r) => r.id === selected) || null

  // 30일 평균·최대·최소. 조치가 실제로 먹혔는지는 한 회차로는 알 수 없다.
  const recent = done.slice(0, 30).map((r) => r.failed || 0)
  const avg = recent.length ? Math.round(recent.reduce((a, b) => a + b, 0) / recent.length) : 0

  const durSec = (r) => (r.finished_at
    ? Math.round((new Date(r.finished_at) - new Date(r.started_at)) / 1000) : null)

  return (
    <div className="ap-page">
      <div className="sf">
        <div className="ap-head">
          <div className="ap-h1">점검 이력</div>
          <div className="ap-h2">점검이 언제 몇 번 돌았고 그때마다 무엇이 늘고 줄었는지 봅니다.</div>
        </div>

        {/* 보안 점검 결과·AWS 현황과 같은 자리, 같은 띠. */}
        <div className="ac-sum">
          <div className="ac-sum-c">
            <div className="k">마지막 점검 건수</div>
            <div className="v">{done[0]?.failed ?? '—'}</div>
            <div className="sub">
              {done[1]
                ? (() => {
                  const d = (done[0]?.failed || 0) - (done[1].failed || 0)
                  return d === 0 ? `직전 ${done[1].failed} · 같음`
                    : `직전 ${done[1].failed} · ${d > 0 ? `${d}건 늘었음` : `${-d}건 줄었음`}`
                })()
                : '견줄 직전 회차가 없습니다'}
            </div>
          </div>
          <div className="ac-sum-c">
            <div className="k">30회 평균</div>
            <div className="v">{avg}</div>
            <div className="sub">
              {recent.length ? `최대 ${Math.max(...recent)} · 최소 ${Math.min(...recent)}` : '자료 없음'}
            </div>
          </div>
          <div className="ac-sum-c">
            <div className="k">점검 실패</div>
            <div className={`v ${summary.bad > 0 ? 'is-gone' : ''}`}>{summary.bad}</div>
            <div className="sub">{summary.runs}회 중</div>
          </div>
          <div className="ac-sum-c">
            <div className="k">증가 감소</div>
            <div className="v sm">+{summary.added} / −{summary.closed}</div>
            <div className="sub">이 기간에 새로 나온 것 / 해결된 것</div>
          </div>
          <div className="ac-sum-c">
            <div className="k">최종 점검일</div>
            <div className="v sm">{runs[0] ? `${mmddw(runs[0].started_at)} ${hhmm(runs[0].started_at)}` : '기록 없음'}</div>
            <div className="sub">{runs[0] ? `${durationLabel(runs[0])} 걸림` : '아직 돌지 않았습니다'}</div>
          </div>
        </div>

        <ErrorBanner message={error} onRetry={fetchAll} />

        <div className={`ac-shell ${sel ? 'has-side' : ''}`}>
          <aside className="ac-facets">
            <div className="ac-fg">
              <div className="ac-fg-t">기간</div>
              {PERIOD_OPTIONS.map((p) => (
                <button key={p.key} className={`ac-fi ${period === p.key ? 'on' : ''}`}
                  onClick={() => changePeriod(p.key)}>
                  <span className="box">{period === p.key ? '✓' : ''}</span>
                  <span className="l">{p.label}</span>
                </button>
              ))}
              {/* 주·월은 앞뒤로 옮겨 볼 수 있어야 한다. 지금 어느 구간인지도 적는다. */}
              {range && (
                <div className="ac-fnav">
                  <button onClick={() => setPeriodOffset(periodOffset - 1)}>‹</button>
                  <span>{range.label}</span>
                  <button onClick={() => setPeriodOffset(periodOffset + 1)}>›</button>
                </div>
              )}
            </div>

            <div className="ac-fg">
              <div className="ac-fg-t">결과</div>
              {['done', 'bad'].map((k) => (
                <button key={k} className={`ac-fi ${results.includes(k) ? 'on' : ''}`}
                  onClick={() => toggleIn(results, setResults, k)}>
                  <span className="box">{results.includes(k) ? '✓' : ''}</span>
                  <span className="l">{RESULT_LABEL[k]}</span>
                  <span className="c">{resultCounts[k]}</span>
                </button>
              ))}
            </div>

            <div className="ac-fg">
              <div className="ac-fg-t">변화</div>
              {['added', 'closed', 'same'].map((k) => (
                <button key={k} className={`ac-fi ${changes.includes(k) ? 'on' : ''}`}
                  onClick={() => toggleIn(changes, setChanges, k)}>
                  <span className="box">{changes.includes(k) ? '✓' : ''}</span>
                  <span className="l">{CHANGE_LABEL[k]}</span>
                  <span className="c">{changeCounts[k]}</span>
                </button>
              ))}
            </div>
          </aside>

          <div className="ac-main">
            {/* 전체 기간일 때만 달력 — 일·주·월은 이미 기간이 좁아 달력이 의미가 없다 */}
            {!loading && period === 'all' && (
              <div className="sh-cal">
                <MonthCalendar items={runs} selected={dateFilter} onSelect={setDateFilter}
                  tsKey="started_at" isBad={isBadRun} />
              </div>
            )}

            {!loading && trend.length > 1 && (
              <div className="sh-trend">
                <div className="sh-trend-label">위반 추이 <span>{trend.length}회 · 최대 {trendMax}</span></div>
                <div className="sh-bars">
                  {trend.map((r) => (
                    <button key={r.id} className={`sh-bar-wrap ${selected === r.id ? 'on' : ''}`}
                      title={`${mmddw(r.started_at)} ${hhmm(r.started_at)} · 위반 ${r.failed}`}
                      onClick={() => setSelected(selected === r.id ? null : r.id)}>
                      <div className="sh-bar" style={{ height: `${Math.max(4, ((r.failed || 0) / trendMax) * 100)}%` }} />
                      <span className="sh-bar-n">{r.failed}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div className="ac-chips">
              <span className="lead">{byPeriod.length}회 중 <b>{filtered.length}회</b></span>
              {chips.map((c) => (
                <button key={c.k} className="ac-chip" onClick={c.off}>{c.label}<span className="x">×</span></button>
              ))}
              {chips.length > 0 && <button className="ac-clr" onClick={clearAll}>모두 해제</button>}
            </div>

            <div className="ac-tw">
              {loading && <div className="ac-empty">불러오는 중…</div>}
              {!loading && filtered.length === 0 && (
                <div className="ac-empty">
                  {chips.length > 0
                    ? <>조건에 맞는 점검이 없습니다. <button className="ac-clr" onClick={clearAll}>모두 해제</button></>
                    : '해당 기간에 점검 기록이 없습니다.'}
                </div>
              )}

              {!loading && filtered.length > 0 && (
                <table className="ac-tbl sh-tbl2">
                  <thead>
                    <tr>
                      <th>일시</th><th>결과</th><th>대상 서비스</th>
                      <th className="num">위반</th><th className="num">통과</th>
                      <th className="num">증감</th><th className="num">소요</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pageRuns.map((r) => {
                      const st = runStatus(r)
                      const meta = STATUS[st]
                      const ok = st === 'done'
                      return (
                        <tr key={r.id} className={selected === r.id ? 'sel' : ''}
                          onClick={() => setSelected(selected === r.id ? null : r.id)}>
                          <td className="name">{mmddw(r.started_at)} {hhmm(r.started_at)}</td>
                          <td><span className={`sh-st sh-st-${meta.cls}`}><i />{meta.label}</span></td>
                          <td>{ok ? (r.services?.length ? r.services.join(' · ') : '전체 서비스') : (r.error ? r.error.slice(0, 40) : '결과 미기록')}</td>
                          <td className="num">{ok ? <b className="sh-fail">{r.failed}</b> : '—'}</td>
                          <td className="num">{ok ? r.passed : '—'}</td>
                          <td className="num">
                            {!ok ? '—'
                              : (r.new_findings > 0 || r.resolved_findings > 0)
                                ? <>
                                  {r.new_findings > 0 && <span className="sf-up">+{r.new_findings}</span>}
                                  {r.resolved_findings > 0 && <span className="sf-down">−{r.resolved_findings}</span>}
                                </>
                                : <span className="sh-same">변화 없음</span>}
                          </td>
                          <td className="num">{durSec(r) == null ? '—' : durationLabel(r)}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
            </div>

            {filtered.length > 0 && (
              <div className="ac-foot">
                <span>{filtered.length}회 중 {page * PER_PAGE + 1}–{Math.min((page + 1) * PER_PAGE, filtered.length)}회</span>
                <span className="pg">
                  <span>{page + 1} / {pageCount}</span>
                  <button className="pgb" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>‹</button>
                  <button className="pgb" disabled={page + 1 >= pageCount} onClick={() => setPage((p) => p + 1)}>›</button>
                </span>
              </div>
            )}
          </div>

          {sel && (
            <RunPanel run={sel} groups={groupFindings(findingsOf(sel))}
              onClose={() => setSelected(null)} />
          )}
        </div>
      </div>
    </div>
  )
}

// 회차 하나의 상세.
//
// 예전에는 줄 아래로 펼쳤다. 그러면 회차를 옮겨 다니며 견줄 수가 없다 —
// 이 화면은 애초에 여러 번의 실행을 나란히 놓고 보려고 만든 곳이다.
function RunPanel({ run: r, groups, onClose }) {
  const [pane, setPane] = useState('sev')
  const ref = useRef(null)
  const st = runStatus(r)
  const meta = STATUS[st]

  useEffect(() => {
    setPane('sev')
    ref.current?.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
  }, [r.id])

  // 심각도별로 접어서 먼저 보여준다. 위반이 수십 건이면 목록만으로는
  // 이번 회차가 나쁜지 좋은지 판단할 수 없다.
  const bySev = ['critical', 'high', 'medium', 'low'].map((s) => ({
    sev: s,
    n: groups.filter((g) => g.severity === s).reduce((a, g) => a + g.n, 0),
  })).filter((x) => x.n > 0)
  const SEV_LABEL = { critical: '치명적', high: '높음', medium: '보통', low: '낮음' }

  return (
    <aside className="ac-side" ref={ref}>
      <div className="ac-side-h">
        <div className="ac-side-t">{mmddw(r.started_at)} {hhmm(r.started_at)}</div>
        <div className="ac-side-s">
          {durationLabel(r)} · {r.services?.length ? r.services.join(' · ') : '전체 서비스'}
        </div>
        <div className="ac-side-badges">
          <span className={`sh-st sh-st-${meta.cls}`}><i />{meta.label}</span>
          {r.new_findings > 0 && <span className="sf-new">새 위반 {r.new_findings}</span>}
        </div>
        <button className="ac-side-x" onClick={onClose} aria-label="닫기">×</button>
      </div>

      <div className="ac-side-tabs">
        <button className={`ac-side-tab ${pane === 'sev' ? 'on' : ''}`} onClick={() => setPane('sev')}>
          심각도별
        </button>
        <button className={`ac-side-tab ${pane === 'list' ? 'on' : ''}`} onClick={() => setPane('list')}>
          위반 항목 <span className="n">{groups.length}</span>
        </button>
      </div>

      <div className="ac-side-b">
        {st !== 'done' && (
          <div className="sf-why">
            {r.error
              ? `점검이 실패했습니다: ${r.error}`
              : '결과가 기록되기 전에 끝났습니다. 에이전트 로그를 확인하세요.'}
          </div>
        )}

        {st === 'done' && groups.length === 0 && (
          <div className="ac-side-none-b">이 실행에서는 위반이 없었습니다.</div>
        )}

        {st === 'done' && groups.length > 0 && pane === 'sev' && (
          <>
            <div className="sh-sevlist">
              {bySev.map((x) => (
                <div key={x.sev} className="sh-sevrow">
                  <span className={`sf-sev sf-s-${SEV_CLS[x.sev]}`}><i />{SEV_LABEL[x.sev]}</span>
                  <span className="n">{x.n}건</span>
                </div>
              ))}
            </div>
            <div className="ac-side-sect">이 회차 요약</div>
            <div className="ac-side-fields">
              <div className="ac-side-f"><dt>위반</dt><dd>{r.failed}</dd></div>
              <div className="ac-side-f"><dt>통과</dt><dd>{r.passed}</dd></div>
              <div className="ac-side-f"><dt>새로 나온 것</dt><dd>{r.new_findings || 0}</dd></div>
              <div className="ac-side-f"><dt>해결된 것</dt><dd>{r.resolved_findings || 0}</dd></div>
              <div className="ac-side-f"><dt>걸린 시간</dt><dd>{durationLabel(r)}</dd></div>
            </div>
          </>
        )}

        {st === 'done' && groups.length > 0 && pane === 'list' && (
          <div className="sh-sevlist">
            {groups.map((g) => (
              <div key={g.check_id} className="sh-grow">
                <span className={`sf-sev sf-s-${SEV_CLS[g.severity] || 'low'}`}><i /></span>
                <span className="t">
                  {checkLabel(g.check_id)}
                  <span className="k">{checkKind(g.check_id)}</span>
                </span>
                <span className="n">{g.n}건</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </aside>
  )
}

