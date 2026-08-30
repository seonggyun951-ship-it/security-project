import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { supabase } from '../lib/supabase'
import { fetchRows } from '../lib/db'
import { elapsedLabel } from '../lib/date'
import ErrorBanner from '../components/ErrorBanner'
import { checkLabel } from '../lib/scan'

// 보안 현황 — 점검 결과를 훑는 자리.
//
// 전에는 'AWS 현황'(수집 이력) · '보안 점검 결과' · '점검 이력' 세 화면으로 나뉘어 있었다.
// 셋 다 "AWS가 지금 어떤 상태인가"의 조각인데 따로 놀아서, 어디를 봐야 전체가 보이는지
// 알 수 없었다. 여기서 요약을 보고 상세는 눌러서 들어간다. 세 화면은 그대로 남아 있고
// 이 화면이 그 앞에 선다.
//
// 판정은 하지 않는다. Prowler가 매긴 심각도를 세고 묶어서 보여줄 뿐이다.

const SEVS = [
  { key: 'critical', label: 'Critical', cls: 'sv-crit' },
  { key: 'high',     label: 'High',     cls: 'sv-high' },
  { key: 'medium',   label: 'Medium',   cls: 'sv-med' },
  { key: 'low',      label: 'Low',      cls: 'sv-low' },
]
const sevMeta = (s) => SEVS.find((x) => x.key === s) || SEVS[3]

// 보류·예외는 기한이 지나면 조치 필요로 돌아온다. 상태를 따로 저장하지 않고
// hold_until을 지금과 비교한다 (점검 결과 화면과 같은 규칙).
const heldNow = (r) => !!r.hold_kind && !!r.hold_until && new Date(r.hold_until) > new Date()
const daysOpen = (iso) => Math.max(0, Math.floor((Date.now() - new Date(iso)) / 86400000))

// 점검이 오래되면 지금 상태와 다르다. 숫자보다 이걸 먼저 알려야 한다.
const STALE_HOURS = 36

export default function SecurityOverview() {
  const nav = useNavigate()
  const [rows, setRows] = useState([])
  const [runs, setRuns] = useState([])
  const [resourceCount, setResourceCount] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const fetchAll = async () => {
    setLoading(true)
    const [f, r, res] = await Promise.all([
      fetchRows(
        supabase.from('scan_findings')
          .select('check_id, severity, environment, first_seen_at, resolved_at, hold_kind, hold_until')
          .order('last_seen_at', { ascending: false }).limit(1000),
        '점검 결과'),
      fetchRows(
        supabase.from('scan_runs').select('started_at, failed, total')
          .not('finished_at', 'is', null)
          .order('started_at', { ascending: false }).limit(8),
        '점검 기록'),
      fetchRows(
        supabase.from('aws_resource_options').select('resource_id').limit(2000),
        '수집 리소스'),
    ])
    setRows(f.rows)
    setRuns([...r.rows].reverse())   // 그래프는 오래된 것이 왼쪽
    setResourceCount(res.error ? null : res.rows.length)
    setError(f.error || r.error)
    setLoading(false)
  }

  useEffect(() => { fetchAll() }, [])

  const open = rows.filter((r) => !r.resolved_at && !heldNow(r))
  const held = rows.filter((r) => !r.resolved_at && heldNow(r))

  const bySev = Object.fromEntries(SEVS.map((s) => [s.key, open.filter((r) => r.severity === s.key).length]))
  const total = open.length
  const crit = bySev.critical || 0

  // 환경 × 심각도. 환경이 몇 줄뿐이라 한 표에 다 들어간다.
  const envMap = {}
  for (const r of open) {
    const key = r.environment || '계정 전체'
    if (!envMap[key]) envMap[key] = { env: key, total: 0, critical: 0, high: 0, medium: 0, low: 0 }
    envMap[key].total += 1
    envMap[key][r.severity] = (envMap[key][r.severity] || 0) + 1
  }
  const envs = Object.values(envMap).sort((a, b) => b.total - a.total)
  // 칸 색의 진하기는 그 열에서 가장 큰 값을 기준으로 잡는다.
  const colMax = Object.fromEntries(SEVS.map((s) => [s.key, Math.max(1, ...envs.map((e) => e[s.key] || 0))]))

  // 체크 단위로 묶는다. 같은 체크가 리소스만 다르게 여러 번 나오기 때문이다.
  const groups = {}
  for (const r of open) {
    const g = groups[r.check_id] || (groups[r.check_id] = {
      check_id: r.check_id, severity: r.severity, n: 0, oldest: 0, envs: new Set(),
    })
    g.n += 1
    g.oldest = Math.max(g.oldest, daysOpen(r.first_seen_at))
    if (r.environment) g.envs.add(r.environment)
  }
  const top = Object.values(groups).sort((a, b) => {
    const d = SEVS.findIndex((s) => s.key === a.severity) - SEVS.findIndex((s) => s.key === b.severity)
    return d !== 0 ? d : (b.oldest - a.oldest) || (b.n - a.n)
  }).slice(0, 8)

  const lastRun = runs[runs.length - 1]
  const stale = lastRun && (Date.now() - new Date(lastRun.started_at)) > STALE_HOURS * 3600000

  // 점검 항목 수가 바뀐 지점을 표시한다. 표시가 없으면 건수가 뛴 걸
  // "보안이 나빠졌다"로 읽는다 — 실제로는 점검 범위를 넓힌 것이다.
  const shiftAt = runs.findIndex((r, i) => i > 0 && r.total && runs[i - 1].total && r.total !== runs[i - 1].total)
  const shiftRun = shiftAt > 0 ? runs[shiftAt] : null

  const maxFailed = Math.max(1, ...runs.map((r) => r.failed || 0))
  const W = 520, H = 92, PAD = 10
  const px = (i) => (runs.length < 2 ? W : (i / (runs.length - 1)) * W)
  const py = (v) => H - PAD - ((v || 0) / maxFailed) * (H - PAD * 2)
  const line = runs.map((r, i) => `${px(i)},${py(r.failed)}`).join(' L')

  return (
    <div className="ac-page">
      <div className="ov">
        <div className="ov-crumb">
          <b>보안 현황</b><i>/</i><span>AWS 자동 점검</span>
        </div>

        <ErrorBanner message={error} onRetry={fetchAll} />
        {loading && <div className="ac-empty">불러오는 중...</div>}

        {!loading && (
          <>
            <section className="ov-panel">
              <div className="ov-hero">
                <p className="ov-state">
                  {total === 0
                    ? <>조치가 필요한 항목이 <b>없습니다</b>.</>
                    : crit > 0
                      ? <>미조치 항목이 <b>{total}</b>건이며, 이 중 <span className="cr">{crit}</span>건이 Critical 등급입니다.</>
                      : <>미조치 항목이 <b>{total}</b>건입니다. Critical 등급은 없습니다.</>}
                </p>
                {lastRun && (
                  <span className={`ov-stale ${stale ? '' : 'is-ok'}`}>
                    <i />마지막 점검 {elapsedLabel(lastRun.started_at)} 전
                  </span>
                )}
              </div>

              {total > 0 && (
                <>
                  <div className="ov-ribbon" role="img"
                    aria-label={`심각도 비율: ${SEVS.map((s) => `${s.label} ${bySev[s.key]}`).join(', ')}`}>
                    {SEVS.map((s) => bySev[s.key] > 0 && (
                      <i key={s.key} className={s.cls} style={{ flex: bySev[s.key], background: 'var(--f)' }} />
                    ))}
                  </div>

                  <div className="ov-legend">
                    {SEVS.map((s) => (
                      <button key={s.key} className={`ov-leg ${s.cls}`}
                        onClick={() => nav('/scan')}>
                        <span className="v">{bySev[s.key]}</span>
                        <span className="k">{s.label}</span>
                      </button>
                    ))}
                  </div>
                </>
              )}
            </section>

            <div className="ov-split">
              <section className="ov-panel">
                <div className="ov-head">
                  <h2>환경별 분포</h2>
                  <span className="sub">환경 × 심각도</span>
                  <Link className="link" to="/scan">전체 목록 ›</Link>
                </div>
                {envs.length === 0 ? (
                  <div className="ac-empty">표시할 항목이 없습니다.</div>
                ) : (
                  <div className="ov-matrix">
                    <table>
                      <thead>
                        <tr>
                          <th>환경</th>
                          {SEVS.map((s) => <th key={s.key}>{s.label}</th>)}
                          <th>계</th>
                        </tr>
                      </thead>
                      <tbody>
                        {envs.map((e) => (
                          <tr key={e.env}>
                            <td>{e.env}</td>
                            {SEVS.map((s) => {
                              const v = e[s.key] || 0
                              // 진하기가 곧 건수. 0은 점으로 남겨 표의 격자가 유지되게 한다.
                              const pct = 35 + Math.round((v / colMax[s.key]) * 65)
                              return (
                                <td key={s.key}>
                                  <span className={`ov-cell ${s.cls} ${v === 0 ? 'is-zero' : ''}`}
                                    style={v === 0 ? undefined : {
                                      background: `color-mix(in srgb, var(--f) ${pct}%, transparent)`,
                                    }}>
                                    {v === 0 ? '·' : v}
                                  </span>
                                </td>
                              )
                            })}
                            <td className="ov-tot">{e.total}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              <section className="ov-panel">
                <div className="ov-head">
                  <h2>점검 기록</h2>
                  <span className="sub">최근 {runs.length}회</span>
                  <Link className="link" to="/scan-history">이력 ›</Link>
                </div>
                <div className="ov-trend">
                  {runs.length < 2 ? (
                    <div className="ac-empty">기록이 아직 부족합니다.</div>
                  ) : (
                    <>
                      <svg className="ov-spark" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img"
                        aria-label={`점검마다 남은 건수: ${runs.map((r) => r.failed ?? 0).join(', ')}`}>
                        <line x1="0" y1={H - PAD} x2={W} y2={H - PAD} stroke="var(--line-2)" strokeWidth="1" />
                        <path d={`M${line} L${W},${H} L0,${H} Z`} fill="var(--fail-bg)" />
                        <path d={`M${line}`} fill="none" stroke="var(--sv-crit)" strokeWidth="1.8"
                          strokeLinejoin="round" strokeLinecap="round" />
                        {shiftRun && (
                          <line x1={px(shiftAt)} y1="4" x2={px(shiftAt)} y2={H - 4}
                            stroke="var(--line)" strokeWidth="1" strokeDasharray="3 3" />
                        )}
                        <circle cx={px(runs.length - 1)} cy={py(runs[runs.length - 1].failed)} r="3.5" fill="var(--sv-crit)" />
                      </svg>
                      <p className="ov-note">
                        {shiftRun
                          ? <>점선 지점에서 점검 항목이 <b>{runs[shiftAt - 1].total}개 → {shiftRun.total}개</b>로
                            늘었습니다. 건수가 뛴 것은 그동안 안 보던 것이 보이기 시작한 것입니다.</>
                          : <>최근 {runs.length}회 점검에서 남은 건수입니다.</>}
                      </p>
                    </>
                  )}
                </div>
              </section>
            </div>

            <section className="ov-panel">
              <div className="ov-head">
                <h2>미조치 항목</h2>
                <span className="sub">심각도 · 방치 기간 순</span>
                <Link className="link" to="/scan">전체 {total}건 ›</Link>
              </div>
              {top.length === 0 ? (
                <div className="ac-empty">조치가 필요한 항목이 없습니다.</div>
              ) : top.map((g) => {
                const m = sevMeta(g.severity)
                const where = g.envs.size === 0 ? '계정 전체'
                  : g.envs.size === 1 ? [...g.envs][0]
                    : `${g.envs.size}개 환경`
                return (
                  <button key={g.check_id} className={`ov-row ${m.cls}`} onClick={() => nav('/scan')}>
                    <span className="bar" />
                    <span className="sev">{m.label}</span>
                    <span className="title">{checkLabel(g.check_id)}</span>
                    <span className="where">{where}</span>
                    <span className="cnt">{g.n}</span>
                    <span className="age">{g.oldest === 0 ? '오늘' : `${g.oldest}일`}</span>
                  </button>
                )
              })}
            </section>

            <div className="ov-tail">
              <Link to="/scan"><span className="v">{held.length}</span><span className="k">보류·예외</span><span className="go">›</span></Link>
              <Link to="/aws-status"><span className="v">{resourceCount ?? '—'}</span><span className="k">수집된 리소스</span><span className="go">›</span></Link>
              <Link to="/scan-history"><span className="v">{runs.length}</span><span className="k">점검 기록</span><span className="go">›</span></Link>
              {lastRun && (
                <Link to="/scan-history">
                  <span className={`v ${stale ? 'warn' : ''}`}>{elapsedLabel(lastRun.started_at)}</span>
                  <span className="k">마지막 점검</span><span className="go">›</span>
                </Link>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
