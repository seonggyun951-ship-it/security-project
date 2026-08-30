import { useState, useEffect, useRef } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { supabase } from '../lib/supabase'
import { fetchRows } from '../lib/db'
import { useIsAdmin } from '../lib/auth'
import { elapsedLabel, localDateKey } from '../lib/date'
import ErrorBanner from '../components/ErrorBanner'
import ExplainPanel from '../components/ExplainPanel'
import HoldDialog from '../components/HoldDialog'
import { CHECK_LABEL, checkLabel, checkKind, remedyFor } from '../lib/scan'

// 자동 점검 결과.
//
// 같은 체크가 리소스만 다르게 여러 번 나온다(NACL 5개가 전부 열려 있는 식).
// 체크 단위로 묶고, 안의 리소스는 표로 보여준다 —
// 줄을 쌓으면 "14일째 / 보류 / 예외"가 줄마다 반복돼 읽히지 않는다.
//
// 보류·예외는 기한이 지나면 자동으로 조치 필요로 돌아온다. 그 판단을 여기서 한다 —
// DB에 상태를 따로 두지 않고 hold_until을 지금과 비교한다.

const SEV = {
  critical: { key: 'crit', label: '치명적', order: 0 },
  high:     { key: 'high', label: '높음',   order: 1 },
  medium:   { key: 'med',  label: '보통',   order: 2 },
  low:      { key: 'low',  label: '낮음',   order: 3 },
}
const sevMeta = (s) => SEV[s] || { key: 'low', label: s || '-', order: 9 }
const SEV_KEYS = ['critical', 'high', 'medium', 'low']

const daysOpen = (iso) => Math.max(0, Math.floor((Date.now() - new Date(iso)) / 86400000))
const ageLabel = (iso) => (daysOpen(iso) === 0 ? '오늘' : `${daysOpen(iso)}일째`)
const mmdd = (iso) => new Date(iso).toLocaleDateString('ko-KR', { month: '2-digit', day: '2-digit' })

// 아직 유효한 보류·예외인지. 기한이 지났으면 조치 필요로 돌아온 것으로 본다.
const heldAs = (r) => {
  if (!r.hold_kind || !r.hold_until) return null
  return new Date(r.hold_until) > new Date() ? r.hold_kind : null
}
const daysLeft = (iso) => Math.ceil((new Date(iso) - Date.now()) / 86400000)

export default function ScanFindings() {
  const isAdmin = useIsAdmin()
  const nav = useNavigate()
  const [rows, setRows] = useState([])
  const [runs, setRuns] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const [tab, setTab] = useState('open')   // open | defer | exception | resolved
  const [sevFilter, setSevFilter] = useState('')
  const [svcFilter, setSvcFilter] = useState('')
  const [envFilter, setEnvFilter] = useState('')
  const [dateFilter, setDateFilter] = useState('')
  const [open, setOpen] = useState({})
  // 처음 들어왔을 때 한 번만 마지막 점검일로 맞춘다. 그 뒤로는 사용자가 고른 날짜를 건드리지 않는다.
  const dateInit = useRef(false)
  const [picked, setPicked] = useState([])   // 선택한 finding id
  const [busy, setBusy] = useState(false)
  const [hold, setHold] = useState(null)     // { kind, ids, label, resourceLabel }

  const fetchAll = async () => {
    setLoading(true)
    const [f, r] = await Promise.all([
      fetchRows(
        supabase.from('scan_findings').select('*')
          .order('last_seen_at', { ascending: false }).limit(500),
        '점검 결과'),
      fetchRows(
        supabase.from('scan_runs').select('*')
          .not('finished_at', 'is', null)
          .order('started_at', { ascending: false }).limit(30),
        '점검 기록'),
    ])
    setRows(f.rows)
    setRuns(r.rows)
    setError(f.error)
    setLoading(false)

    // 기본은 마지막 점검일(점검이 매일 도니 보통 오늘). 전체를 펼치면 며칠 치가 섞여
    // 지금 상태를 보기 어렵다. '날짜 해제'를 누르면 전체가 된다.
    if (!dateInit.current && r.rows[0]) {
      dateInit.current = true
      setDateFilter(localDateKey(r.rows[0].started_at))
    }
  }

  useEffect(() => { fetchAll() }, [])

  const applyHold = async ({ days, reason }) => {
    setBusy(true)
    // 여러 건을 고른 경우 하나씩 처리한다. 중간에 실패해도 나머지는 그대로 둔다.
    const failed = []
    for (const id of hold.ids) {
      const { error: e } = await supabase.rpc('hold_finding', {
        finding_id: id, kind: hold.kind, days, reason,
      })
      if (e) failed.push(e.message)
    }
    setBusy(false)
    setHold(null)
    setPicked([])
    if (failed.length > 0) alert(`${failed.length}건 실패: ${failed[0]}`)
    await fetchAll()
  }

  const release = async (id) => {
    setBusy(true)
    const { error: e } = await supabase.rpc('release_finding', { finding_id: id })
    setBusy(false)
    if (e) return alert('되돌리기 실패: ' + e.message)
    await fetchAll()
  }

  const inTab = (r) => {
    if (r.resolved_at) return tab === 'resolved'
    const h = heldAs(r)
    if (h) return tab === h
    return tab === 'open'
  }
  const tabRows = rows.filter(inTab)

  const serviceOf = (r) => String(r.check_id || '').split('_')[0]

  const shown = tabRows.filter((r) =>
    (!sevFilter || r.severity === sevFilter)
    && (!svcFilter || serviceOf(r) === svcFilter)
    && (!envFilter || r.environment === envFilter)
    // 점검일 기준. 그날 점검에서 실제로 보인 것만 남긴다.
    // (발견일 기준이면 "그날 처음 나온 것"만 걸려서 그날의 상태를 볼 수 없다)
    //
    // 해결됨은 예외 — 해결된 건의 last_seen_at은 '마지막으로 보였던 날'이라 정의상
    // 최근 점검일과 겹치지 않는다. 날짜를 걸면 탭이 늘 비어버린다.
    && (tab === 'resolved' || !dateFilter || localDateKey(r.last_seen_at) === dateFilter))

  const groups = {}
  for (const r of shown) {
    if (!groups[r.check_id]) {
      groups[r.check_id] = { check_id: r.check_id, severity: r.severity, detail: r.detail, items: [] }
    }
    groups[r.check_id].items.push(r)
  }
  const grouped = Object.values(groups).map((g) => ({
    ...g,
    oldest: Math.max(...g.items.map((i) => daysOpen(i.first_seen_at))),
    hasNew: g.items.some((i) => daysOpen(i.first_seen_at) === 0),
  })).sort((a, b) => {
    const d = sevMeta(a.severity).order - sevMeta(b.severity).order
    return d !== 0 ? d : b.oldest - a.oldest
  })

  // 타일은 지금 실제로 손봐야 하는 것만 센다 (보류·예외 제외)
  const openRows = rows.filter((r) => !r.resolved_at && !heldAs(r))
  const counts = {
    open: openRows.length,
    defer: rows.filter((r) => !r.resolved_at && heldAs(r) === 'defer').length,
    exception: rows.filter((r) => !r.resolved_at && heldAs(r) === 'exception').length,
    resolved: rows.filter((r) => r.resolved_at).length,
  }

  const services = [...new Set(tabRows.map(serviceOf))].sort()
  const environments = [...new Set(tabRows.map((r) => r.environment).filter(Boolean))].sort()
  const lastRun = runs[0]
  const prevRun = runs[1]
  const canAct = isAdmin && tab === 'open'

  const toggle = (id) => setPicked((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p, id]))
  const toggleAll = (items) => {
    const ids = items.map((i) => i.id)
    const allOn = ids.every((id) => picked.includes(id))
    setPicked((p) => (allOn ? p.filter((x) => !ids.includes(x)) : [...new Set([...p, ...ids])]))
  }

  return (
    <div className="ap-page">
      {hold && (
        <HoldDialog kind={hold.kind} target={{ label: hold.label, resource_id: hold.resourceLabel }}
          onCancel={() => setHold(null)} onConfirm={applyHold} />
      )}

      <div className="sf">
        <div className="ap-head">
          <div className="ap-h1">보안 점검 결과</div>
          <div className="ap-h2">AWS 계정 · {lastRun?.services?.join(', ') || '전체 서비스'}</div>
        </div>

        <div className="sf-tiles">
          {SEV_KEYS.map((s) => {
            const m = sevMeta(s)
            return (
              <button key={s}
                className={`sf-tile sf-t-${m.key} ${sevFilter === s ? 'on' : ''}`}
                onClick={() => setSevFilter(sevFilter === s ? '' : s)}>
                <span className="sf-tile-n">{openRows.filter((r) => r.severity === s).length}</span>
                <span className="sf-tile-l">{m.label}</span>
              </button>
            )
          })}
        </div>

        <div className="sf-runbar">
          {lastRun ? (
            <>
              <span className="sf-dot" />
              <span>마지막 점검 <b>{elapsedLabel(lastRun.started_at)} 전</b></span>
              <span className="sf-sep">|</span>
              <span>위반 {lastRun.failed} · 통과 {lastRun.passed}</span>
              {(lastRun.new_findings > 0 || lastRun.resolved_findings > 0) && (
                <>
                  <span className="sf-sep">|</span>
                  {lastRun.new_findings > 0 && <span className="sf-up">새로 {lastRun.new_findings}</span>}
                  {lastRun.resolved_findings > 0 && <span className="sf-down">해결 {lastRun.resolved_findings}</span>}
                </>
              )}
              {prevRun && (
                <>
                  <span className="sf-sep">|</span>
                  <span className="sf-prev">직전 {elapsedLabel(prevRun.started_at)} 전 · 위반 {prevRun.failed}</span>
                </>
              )}
              {isAdmin && <Link className="sf-histlink" to="/scan-history">이력 전체 보기 ›</Link>}
            </>
          ) : (
            <span>아직 점검 기록이 없습니다. 에이전트가 실행되면 결과가 쌓입니다.</span>
          )}
        </div>

        <div className="sf-filters">
          <select className="sf-select" value={sevFilter} onChange={(e) => setSevFilter(e.target.value)}>
            <option value="">모든 심각도</option>
            {SEV_KEYS.map((s) => <option key={s} value={s}>{sevMeta(s).label}</option>)}
          </select>
          <select className="sf-select" value={svcFilter} onChange={(e) => setSvcFilter(e.target.value)}>
            <option value="">모든 서비스</option>
            {services.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          {environments.length > 0 && (
            <select className="sf-select" value={envFilter} onChange={(e) => setEnvFilter(e.target.value)}>
              <option value="">모든 환경</option>
              {environments.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          )}
          {/* 점검일 기준. 그날 점검에서 보인 것만 남긴다. */}
          <input type="date" className="sf-select" value={dateFilter}
            title="이 날 점검에서 나온 것만"
            onChange={(e) => setDateFilter(e.target.value)} />
          {dateFilter && (
            <button className="sf-act" onClick={() => setDateFilter('')}>날짜 해제</button>
          )}

          <div className="sf-tabs">
            <button className={`ap-chip ${tab === 'open' ? 'on' : ''}`} onClick={() => { setTab('open'); setPicked([]) }}>
              조치 필요 {counts.open}
            </button>
            <button className={`ap-chip ${tab === 'defer' ? 'on' : ''}`} onClick={() => { setTab('defer'); setPicked([]) }}>
              보류 {counts.defer}
            </button>
            <button className={`ap-chip ${tab === 'exception' ? 'on' : ''}`} onClick={() => { setTab('exception'); setPicked([]) }}>
              예외 {counts.exception}
            </button>
            <button className={`ap-chip ${tab === 'resolved' ? 'on' : ''}`} onClick={() => { setTab('resolved'); setPicked([]) }}>
              해결됨 {counts.resolved}
            </button>
          </div>
        </div>

        <div className="ap-body">
          <ErrorBanner message={error} onRetry={fetchAll} />
          {loading && <div className="ac-empty">불러오는 중...</div>}

          {!loading && grouped.length === 0 && (
            <div className="ac-empty">
              {tab === 'open'
                ? (!lastRun ? '점검이 아직 실행되지 않았습니다.'
                  : dateFilter ? `${dateFilter} 점검에서 나온 항목이 없습니다. 날짜를 해제하면 전체를 봅니다.`
                    : '조치가 필요한 항목이 없습니다.')
                : tab === 'defer' ? '보류한 항목이 없습니다.'
                  : tab === 'exception' ? '예외 처리한 항목이 없습니다.'
                    : '해결된 항목이 없습니다.'}
            </div>
          )}

          {!loading && grouped.map((g) => {
            const m = sevMeta(g.severity)
            const isOpen = !!open[g.check_id]
            const label = checkLabel(g.check_id)
            const held = tab === 'defer' || tab === 'exception'
            const pickedHere = g.items.filter((i) => picked.includes(i.id))

            return (
              <div key={g.check_id} className={`sf-row ${held ? 'is-held' : ''}`}>
                <button className="sf-rowhead" onClick={() => setOpen({ ...open, [g.check_id]: !isOpen })}>
                  <span className={`sf-sev sf-s-${m.key}`}><i />{m.label}</span>
                  <span className="sf-name">
                    <b>{label}{g.hasNew && tab === 'open' && <span className="sf-new">NEW</span>}</b>
                    <span>{g.check_id} · {checkKind(g.check_id)}</span>
                  </span>
                  <span className="sf-cnt">{g.items.length}</span>
                  <span className={`sf-age ${g.oldest >= 7 && tab === 'open' ? 'old' : ''}`}>
                    {held
                      ? `${daysLeft(g.items[0].hold_until)}일 남음`
                      : g.oldest === 0 ? '오늘' : `${g.oldest}일째`}
                  </span>
                  <span className="sf-caret">{isOpen ? '−' : '+'}</span>
                </button>

                {isOpen && (
                  <div className="sf-body2">
                    {g.detail && <div className="sf-why">{g.detail}</div>}

                    {canAct && pickedHere.length > 0 && (
                      <div className="sf-selbar">
                        <span><b>{pickedHere.length}건</b> 선택됨</span>
                        <span className="sf-selacts">
                          <button className="sf-act" disabled={busy}
                            onClick={() => setHold({
                              kind: 'defer', ids: pickedHere.map((i) => i.id), label,
                              resourceLabel: `${pickedHere.length}건`,
                            })}>보류</button>
                          <button className="sf-act" disabled={busy}
                            onClick={() => setHold({
                              kind: 'exception', ids: pickedHere.map((i) => i.id), label,
                              resourceLabel: `${pickedHere.length}건`,
                            })}>예외</button>
                          <button className="sf-act" onClick={() => setPicked([])}>선택 해제</button>
                        </span>
                      </div>
                    )}

                    <div className="sf-tblwrap">
                      <table className="sf-tbl">
                        <thead>
                          <tr>
                            {canAct && (
                              <th className="sf-c-sel">
                                <input type="checkbox"
                                  checked={g.items.every((i) => picked.includes(i.id))}
                                  onChange={() => toggleAll(g.items)} />
                              </th>
                            )}
                            <th>리소스</th>
                            <th>환경</th>
                            {held ? <th>처리자</th> : <th>만든 사람</th>}
                            {held ? <th>처리일</th> : <th>처음 발견</th>}
                            {held ? <th>남은 기간</th> : <th>경과</th>}
                            {!held && <th>마지막 확인</th>}
                            <th />
                          </tr>
                        </thead>
                        <tbody>
                          {g.items.map((it) => (
                            <tr key={it.id}>
                              {canAct && (
                                <td className="sf-c-sel">
                                  <input type="checkbox"
                                    checked={picked.includes(it.id)}
                                    onChange={() => toggle(it.id)} />
                                </td>
                              )}
                              <td className="sf-c-rid">{it.resource_id}</td>
                              <td className="sf-c-env">{it.environment || '—'}</td>
                              <td>
                                {held
                                  ? (it.hold_by ? <span className="sf-who">{it.hold_by}</span> : '—')
                                  : (it.owner_email
                                    ? <span className="sf-who">{it.owner_email}</span>
                                    : <span className="sf-who-none">—</span>)}
                              </td>
                              <td className="sf-c-num">
                                {held ? mmdd(it.hold_at) : mmdd(it.first_seen_at)}
                              </td>
                              <td className={`sf-c-num ${!held && daysOpen(it.first_seen_at) >= 7 ? 'old' : ''}`}>
                                {held
                                  ? `${daysLeft(it.hold_until)}일`
                                  : it.resolved_at ? '해결됨' : ageLabel(it.first_seen_at)}
                              </td>
                              {!held && (
                                <td className="sf-c-num">{elapsedLabel(it.last_seen_at)} 전</td>
                              )}
                              <td className="sf-c-act">
                                {/* 이 항목을 앱에서 고칠 수 있으면 신청 화면으로 넘긴다.
                                    대상과 규칙이 채워진 채로 열려 같은 내용을 다시 입력하지 않는다.
                                    고칠 방법이 없는 항목(MFA 등록 등)에는 버튼이 뜨지 않는다. */}
                                {!it.resolved_at && (() => {
                                  const fix = remedyFor(g.check_id, it.resource_id)
                                  if (!fix) return null
                                  return (
                                    <button className="sf-act sf-act-fix" disabled={busy}
                                      title={fix.label}
                                      onClick={() => nav(fix.to, { state: fix.state })}>
                                      조치 신청
                                    </button>
                                  )
                                })()}
                                {isAdmin && !it.resolved_at && (
                                  held ? (
                                    <button className="sf-act" disabled={busy} onClick={() => release(it.id)}>해제</button>
                                  ) : (
                                    <>
                                      <button className="sf-act" disabled={busy}
                                        onClick={() => setHold({ kind: 'defer', ids: [it.id], label, resourceLabel: it.resource_id })}>
                                        보류
                                      </button>
                                      <button className="sf-act" disabled={busy}
                                        onClick={() => setHold({ kind: 'exception', ids: [it.id], label, resourceLabel: it.resource_id })}>
                                        예외
                                      </button>
                                    </>
                                  )
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    {held && g.items[0]?.hold_reason && (
                      <div className="sf-holdnote">
                        <b>{tab === 'defer' ? '보류 사유' : '예외 사유'}</b> {g.items[0].hold_reason}
                        {g.items[0].hold_until && ` · ${new Date(g.items[0].hold_until).toLocaleDateString('ko-KR')}까지`}
                      </div>
                    )}

                    {/* 왜 문제이고 어떻게 고치는지 — 지식 베이스에 이 체크 ID가 그대로 있다 */}
                    <ExplainPanel key={g.check_id} finding={{
                      check_id: g.check_id,
                      severity: g.severity,
                      title: CHECK_LABEL[g.check_id] || g.check_id,
                      detail: g.detail,
                    }} />
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
