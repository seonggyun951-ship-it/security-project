import { useState, useEffect, useRef, Fragment } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { supabase } from '../lib/supabase'
import { fetchRows } from '../lib/db'
import { useIsAdmin } from '../lib/auth'
import { elapsedLabel, localDateKey } from '../lib/date'
import ErrorBanner from '../components/ErrorBanner'
import ExplainPanel from '../components/ExplainPanel'
import HoldDialog from '../components/HoldDialog'
import { CHECK_LABEL, checkLabel, checkKind, remedyFor, ismspFor } from '../lib/scan'

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
  // 셀렉트 하나에 값 하나였던 것을 여러 개 고를 수 있게 바꿨다.
  // '긴급과 높음만' 같은 흔한 요구를 예전 방식으로는 받을 수 없었다.
  const [sevs, setSevs] = useState([])
  const [svcs, setSvcs] = useState([])
  const [envs, setEnvs] = useState([])
  const [dateFilter, setDateFilter] = useState('')
  // 아코디언을 접었다. 고른 항목 하나를 오른쪽 패널에 띄운다 —
  // 펼치면 아래 목록이 통째로 밀려 방금 보던 자리를 잃었다.
  const [selected, setSelected] = useState(null)
  const [page, setPage] = useState(0)
  const [q, setQ] = useState('')
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
    (!sevs.length || sevs.includes(r.severity))
    && (!svcs.length || svcs.includes(serviceOf(r)))
    && (!envs.length || envs.includes(r.environment))
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

  // 패싯에는 개수가 함께 나와야 한다. 눌러 보기 전에 몇 건인지 알 수 있어야
  // 빈 결과를 고르는 헛걸음이 없다.
  const countBy = (fn) => {
    const m = {}
    for (const r of tabRows) { const k = fn(r); if (k) m[k] = (m[k] || 0) + 1 }
    return m
  }
  const sevCounts = countBy((r) => r.severity)
  const svcCounts = countBy(serviceOf)
  const envCounts = countBy((r) => r.environment)
  const services = Object.keys(svcCounts).sort()
  const environments = Object.keys(envCounts).sort()

  const lastRun = runs[0]
  const prevRun = runs[1]
  const canAct = isAdmin && tab === 'open'

  // 필터가 바뀌면 첫 쪽으로. 3쪽을 보다가 결과가 줄면 빈 화면이 남는다.
  useEffect(() => { setPage(0) }, [tab, sevs, svcs, envs, dateFilter, q])

  // 검색은 점검 항목 이름과 리소스 둘 다 훑는다. "sg-0a41"로도, "관리자"로도 찾을 수 있어야 한다.
  const qq = q.trim().toLowerCase()
  const visible = !qq ? grouped : grouped.filter((g) =>
    `${checkLabel(g.check_id)} ${g.check_id}`.toLowerCase().includes(qq)
    || g.items.some((i) => String(i.resource_id || '').toLowerCase().includes(qq)))

  const GROUPS_PER_PAGE = 20
  const pageCount = Math.max(1, Math.ceil(visible.length / GROUPS_PER_PAGE))
  const pageGroups = visible.slice(page * GROUPS_PER_PAGE, (page + 1) * GROUPS_PER_PAGE)

  // 표 안에서 서비스가 바뀌는 자리에 구분줄을 넣는다.
  const sections = []
  for (const g of pageGroups) {
    const svc = serviceOf(g)
    const last = sections[sections.length - 1]
    if (!last || last.svc !== svc) sections.push({ svc, items: [g] })
    else last.items.push(g)
  }

  const toggleIn = (list, set, v) => set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v])
  const TAB_LABEL = { open: '조치 필요', defer: '보류', exception: '예외', resolved: '해결됨' }
  const chips = [
    ...sevs.map((s) => ({ k: `v:${s}`, label: `심각도 : ${sevMeta(s).label}`, off: () => toggleIn(sevs, setSevs, s) })),
    ...svcs.map((s) => ({ k: `s:${s}`, label: `서비스 : ${s}`, off: () => toggleIn(svcs, setSvcs, s) })),
    ...envs.map((s) => ({ k: `e:${s}`, label: `환경 : ${s}`, off: () => toggleIn(envs, setEnvs, s) })),
    ...(dateFilter ? [{ k: 'd', label: `점검일 : ${dateFilter}`, off: () => setDateFilter('') }] : []),
  ]
  const clearAll = () => { setSevs([]); setSvcs([]); setEnvs([]); setDateFilter('') }

  const sel = grouped.find((g) => g.check_id === selected) || null
  const selPicked = sel ? sel.items.filter((i) => picked.includes(i.id)) : []
  const held = tab === 'defer' || tab === 'exception'

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

        {/* 먼저 알아야 할 숫자를 AWS 현황과 같은 자리·같은 띠에 둔다.
            심각도 타일 네 개는 왼쪽 패싯으로 옮겼다 — 거르는 수단이
            화면마다 타일·셀렉트·탭으로 갈리면 쓰는 법을 매번 새로 배워야 한다. */}
        <div className="ac-sum">
          <div className="ac-sum-c">
            <div className="k">조치 필요</div>
            <div className="v">{counts.open}</div>
            <div className="sub">
              긴급 {openRows.filter((r) => r.severity === 'critical').length}
              {' · '}높음 {openRows.filter((r) => r.severity === 'high').length}
            </div>
          </div>
          <div className="ac-sum-c">
            <div className="k">신규</div>
            <div className="v">{lastRun?.new_findings ?? 0}</div>
            <div className="sub">이번 점검에서</div>
          </div>
          <div className="ac-sum-c">
            <div className="k">해결됨</div>
            <div className="v">{lastRun?.resolved_findings ?? 0}</div>
            <div className="sub">직전 대비</div>
          </div>
          <div className="ac-sum-c">
            <div className="k">보류 · 예외</div>
            <div className="v">{counts.defer + counts.exception}</div>
            <div className="sub">보류 {counts.defer} · 예외 {counts.exception}</div>
          </div>
          <div className="ac-sum-c">
            <div className="k">마지막 점검</div>
            <div className="v sm">{lastRun ? `${elapsedLabel(lastRun.started_at)} 전` : '기록 없음'}</div>
            <div className="sub">
              {lastRun
                ? <>위반 {lastRun.failed} · 통과 {lastRun.passed}
                  {prevRun && ` · 직전 ${prevRun.failed}`}</>
                : '에이전트가 실행되면 결과가 쌓입니다'}
            </div>
          </div>
          {isAdmin && (
            <div className="ac-sum-c ac-sum-act">
              <Link className="ac-btn" to="/scan-history">이력 전체 보기</Link>
            </div>
          )}
        </div>

        <ErrorBanner message={error} onRetry={fetchAll} />

        <div className={`ac-shell ${sel ? 'has-side' : ''}`}>
          {/* 셀렉트 3개와 탭 4개가 여기로 모였다. 개수가 항상 보이므로
              눌러 보기 전에 몇 건인지 알 수 있다. */}
          <aside className="ac-facets">
            <div className="ac-fg">
              <div className="ac-fg-t">상태</div>
              {['open', 'defer', 'exception', 'resolved'].map((k) => (
                <button key={k} className={`ac-fi ${tab === k ? 'on' : ''}`}
                  onClick={() => { setTab(k); setPicked([]); setSelected(null) }}>
                  <span className="box">{tab === k ? '✓' : ''}</span>
                  <span className="l">{TAB_LABEL[k]}</span>
                  <span className="c">{counts[k]}</span>
                </button>
              ))}
            </div>

            <div className="ac-fg">
              <div className="ac-fg-t">심각도</div>
              {SEV_KEYS.map((s) => (
                <button key={s} className={`ac-fi ${sevs.includes(s) ? 'on' : ''}`}
                  onClick={() => toggleIn(sevs, setSevs, s)}>
                  <span className="box">{sevs.includes(s) ? '✓' : ''}</span>
                  <span className={`ac-sw sf-s-${sevMeta(s).key}`} />
                  <span className="l">{sevMeta(s).label}</span>
                  <span className="c">{sevCounts[s] || 0}</span>
                </button>
              ))}
            </div>

            {services.length > 0 && (
              <div className="ac-fg">
                <div className="ac-fg-t">서비스</div>
                {services.map((s) => (
                  <button key={s} className={`ac-fi ${svcs.includes(s) ? 'on' : ''}`}
                    onClick={() => toggleIn(svcs, setSvcs, s)}>
                    <span className="box">{svcs.includes(s) ? '✓' : ''}</span>
                    <span className="l">{s}</span>
                    <span className="c">{svcCounts[s]}</span>
                  </button>
                ))}
              </div>
            )}

            {environments.length > 0 && (
              <div className="ac-fg">
                <div className="ac-fg-t">환경</div>
                {environments.map((s) => (
                  <button key={s} className={`ac-fi ${envs.includes(s) ? 'on' : ''}`}
                    onClick={() => toggleIn(envs, setEnvs, s)}>
                    <span className="box">{envs.includes(s) ? '✓' : ''}</span>
                    <span className="l">{s}</span>
                    <span className="c">{envCounts[s]}</span>
                  </button>
                ))}
              </div>
            )}
          </aside>

          <div className="ac-main">
            <div className="ac-tb">
              <input className="ac-tb-s" placeholder="점검 항목 또는 리소스로 검색"
                value={q} onChange={(e) => setQ(e.target.value)} />
              {/* 점검일 기준. 그날 점검에서 실제로 보인 것만 남긴다. */}
              <input type="date" className="ac-tb-d" value={dateFilter}
                title="이 날 점검에서 나온 것만"
                onChange={(e) => setDateFilter(e.target.value)} />
            </div>

            <div className="ac-chips">
              <span className="lead">{TAB_LABEL[tab]} {counts[tab]}건 중 <b>{visible.reduce((n, g) => n + g.items.length, 0)}건</b></span>
              {chips.map((c) => (
                <button key={c.k} className="ac-chip" onClick={c.off}>{c.label}<span className="x">×</span></button>
              ))}
              {chips.length > 0 && <button className="ac-clr" onClick={clearAll}>모두 해제</button>}
            </div>

            <div className="ac-tw">
              {loading && <div className="ac-empty">불러오는 중…</div>}
              {!loading && visible.length === 0 && (
                <div className="ac-empty">
                  {chips.length > 0 || qq
                    ? <>조건에 맞는 항목이 없습니다. <button className="ac-clr" onClick={() => { clearAll(); setQ('') }}>모두 해제</button></>
                    : tab === 'open'
                      ? (!lastRun ? '점검이 아직 실행되지 않았습니다.' : '조치가 필요한 항목이 없습니다.')
                      : tab === 'defer' ? '보류한 항목이 없습니다.'
                        : tab === 'exception' ? '예외 처리한 항목이 없습니다.'
                          : '해결된 항목이 없습니다.'}
                </div>
              )}

              {!loading && visible.length > 0 && (
                <table className="ac-tbl sf-tbl2">
                  <thead>
                    <tr>
                      <th>심각도</th><th>점검 항목</th><th>종류</th>
                      <th className="num">대상</th><th className="num">경과</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sections.map((sec) => (
                      <Fragment key={sec.svc}>
                        <tr className="ac-grp">
                          <td colSpan={5}>
                            {sec.svc}
                            <span className="cnt">{sec.items.reduce((n, g) => n + g.items.length, 0)}건</span>
                          </td>
                        </tr>
                        {sec.items.map((g) => {
                          const m = sevMeta(g.severity)
                          return (
                            <tr key={g.check_id}
                              className={selected === g.check_id ? 'sel' : ''}
                              onClick={() => setSelected(selected === g.check_id ? null : g.check_id)}>
                              <td><span className={`sf-sev sf-s-${m.key}`}><i />{m.label}</span></td>
                              <td className="name">
                                {checkLabel(g.check_id)}
                                {g.hasNew && tab === 'open' && <span className="sf-new">NEW</span>}
                              </td>
                              <td>{checkKind(g.check_id)}</td>
                              <td className="num">{g.items.length}</td>
                              <td className={`num ${g.oldest >= 7 && tab === 'open' ? 'old' : ''}`}>
                                {held
                                  ? `${daysLeft(g.items[0].hold_until)}일 남음`
                                  : g.oldest === 0 ? '오늘' : `${g.oldest}일째`}
                              </td>
                            </tr>
                          )
                        })}
                      </Fragment>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            {visible.length > 0 && (
              <div className="ac-foot">
                <span>{visible.length}개 항목 중 {page * GROUPS_PER_PAGE + 1}–{Math.min((page + 1) * GROUPS_PER_PAGE, visible.length)}개</span>
                <span className="pg">
                  <span>{page + 1} / {pageCount}</span>
                  <button className="pgb" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>‹</button>
                  <button className="pgb" disabled={page + 1 >= pageCount} onClick={() => setPage((p) => p + 1)}>›</button>
                </span>
              </div>
            )}
          </div>

          {sel && (
            <FindingPanel
              group={sel} tab={tab} held={held} canAct={canAct} isAdmin={isAdmin} busy={busy}
              picked={picked} selPicked={selPicked}
              onClose={() => setSelected(null)}
              onToggle={toggle} onToggleAll={toggleAll} onHold={setHold}
              onRelease={release} onClearPick={() => setPicked([])} onFix={nav}
            />
          )}
        </div>
      </div>
    </div>
  )
}

// 오른쪽 상세 패널.
//
// 예전에는 줄 아래로 펼쳤다. 그러면 누를 때마다 아래 목록이 통째로 밀려
// 방금 보던 자리를 잃고, 항목끼리 비교할 수도 없었다.
//
// 탭은 셋이다. 설명(왜 문제이고 어떻게 고치나) · 대상(어느 리소스냐) ·
// 근거(어느 인증기준에 걸리나). 예전에는 이 셋이 한 덩어리로 쏟아졌다.
function FindingPanel({
  group: g, tab, held, canAct, isAdmin, busy, picked, selPicked,
  onClose, onToggle, onToggleAll, onHold, onRelease, onClearPick, onFix,
}) {
  const [pane, setPane] = useState('why')
  const ref = useRef(null)
  const m = sevMeta(g.severity)
  const label = checkLabel(g.check_id)
  const refs = ismspFor(g.check_id)

  useEffect(() => {
    setPane('why')
    // 넓은 화면에서는 패널이 sticky라 이미 보인다. 좁은 화면에서는 표 아래로
    // 내려가므로 눌러도 아무 일이 없어 보인다.
    ref.current?.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
  }, [g.check_id])

  return (
    <aside className="ac-side" ref={ref}>
      <div className="ac-side-h">
        <div className="ac-side-t">{label}</div>
        <div className="ac-side-s">{g.check_id}</div>
        <div className="ac-side-badges">
          <span className={`sf-sev sf-s-${m.key}`}><i />{m.label}</span>
          {g.hasNew && tab === 'open' && <span className="sf-new">NEW</span>}
        </div>
        <button className="ac-side-x" onClick={onClose} aria-label="닫기">×</button>
      </div>

      <div className="ac-side-tabs">
        <button className={`ac-side-tab ${pane === 'why' ? 'on' : ''}`} onClick={() => setPane('why')}>설명</button>
        <button className={`ac-side-tab ${pane === 'items' ? 'on' : ''}`} onClick={() => setPane('items')}>
          대상 <span className="n">{g.items.length}</span>
        </button>
        <button className={`ac-side-tab ${pane === 'refs' ? 'on' : ''}`} onClick={() => setPane('refs')}>
          근거 {refs.length > 0 && <span className="n">{refs.length}</span>}
        </button>
      </div>

      <div className="ac-side-b">
        {pane === 'why' && (
          <>
            {g.detail && <div className="sf-why">{g.detail}</div>}
            {/* 왜 문제이고 어떻게 고치는지 — 지식 베이스에 이 체크 ID가 그대로 있다 */}
            <ExplainPanel key={g.check_id} finding={{
              check_id: g.check_id,
              severity: g.severity,
              title: CHECK_LABEL[g.check_id] || g.check_id,
              detail: g.detail,
            }} />
            {held && g.items[0]?.hold_reason && (
              <div className="sf-holdnote">
                <b>{tab === 'defer' ? '보류 사유' : '예외 사유'}</b> {g.items[0].hold_reason}
                {g.items[0].hold_until && ` · ${new Date(g.items[0].hold_until).toLocaleDateString('ko-KR')}까지`}
              </div>
            )}
          </>
        )}

        {pane === 'items' && (
          <>
            {canAct && selPicked.length > 0 && (
              <div className="sf-selbar">
                <span><b>{selPicked.length}건</b> 선택됨</span>
                <span className="sf-selacts">
                  <button className="sf-act" disabled={busy}
                    onClick={() => onHold({
                      kind: 'defer', ids: selPicked.map((i) => i.id), label,
                      resourceLabel: `${selPicked.length}건`,
                    })}>보류</button>
                  <button className="sf-act" disabled={busy}
                    onClick={() => onHold({
                      kind: 'exception', ids: selPicked.map((i) => i.id), label,
                      resourceLabel: `${selPicked.length}건`,
                    })}>예외</button>
                  <button className="sf-act" onClick={onClearPick}>선택 해제</button>
                </span>
              </div>
            )}

            {canAct && (
              <label className="sf-allpick">
                <input type="checkbox"
                  checked={g.items.every((i) => picked.includes(i.id))}
                  onChange={() => onToggleAll(g.items)} />
                전체 선택
              </label>
            )}

            <div className="sf-items">
              {g.items.map((it) => (
                <div key={it.id} className="sf-item">
                  <div className="sf-item-top">
                    {canAct && (
                      <input type="checkbox" checked={picked.includes(it.id)} onChange={() => onToggle(it.id)} />
                    )}
                    <span className="sf-item-id" title={it.resource_id}>{it.resource_id}</span>
                    <span className={`sf-item-age ${!held && daysOpen(it.first_seen_at) >= 7 ? 'old' : ''}`}>
                      {held
                        ? `${daysLeft(it.hold_until)}일 남음`
                        : it.resolved_at ? '해결됨' : ageLabel(it.first_seen_at)}
                    </span>
                  </div>
                  <div className="sf-item-meta">
                    <span>{it.environment || '환경 없음'}</span>
                    <span>
                      {held
                        ? `${it.hold_by || '처리자 없음'} · ${mmdd(it.hold_at)}`
                        : `${it.owner_email || '만든 사람 모름'} · ${mmdd(it.first_seen_at)} 발견`}
                    </span>
                    {!held && <span>{elapsedLabel(it.last_seen_at)} 전 확인</span>}
                  </div>
                  <div className="sf-item-acts">
                    {/* 이 항목을 앱에서 고칠 수 있으면 신청 화면으로 넘긴다.
                        대상과 규칙이 채워진 채로 열려 같은 내용을 다시 입력하지 않는다.
                        고칠 방법이 없는 항목(MFA 등록 등)에는 버튼이 뜨지 않는다. */}
                    {!it.resolved_at && (() => {
                      const fix = remedyFor(g.check_id, it.resource_id)
                      if (!fix) return null
                      return (
                        <button className="sf-act sf-act-fix" disabled={busy} title={fix.label}
                          onClick={() => onFix(fix.to, { state: fix.state })}>조치 신청</button>
                      )
                    })()}
                    {isAdmin && !it.resolved_at && (
                      held ? (
                        <button className="sf-act" disabled={busy} onClick={() => onRelease(it.id)}>해제</button>
                      ) : (
                        <>
                          <button className="sf-act" disabled={busy}
                            onClick={() => onHold({ kind: 'defer', ids: [it.id], label, resourceLabel: it.resource_id })}>보류</button>
                          <button className="sf-act" disabled={busy}
                            onClick={() => onHold({ kind: 'exception', ids: [it.id], label, resourceLabel: it.resource_id })}>예외</button>
                        </>
                      )
                    )}
                  </div>
                </div>
              ))}
            </div>
          </>
        )}

        {pane === 'refs' && (
          refs.length === 0
            ? <div className="ac-side-none-b">이 항목에 대응하는 인증기준이 아직 정리되지 않았습니다.</div>
            : refs.map((s) => (
              <div key={s.no} className="sf-ref">
                <span className="no">ISMS-P {s.no}</span>
                <span className="t">{s.title}</span>
              </div>
            ))
        )}
      </div>
    </aside>
  )
}
