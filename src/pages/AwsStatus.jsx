import { useState, useEffect, useMemo, useRef, Fragment } from 'react'
import { supabase } from '../lib/supabase'
import { RESOURCE_META } from '../lib/aws'
import { summarize, briefOf } from '../lib/snapshot'
import { fetchPage, callFunction } from '../lib/db'
import ErrorBanner from '../components/ErrorBanner'

// 두 줄 배열의 LCS 기반 라인 diff
function diffLines(oldLines, newLines) {
  const m = oldLines.length, n = newLines.length
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0))
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      dp[i][j] = oldLines[i] === newLines[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1])
    }
  }
  const result = []
  let i = 0, j = 0
  while (i < m && j < n) {
    if (oldLines[i] === newLines[j]) { result.push({ type: 'same', text: oldLines[i] }); i++; j++ }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { result.push({ type: 'removed', text: oldLines[i] }); i++ }
    else { result.push({ type: 'added', text: newLines[j] }); j++ }
  }
  while (i < m) { result.push({ type: 'removed', text: oldLines[i] }); i++ }
  while (j < n) { result.push({ type: 'added', text: newLines[j] }); j++ }
  return result
}

function DiffView({ oldData, newData }) {
  if (!oldData) return <pre className="ac-snapshot-json">{JSON.stringify(newData, null, 2)}</pre>
  const oldLines = JSON.stringify(oldData, null, 2).split('\n')
  const newLines = JSON.stringify(newData, null, 2).split('\n')
  const lines = diffLines(oldLines, newLines)
  return (
    <pre className="ac-snapshot-json ac-diff">
      {lines.map((l, i) => (
        <div key={i} className={`ac-diff-line ac-diff-${l.type}`}>
          {l.type === 'added' ? '+ ' : l.type === 'removed' ? '- ' : '  '}{l.text}
        </div>
      ))}
    </pre>
  )
}

// 목록의 시각은 대부분 같은 값이 반복된다. 자리를 다 내주고 얻는 게 없다.
// 짧게 줄이고 정확한 시각은 title로 넘긴다.
function relTime(iso) {
  const t = new Date(iso)
  const min = Math.floor((Date.now() - t) / 60000)
  if (min < 1) return '방금'
  if (min < 60) return `${min}분 전`
  if (min < 1440) return `${Math.floor(min / 60)}시간 전`
  if (min < 43200) return `${Math.floor(min / 1440)}일 전`
  return t.toLocaleDateString('ko-KR', { year: '2-digit', month: '2-digit', day: '2-digit' })
}

const shortTime = (iso) => new Date(iso).toLocaleString('ko-KR', {
  month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
})

const DAY = 86400000

// 한 번에 가져올 스냅샷 수. 리소스 50개에 이력이 쌓이는 속도를 감안한 값이다.
// 넘으면 화면이 '더 있음'을 알리므로 조용히 잘리지는 않는다.
const SNAPSHOT_LIMIT = 1000
const PAGE_SIZE = 25

function groupSnapshotsByResource(snapshots) {
  const groups = {}
  for (const s of snapshots) {
    const key = `${s.resource_type}:${s.resource_id}`
    if (!groups[key]) groups[key] = []
    groups[key].push(s)
  }
  return Object.entries(groups).map(([key, list]) => {
    const sorted = [...list].sort((a, b) => new Date(a.collected_at) - new Date(b.collected_at))
    return { key, sorted, latest: sorted[sorted.length - 1], history: sorted.slice(0, -1).reverse() }
  }).sort((a, b) => new Date(b.latest.collected_at) - new Date(a.latest.collected_at))
}

// 오른쪽 상세 패널.
//
// 원래는 줄 아래로 펼쳤다. 그러면 누를 때마다 아래 목록이 통째로 밀려서
// 방금 보던 자리를 잃는다. 옆에 띄우면 목록이 안 움직인다.
function DetailPanel({ group, status, onClose }) {
  const [tab, setTab] = useState('info')
  const [rawOpen, setRawOpen] = useState(false)
  const ref = useRef(null)
  useEffect(() => {
    setTab('info'); setRawOpen(false)
    // 넓은 화면에서는 패널이 sticky라 이미 보인다. 좁은 화면에서는 표 아래로
    // 내려가므로 눌러도 아무 일이 없어 보인다. 'nearest'라서 이미 보일 때는
    // 화면이 움직이지 않는다.
    if (group) ref.current?.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
  }, [group?.key])

  if (!group) {
    return (
      <aside className="ac-side ac-side-empty">
        <div className="ac-side-empty-t">줄을 누르면 여기에 자세한 내용이 나옵니다.</div>
      </aside>
    )
  }

  const { latest, sorted, history } = group
  const meta = RESOURCE_META[latest.resource_type] || { label: latest.resource_type }
  const { fields, rules, warn } = summarize(latest.resource_type, latest.raw_data)
  const prevOf = (item) => {
    const idx = sorted.findIndex((s) => s.id === item.id)
    return idx > 0 ? sorted[idx - 1] : null
  }

  return (
    <aside className="ac-side" ref={ref}>
      <div className="ac-side-h">
        <div className="ac-side-t">{latest.resource_name || latest.resource_id}</div>
        <div className="ac-side-s">{meta.label}{latest.region ? ` · ${latest.region}` : ''}</div>
        {status === 'deleted' && <div className="ac-state is-deleted">삭제</div>}
        <button className="ac-side-x" onClick={onClose} aria-label="닫기">×</button>
      </div>

      <div className="ac-side-tabs">
        <button className={`ac-side-tab ${tab === 'info' ? 'on' : ''}`} onClick={() => setTab('info')}>정보</button>
        <button className={`ac-side-tab ${tab === 'hist' ? 'on' : ''}`} onClick={() => setTab('hist')}>
          변경 {history.length > 0 && <span className="n">{history.length}</span>}
        </button>
      </div>

      <div className="ac-side-b">
        {tab === 'info' && (
          <>
            {warn.length > 0 && (
              <div className="ac-side-warn">{warn.map((w, i) => <span key={i}>{w}</span>)}</div>
            )}
            <dl className="ac-side-fields">
              {fields.map(([k, v]) => (
                <div key={k} className="ac-side-f">
                  <dt>{k}</dt>
                  <dd>{v || <span className="ac-side-none">—</span>}</dd>
                </div>
              ))}
              <div className="ac-side-f">
                <dt>식별자</dt><dd className="mono">{latest.resource_id}</dd>
              </div>
              <div className="ac-side-f">
                <dt>마지막 수집</dt><dd>{shortTime(latest.collected_at)}</dd>
              </div>
            </dl>

            {rules.length > 0 && (
              <>
                <div className="ac-side-sect">규칙 {rules.length}개</div>
                <div className="ac-side-rules">
                  {rules.map((r, i) => (
                    <div key={i} className="ac-side-rule">
                      <span className="d">{r.dir}</span><span className="t">{r.text}</span>
                    </div>
                  ))}
                </div>
              </>
            )}

            <button className="ac-side-raw" onClick={() => setRawOpen((v) => !v)}>
              원본 {rawOpen ? '접기' : '보기'}
            </button>
            {rawOpen && <DiffView oldData={prevOf(latest)?.raw_data} newData={latest.raw_data} />}
          </>
        )}

        {tab === 'hist' && (
          history.length === 0
            ? <div className="ac-side-none-b">수집을 시작한 뒤로 바뀐 적이 없습니다.</div>
            : history.map((h) => (
              <div key={h.id} className="ac-side-hist">
                <div className="ac-side-hist-t">{shortTime(h.collected_at)}</div>
                <DiffView oldData={prevOf(h)?.raw_data} newData={h.raw_data} />
              </div>
            ))
        )}
      </div>
    </aside>
  )
}

export default function AwsStatus() {
  const [collecting, setCollecting] = useState(false)
  const [collectResult, setCollectResult] = useState(null)
  const [snapshots, setSnapshots] = useState([])
  const [snapshotTotal, setSnapshotTotal] = useState(0)
  const [seen, setSeen] = useState([])
  const [runs, setRuns] = useState([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(null)

  // 패싯은 여러 개를 동시에 고를 수 있다. 하나를 누르면 나머지가 사라지던
  // 예전 방식은 '보안 그룹과 IAM만' 같은 흔한 요구를 아예 못 받는다.
  const [types, setTypes] = useState([])
  // 기본은 운영 중인 것만. 삭제된 리소스는 이력을 보려고 남겨 두는 것이지
  // 현황의 총 건수에 섞이면 "지금 몇 개 굴리고 있나"를 알 수 없게 된다.
  const [states, setStates] = useState(['live'])
  const [changedIn, setChangedIn] = useState(null)
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(0)
  const [selected, setSelected] = useState(null)

  const fetchSnapshots = async () => {
    setLoading(true)
    const { rows, total, error } = await fetchPage(
      supabase.from('aws_resource_snapshots').select('*', { count: 'exact' })
        .order('collected_at', { ascending: false }).range(0, SNAPSHOT_LIMIT - 1),
      '리소스 스냅샷')
    setSnapshots(rows)
    setSnapshotTotal(total)
    setLoadError(error)
    setLoading(false)
  }

  // 삭제 판정에 쓴다. 스냅샷은 덧붙이기만 하는 이력이라 지워진 리소스도
  // 마지막 모습이 영원히 남는다. '이번 수집에서 실제로 보였는가'는 여기에만 있다.
  const fetchSeen = async () => {
    const { rows } = await fetchPage(
      supabase.from('aws_resource_seen').select('*'), '리소스 확인 기록')
    setSeen(rows)
  }

  // 수집을 언제 돌렸는지. 스냅샷은 값이 바뀌었을 때만 쌓이므로 이것만으로는
  // '돌았는데 변화가 없었다'와 '아예 안 돌았다'를 구별할 수 없다.
  const fetchRuns = async () => {
    const { rows } = await fetchPage(
      supabase.from('collect_runs').select('*', { count: 'exact' })
        .order('started_at', { ascending: false }).range(0, 19),
      '수집 실행 기록')
    setRuns(rows)
  }

  useEffect(() => { fetchSnapshots(); fetchSeen(); fetchRuns() }, [])

  const runCollect = async () => {
    setCollecting(true)
    setCollectResult(null)
    const data = await callFunction('aws-collect')
    setCollectResult(data)
    if (data.ok) { await fetchSnapshots(); await fetchSeen(); await fetchRuns() }
    setCollecting(false)
  }

  const allGroups = useMemo(() => groupSnapshotsByResource(snapshots), [snapshots])

  // 종류별 마지막 수집 시각. 수집은 종류별로 따로 돌고 하나가 실패해도
  // 나머지는 진행하므로, 전체 최대 시각을 기준 삼으면 실패한 종류가
  // 통째로 '삭제'로 뒤집힌다. aws_resource_options 뷰와 같은 기준을 쓴다.
  const runAtByType = useMemo(() => {
    const m = {}
    for (const s of seen) {
      const t = new Date(s.last_seen_at).getTime()
      if (!m[s.resource_type] || t > m[s.resource_type]) m[s.resource_type] = t
    }
    return m
  }, [seen])

  const seenMap = useMemo(() => {
    const m = {}
    for (const s of seen) m[`${s.resource_type}:${s.resource_id}`] = new Date(s.last_seen_at).getTime()
    return m
  }, [seen])

  // 리소스마다 상태·신규·변경을 한 번만 계산해 붙인다.
  const enriched = useMemo(() => allGroups.map((g) => {
    const t = g.latest.resource_type
    const last = seenMap[g.key]
    // 확인 기록이 아예 없으면 판단할 근거가 없다. 삭제로 몰지 않는다.
    const state = last == null || !runAtByType[t] || last >= runAtByType[t] ? 'live' : 'deleted'
    const firstAt = new Date(g.sorted[0].collected_at).getTime()
    const lastChange = g.history.length > 0 ? new Date(g.latest.collected_at).getTime() : null
    return {
      ...g, state,
      isNew: Date.now() - firstAt < 7 * DAY,
      changedDays: lastChange == null ? null : (Date.now() - lastChange) / DAY,
    }
  }), [allGroups, seenMap, runAtByType])

  const typeCounts = useMemo(() => {
    const m = {}
    for (const g of enriched) m[g.latest.resource_type] = (m[g.latest.resource_type] || 0) + 1
    return m
  }, [enriched])

  const stateCounts = useMemo(() => ({
    live: enriched.filter((g) => g.state === 'live').length,
    deleted: enriched.filter((g) => g.state === 'deleted').length,
  }), [enriched])

  const changedCounts = useMemo(() => ({
    7: enriched.filter((g) => g.changedDays != null && g.changedDays <= 7).length,
    30: enriched.filter((g) => g.changedDays != null && g.changedDays <= 30).length,
    none: enriched.filter((g) => g.changedDays == null).length,
  }), [enriched])

  const newCount = enriched.filter((g) => g.isNew).length
  const lastRun = runs.find((r) => r.finished_at) || runs[0]

  const q = search.trim().toLowerCase()
  const filtered = useMemo(() => enriched.filter((g) => {
    if (types.length && !types.includes(g.latest.resource_type)) return false
    if (states.length && !states.includes(g.state)) return false
    if (changedIn === 'none' && g.changedDays != null) return false
    if (changedIn === 7 && !(g.changedDays != null && g.changedDays <= 7)) return false
    if (changedIn === 30 && !(g.changedDays != null && g.changedDays <= 30)) return false
    if (q && !`${g.latest.resource_name || ''} ${g.latest.resource_id}`.toLowerCase().includes(q)) return false
    return true
  }), [enriched, types, states, changedIn, q])

  // 필터가 바뀌면 첫 쪽으로. 3쪽을 보다가 결과가 5건으로 줄면 빈 화면이 남는다.
  useEffect(() => { setPage(0) }, [types, states, changedIn, q])

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const pageRows = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  // 이 쪽에 실린 것만 종류별로 묶는다. 표 안에서 종류가 바뀌는 지점이 보이면
  // 지금 무엇을 보고 있는지 스크롤 중에도 알 수 있다.
  const sections = useMemo(() => {
    const out = []
    for (const g of pageRows) {
      const t = g.latest.resource_type
      const last = out[out.length - 1]
      if (!last || last.type !== t) out.push({ type: t, label: (RESOURCE_META[t] || {}).label || t, items: [g] })
      else last.items.push(g)
    }
    return out
  }, [pageRows])

  const toggleIn = (list, setList, v) =>
    setList(list.includes(v) ? list.filter((x) => x !== v) : [...list, v])

  const chips = [
    ...types.map((t) => ({ k: `t:${t}`, label: `종류 : ${(RESOURCE_META[t] || {}).label || t}`, off: () => toggleIn(types, setTypes, t) })),
    ...states.map((s) => ({ k: `s:${s}`, label: `상태 : ${s === 'live' ? '활성' : '삭제'}`, off: () => toggleIn(states, setStates, s) })),
    ...(changedIn ? [{ k: 'c', label: `변경 : ${changedIn === 'none' ? '없음' : `최근 ${changedIn}일`}`, off: () => setChangedIn(null) }] : []),
  ]
  // '모두 해제'도 활성만 보는 상태로 돌아간다. 아무것도 안 걸린 목록에
  // 삭제된 리소스가 섞여 나오면 그게 기본값처럼 보인다.
  const clearAll = () => { setTypes([]); setStates(['live']); setChangedIn(null); setSearch('') }

  const onlyLive = states.length === 1 && states[0] === 'live'
  const selectedGroup = enriched.find((g) => g.key === selected) || null

  return (
    <div className="ac-page">
      <h2 className="ac-title">AWS 현황</h2>
      <p className="ac-sub">AWS에 실제로 적용된 설정을 수집해서 변경 이력을 추적합니다.</p>

      <ErrorBanner message={loadError} onRetry={fetchSnapshots} />

      {/* 열자마자 읽혀야 하는 것만. 위험 판정은 여기서 하지 않는다 —
          그건 보안 점검이 답할 일이고, 두 군데서 따로 판정하면 어긋난다. */}
      <div className="ac-sum">
        <div className="ac-sum-c">
          <div className="k">신규</div>
          <div className="v">{newCount}</div>
          <div className="sub">최근 7일 내 처음 잡힘</div>
        </div>
        <div className="ac-sum-c">
          <div className="k">삭제</div>
          <div className={`v ${stateCounts.deleted > 0 ? 'is-gone' : ''}`}>{stateCounts.deleted}</div>
          <div className="sub">마지막 수집에 없음</div>
        </div>
        <div className="ac-sum-c">
          <div className="k">7일 내 변경</div>
          <div className="v">{changedCounts[7]}</div>
          <div className="sub">30일 {changedCounts[30]}건</div>
        </div>
        <div className="ac-sum-c">
          <div className="k">마지막 수집</div>
          <div className="v sm">{lastRun ? relTime(lastRun.started_at) : '기록 없음'}</div>
          <div className="sub">
            {lastRun
              ? `${shortTime(lastRun.started_at)} ${lastRun.trigger === 'cron' ? '자동' : '수동'}${lastRun.error ? ' · 실패' : ''}`
              : '아직 수집한 적이 없습니다'}
          </div>
        </div>
        <div className="ac-sum-c ac-sum-act">
          <button className="ac-btn" onClick={runCollect} disabled={collecting}>
            {collecting ? '수집 중…' : '지금 수집'}
          </button>
          {collectResult && (
            <div className={`ac-sum-msg ${collectResult.ok ? '' : 'is-err'}`}>
              {collectResult.ok ? `조회 ${collectResult.seen ?? '-'} · 변경 ${collectResult.changed}` : collectResult.error}
            </div>
          )}
        </div>
      </div>

      {/* 아무것도 안 골랐으면 오른쪽 칸을 아예 없앤다. 빈 패널이 320px을
          붙들고 있으면 정작 봐야 할 표가 눌린다. */}
      <div className={`ac-shell ${selectedGroup ? 'has-side' : ''}`}>
        {/* 왼쪽 패싯. 눌러도 나머지 종류가 사라지지 않고 개수가 그대로 보인다. */}
        <aside className="ac-facets">
          <div className="ac-fg">
            <div className="ac-fg-t">종류</div>
            {Object.entries(typeCounts)
              .sort((a, b) => b[1] - a[1])
              .map(([t, n]) => (
                <button key={t} className={`ac-fi ${types.includes(t) ? 'on' : ''}`}
                  onClick={() => toggleIn(types, setTypes, t)}>
                  <span className="box">{types.includes(t) ? '✓' : ''}</span>
                  <span className="l">{(RESOURCE_META[t] || {}).label || t}</span>
                  <span className="c">{n}</span>
                </button>
              ))}
          </div>

          <div className="ac-fg">
            <div className="ac-fg-t">상태</div>
            {[['live', '활성'], ['deleted', '삭제']].map(([k, label]) => (
              <button key={k} className={`ac-fi ${states.includes(k) ? 'on' : ''}`}
                onClick={() => toggleIn(states, setStates, k)}>
                <span className="box">{states.includes(k) ? '✓' : ''}</span>
                <span className="l">{label}</span>
                <span className="c">{stateCounts[k]}</span>
              </button>
            ))}
          </div>

          <div className="ac-fg">
            <div className="ac-fg-t">변경</div>
            {[[7, '최근 7일'], [30, '최근 30일'], ['none', '변경 없음']].map(([k, label]) => (
              <button key={k} className={`ac-fi ${changedIn === k ? 'on' : ''}`}
                onClick={() => setChangedIn(changedIn === k ? null : k)}>
                <span className="box">{changedIn === k ? '✓' : ''}</span>
                <span className="l">{label}</span>
                <span className="c">{changedCounts[k]}</span>
              </button>
            ))}
          </div>
        </aside>

        <div className="ac-main">
          <div className="ac-tb">
            <input className="ac-tb-s" placeholder="이름 또는 ID로 검색"
              value={search} onChange={(e) => setSearch(e.target.value)} />
          </div>

          {/* 지금 뭐가 걸려 있는지 항상 보여야 한다. 거른 표와 안 거른 표가
              똑같이 생기면 사람이 잘못 읽는다. */}
          <div className="ac-chips">
            {/* 총 건수는 지금 굴리고 있는 것이 기준이다. 삭제된 리소스를 섞어 세면
                "우리가 몇 개를 운영 중인가"라는 물음에 답할 수 없다. */}
            <span className="lead">
              {onlyLive
                ? (filtered.length === stateCounts.live
                  ? <>운영 중 <b>{stateCounts.live}건</b></>
                  : <>운영 중 {stateCounts.live}건 중 <b>{filtered.length}건</b></>)
                : <>전체 {enriched.length}건 중 <b>{filtered.length}건</b></>}
              {snapshotTotal > SNAPSHOT_LIMIT && (
                <span className="ac-snap-more">
                  · 이력 최근 {SNAPSHOT_LIMIT.toLocaleString()}건만 반영 (전체 {snapshotTotal.toLocaleString()}건)
                </span>
              )}
            </span>
            {chips.map((c) => (
              <button key={c.k} className="ac-chip" onClick={c.off}>{c.label}<span className="x">×</span></button>
            ))}
            {chips.length > 0 && <button className="ac-clr" onClick={clearAll}>모두 해제</button>}
          </div>

          <div className="ac-tw">
            {loading && <div className="ac-empty">불러오는 중…</div>}
            {!loading && enriched.length === 0 && (
              <div className="ac-empty">아직 수집된 데이터가 없습니다. "지금 수집"을 눌러보세요.</div>
            )}
            {!loading && enriched.length > 0 && filtered.length === 0 && (
              <div className="ac-empty">조건에 맞는 리소스가 없습니다. <button className="ac-clr" onClick={clearAll}>모두 해제</button></div>
            )}

            {filtered.length > 0 && (
              <table className="ac-tbl">
                <thead>
                  <tr>
                    <th>이름</th><th>식별자</th><th>구성</th>
                    <th className="num">변경</th><th className="num">수집</th>
                  </tr>
                </thead>
                <tbody>
                  {sections.map((sec) => (
                    <Fragment key={sec.type}>
                      <tr className="ac-grp">
                        <td colSpan={5}>
                          {sec.label}<span className="cnt">{typeCounts[sec.type]}개</span>
                        </td>
                      </tr>
                      {sec.items.map((g) => (
                        <tr key={g.key}
                          className={`${selected === g.key ? 'sel' : ''} ${g.state === 'deleted' ? 'gone' : ''}`}
                          onClick={() => setSelected(selected === g.key ? null : g.key)}>
                          <td className="name">
                            {g.latest.resource_name || g.latest.resource_id}
                            {g.state === 'deleted' && <span className="ac-state is-deleted">삭제</span>}
                            {g.isNew && g.state !== 'deleted' && <span className="ac-state is-new">신규</span>}
                          </td>
                          <td className="mono">{g.latest.resource_id}</td>
                          <td>{briefOf(g.latest.resource_type, g.latest.raw_data)}</td>
                          <td className="num">{g.history.length || '—'}</td>
                          <td className="num" title={new Date(g.latest.collected_at).toLocaleString('ko-KR')}>
                            {relTime(g.latest.collected_at)}
                          </td>
                        </tr>
                      ))}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {filtered.length > 0 && (
            <div className="ac-foot">
              <span>{filtered.length}건 중 {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, filtered.length)}건</span>
              <span className="pg">
                <span>{page + 1} / {pageCount}</span>
                <button className="pgb" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>‹</button>
                <button className="pgb" disabled={page + 1 >= pageCount} onClick={() => setPage((p) => p + 1)}>›</button>
              </span>
            </div>
          )}
        </div>

        {selectedGroup && (
          <DetailPanel group={selectedGroup} status={selectedGroup.state} onClose={() => setSelected(null)} />
        )}
      </div>
    </div>
  )
}
