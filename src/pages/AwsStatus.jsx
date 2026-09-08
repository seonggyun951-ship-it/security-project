import { useState, useEffect } from 'react'
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

// 수집한 내용을 사람이 읽는 형태로 보여준다.
//
// 원래는 raw_data를 JSON 그대로 뿌렸다. 그건 화면이 아니라 로그다 — 보는 사람이
// 중괄호를 헤치며 필요한 값을 직접 찾아야 한다. 리소스마다 볼 값은 정해져 있으므로
// 그것만 뽑아 이름을 붙인다(lib/snapshot.js).
//
// 원본은 버리지 않고 접어 둔다. 수집이 잘못됐는지 따질 때 필요하고,
// 우리가 뽑지 않은 값을 확인해야 할 때도 있다.
function SnapshotView({ type, oldData, newData }) {
  const [rawOpen, setRawOpen] = useState(false)
  const { fields, rules, warn } = summarize(type, newData)

  // 바뀐 값은 옆에 이전 값을 함께 적는다. 무엇이 어떻게 달라졌는지
  // 원본 diff를 펴지 않고도 한 줄에서 읽히게 한다.
  const before = oldData ? summarize(type, oldData) : null
  const prevOf = (label) => {
    if (!before) return null
    const hit = before.fields.find(([k]) => k === label)
    return hit ? hit[1] : null
  }

  return (
    <div className="ac-snap-body">
      {warn.length > 0 && (
        <div className="ac-snap-warn">
          {warn.map((w, i) => <span key={i}>{w}</span>)}
        </div>
      )}

      <dl className="ac-snap-fields">
        {fields.map(([k, v]) => {
          const p = prevOf(k)
          const changed = p != null && String(p) !== String(v)
          return (
            <div key={k} className={`ac-snap-f ${changed ? 'is-changed' : ''}`}>
              <dt>{k}</dt>
              <dd>
                {v || <span className="ac-snap-none">—</span>}
                {changed && <span className="ac-snap-was">이전 {p || '없음'}</span>}
              </dd>
            </div>
          )
        })}
      </dl>

      {rules.length > 0 && (
        <div className="ac-snap-rules">
          <div className="ac-snap-rules-h">규칙 {rules.length}개</div>
          {rules.map((r, i) => (
            <div key={i} className="ac-snap-rule">
              <span className="d">{r.dir}</span>
              <span className="t">{r.text}</span>
            </div>
          ))}
        </div>
      )}

      <button className="ac-snap-raw-toggle" onClick={() => setRawOpen((v) => !v)}>
        원본 {rawOpen ? '접기' : '보기'}
      </button>
      {rawOpen && <DiffView oldData={oldData} newData={newData} />}
    </div>
  )
}

// 한 번에 가져올 스냅샷 수. 리소스 50개에 이력이 쌓이는 속도를 감안한 값이다.
// 넘으면 화면이 '더 있음'을 알리므로 조용히 잘리지는 않는다.
const SNAPSHOT_LIMIT = 1000

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

export default function AwsStatus() {
  const [cred, setCred] = useState({ accessKeyId: '', secretAccessKey: '', region: 'ap-northeast-2' })
  const [collecting, setCollecting] = useState(false)
  const [collectResult, setCollectResult] = useState(null)
  const [snapshots, setSnapshots] = useState([])
  const [snapshotTotal, setSnapshotTotal] = useState(0)
  const [runs, setRuns] = useState([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(null)
  const [expanded, setExpanded] = useState(() => new Set())
  const [expandedHistory, setExpandedHistory] = useState(() => new Set())
  const [filter, setFilter] = useState('all')
  const [changedOnly, setChangedOnly] = useState(true)
  const [search, setSearch] = useState('')

  // 최근 100건만 가져오던 것을 늘렸다.
  //
  // 이 표는 시각이 아니라 '리소스'가 단위인데 시각으로 잘라 오고 있었다.
  // 리소스 50개에 이력이 300건 넘게 쌓인 상태에서 최근 100건을 가져오면
  // 리소스 12개만 덮이고 나머지 38개는 화면에서 사라진다. 남은 12개도
  // 앞부분이 잘려 변경 이력이 비어 보인다.
  //
  // 한 번에 다 가져오는 대신 상한을 크게 두고 총 건수를 함께 받는다.
  // 조용히 잘라내지 않기 위해서다 — 넘치면 화면에 알린다.
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

  // 수집을 언제 돌렸는지. 스냅샷은 값이 바뀌었을 때만 쌓이므로 이것만으로는
  // '돌았는데 변화가 없었다'와 '아예 안 돌았다'를 구별할 수 없다.
  const fetchRuns = async () => {
    const { rows } = await fetchPage(
      supabase.from('collect_runs').select('*', { count: 'exact' })
        .order('started_at', { ascending: false }).range(0, 19),
      '수집 실행 기록')
    setRuns(rows)
  }

  useEffect(() => { fetchSnapshots(); fetchRuns() }, [])

  const runCollect = async () => {
    setCollecting(true)
    setCollectResult(null)
    const data = await callFunction('aws-collect')
    setCollectResult(data)
    if (data.ok) { await fetchSnapshots(); await fetchRuns() }
    setCollecting(false)
  }

  const toggle = (id) => setExpanded((prev) => {
    const next = new Set(prev)
    next.has(id) ? next.delete(id) : next.add(id)
    return next
  })

  const toggleHistory = (key) => setExpandedHistory((prev) => {
    const next = new Set(prev)
    next.has(key) ? next.delete(key) : next.add(key)
    return next
  })

  const visible = filter === 'all' ? snapshots : snapshots.filter((s) => s.resource_type === filter)
  const counts = Object.keys(RESOURCE_META).reduce((acc, k) => {
    acc[k] = new Set(snapshots.filter((s) => s.resource_type === k).map((s) => s.resource_id)).size
    return acc
  }, {})
  const totalResources = new Set(snapshots.map((s) => `${s.resource_type}:${s.resource_id}`)).size
  const resourceGroupsAll = groupSnapshotsByResource(visible)
  const changedCount = resourceGroupsAll.filter((g) => g.history.length > 0).length
  const q = search.trim().toLowerCase()
  const resourceGroups = resourceGroupsAll
    .filter((g) => !changedOnly || g.history.length > 0)
    .filter((g) => !q || (g.latest.resource_name || '').toLowerCase().includes(q) || (g.latest.resource_id || '').toLowerCase().includes(q))

  return (
    <div className="ac-page">
      <h2 className="ac-title">AWS 현황</h2>
      <p className="ac-sub">AWS에 실제로 적용된 설정을 수집해서 변경 이력을 추적합니다.</p>

      <ErrorBanner message={loadError} onRetry={fetchSnapshots} />

      <div className="ac-grid">
      <details className="ac-card ac-card-muted">
        <summary className="ac-card-summary">AWS 자격증명 <span className="ac-tag">준비 중</span></summary>
        <p className="ac-cred-note">실제 운영 키는 여기 저장되지 않습니다. Supabase Edge Function 시크릿으로 별도 설정합니다. 이 폼은 아직 스켈레톤 단계입니다.</p>
        <div className="ac-form-row">
          <input
            className="ac-input"
            type="password"
            placeholder="Access Key ID"
            value={cred.accessKeyId}
            onChange={(e) => setCred({ ...cred, accessKeyId: e.target.value })}
            autoComplete="off"
          />
          <input
            className="ac-input"
            type="password"
            placeholder="Secret Access Key"
            value={cred.secretAccessKey}
            onChange={(e) => setCred({ ...cred, secretAccessKey: e.target.value })}
            autoComplete="off"
          />
          <input
            className="ac-input"
            placeholder="Region"
            value={cred.region}
            onChange={(e) => setCred({ ...cred, region: e.target.value })}
          />
        </div>
        <button className="ac-btn ac-btn-secondary" disabled>저장 (준비 중)</button>
      </details>

      <div className="ac-card">
        <div className="ac-card-title">수동 수집</div>
        <p className="ac-cred-note">자격증명이 설정되면 여기서 바로 수집을 실행할 수 있습니다.</p>
        <button className="ac-btn" onClick={runCollect} disabled={collecting}>
          {collecting ? '수집 중...' : '지금 수집하기'}
        </button>
        {collectResult && (
          collectResult.ok ? (
            <div className="ac-result ac-result-ok">
              수집 완료 — 조회 SG {collectResult.counts.security_group}/IAM Role {collectResult.counts.iam_role}/
              IAM Policy {collectResult.counts.iam_policy}/WAF {collectResult.counts.waf_web_acl}개, 그중 변경 {collectResult.changed}건 기록됨
            </div>
          ) : (
            <div className="ac-result ac-result-error">{collectResult.error}</div>
          )
        )}
      </div>

      <div className="ac-card ac-card-wide">
        {/* 언제 돌았는지 먼저 보여준다. 아래 목록은 '무엇이 바뀌었나'라서,
            변화가 없는 날은 아무것도 안 나온다. 그때 수집이 멈춘 건지
            바뀐 게 없는 건지 여기서 갈린다. */}
        {runs.length > 0 && (
          <div className="ac-runs">
            <div className="ac-runs-h">최근 수집</div>
            <div className="ac-runs-list">
              {runs.slice(0, 8).map((r) => (
                <div key={r.id} className={`ac-run ${r.error ? 'is-err' : ''}`}>
                  <span className="t">{new Date(r.started_at).toLocaleString('ko-KR', {
                    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })}</span>
                  <span className="w">{r.trigger === 'cron' ? '자동' : '수동'}</span>
                  <span className="r">
                    {r.error ? '실패'
                      : r.changed > 0 ? `${r.changed}건 변경`
                        : r.seen != null ? '변화 없음' : '진행 중'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="ac-card-title">
          변경 이력 {changedCount > 0 && <span className="ac-count-badge">{changedCount}</span>}
          {/* 상한에 걸리면 알린다. 조용히 잘라내면 '변경 이력이 없다'와
              '못 가져왔다'를 구별할 수 없다. */}
          {snapshotTotal > SNAPSHOT_LIMIT && (
            <span className="ac-snap-more">
              최근 {SNAPSHOT_LIMIT.toLocaleString()}건만 표시 · 전체 {snapshotTotal.toLocaleString()}건
            </span>
          )}
        </div>
        <div className="ac-filter-row">
          <button className={`ac-filter-btn ${filter === 'all' ? 'active' : ''}`} onClick={() => setFilter('all')}>
            전체 {totalResources}
          </button>
          {Object.entries(RESOURCE_META).map(([key, meta]) => counts[key] > 0 && (
            <button key={key} className={`ac-filter-btn ${filter === key ? 'active' : ''}`} onClick={() => setFilter(filter === key ? 'all' : key)}>
              {meta.label} {counts[key]}
            </button>
          ))}
        </div>
        <div className="ac-filter-row">
          <button className={`ac-filter-btn ${changedOnly ? 'active' : ''}`} onClick={() => setChangedOnly((v) => !v)}>
            변경된 것만 {changedCount}
          </button>
          <input
            className="ac-input ac-search-input"
            placeholder=" 이름 또는 ID로 검색"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        {loading && <div className="ac-empty">불러오는 중...</div>}
        {!loading && resourceGroups.length === 0 && resourceGroupsAll.length === 0 && (
          <div className="ac-empty">아직 수집된 데이터가 없습니다. 자격증명 설정 후 "지금 수집하기"를 눌러보세요.</div>
        )}
        {!loading && resourceGroups.length === 0 && resourceGroupsAll.length > 0 && (
          <div className="ac-empty">조건에 맞는 리소스가 없습니다. {changedOnly && '(변경된 것만 보기 켜짐)'}</div>
        )}

        <div className="ac-snapshot-list">
          {resourceGroups.map(({ key, sorted, latest, history }) => {
            const meta = RESOURCE_META[latest.resource_type] || { label: latest.resource_type }
            const isOpen = expanded.has(latest.id)
            const historyOpen = expandedHistory.has(key)
            const prevOf = (item) => {
              const idx = sorted.findIndex((s) => s.id === item.id)
              return idx > 0 ? sorted[idx - 1] : null
            }
            return (
              <div key={key} className={`ac-snapshot ${history.length > 0 ? 'has-changes' : ''}`}>
                <div className="ac-snapshot-top" onClick={() => toggle(latest.id)}>
                  <span className="ac-snapshot-name">
                    {latest.resource_name || latest.resource_id}
                    {/* 펼치지 않아도 무엇인지 알 수 있게 한 줄 요약을 붙인다.
                        규칙이 몇 개인지, 권한이 붙었는지 같은 것들이다. */}
                    <span className="ac-snap-brief">{briefOf(latest.resource_type, latest.raw_data)}</span>
                  </span>
                  <span className="ac-snapshot-type">{meta.label}</span>
                  <span className="ac-snapshot-time">{new Date(latest.collected_at).toLocaleString('ko-KR')}</span>
                  <span className="ac-expand-icon">{isOpen ? '▲' : '▼'}</span>
                </div>
                {isOpen && (
                  <SnapshotView type={latest.resource_type} oldData={prevOf(latest)?.raw_data} newData={latest.raw_data} />
                )}
                {history.length > 0 && (
                  <div className="ac-snapshot-history">
                    <div className="ac-snapshot-history-toggle" onClick={() => toggleHistory(key)}>
                      변경 이력 {history.length}건 {historyOpen ? '▲' : '▼'}
                    </div>
                    {historyOpen && history.map((h) => {
                      const hOpen = expanded.has(h.id)
                      return (
                        <div key={h.id} className="ac-snapshot-history-item">
                          <div className="ac-snapshot-history-top" onClick={() => toggle(h.id)}>
                            <span className="ac-snapshot-time">{new Date(h.collected_at).toLocaleString('ko-KR')}</span>
                            <span className="ac-expand-icon">{hOpen ? '▲' : '▼'}</span>
                          </div>
                          {hOpen && <SnapshotView type={h.resource_type} oldData={prevOf(h)?.raw_data} newData={h.raw_data} />}
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
      </div>
    </div>
  )
}
