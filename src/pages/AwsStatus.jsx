import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'
import { RESOURCE_META } from '../lib/aws'

const AWS_COLLECT_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/aws-collect'

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
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState(() => new Set())
  const [expandedHistory, setExpandedHistory] = useState(() => new Set())
  const [filter, setFilter] = useState('all')
  const [changedOnly, setChangedOnly] = useState(true)
  const [search, setSearch] = useState('')

  const fetchSnapshots = async () => {
    setLoading(true)
    const { data } = await supabase.from('aws_resource_snapshots').select('*').order('collected_at', { ascending: false }).limit(100)
    setSnapshots(data || [])
    setLoading(false)
  }

  useEffect(() => { fetchSnapshots() }, [])

  const runCollect = async () => {
    setCollecting(true)
    setCollectResult(null)
    try {
      const { data: { session } } = await supabase.auth.getSession()
      const res = await fetch(AWS_COLLECT_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${session?.access_token}` },
        body: JSON.stringify({}),
      })
      const data = await res.json()
      setCollectResult(data)
      if (data.ok) await fetchSnapshots()
    } catch (e) {
      setCollectResult({ ok: false, error: String(e) })
    }
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
      <h2 className="ac-title">📡 AWS 현황</h2>
      <p className="ac-sub">AWS에 실제로 적용된 설정을 수집해서 변경 이력을 추적합니다.</p>

      <div className="ac-grid">
      <details className="ac-card ac-card-muted">
        <summary className="ac-card-summary">AWS 자격증명 <span className="ac-tag">준비 중</span></summary>
        <p className="ac-cred-note">⚠️ 실제 운영 키는 여기 저장되지 않습니다. Supabase Edge Function 시크릿으로 별도 설정합니다. 이 폼은 아직 스켈레톤 단계입니다.</p>
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
              ✅ 수집 완료 — 조회 SG {collectResult.counts.security_group}/IAM Role {collectResult.counts.iam_role}/
              IAM Policy {collectResult.counts.iam_policy}/WAF {collectResult.counts.waf_web_acl}개, 그중 변경 {collectResult.changed}건 기록됨
            </div>
          ) : (
            <div className="ac-result ac-result-error">⚠️ {collectResult.error}</div>
          )
        )}
      </div>

      <div className="ac-card ac-card-wide">
        <div className="ac-card-title">수집 이력 {changedCount > 0 && <span className="ac-count-badge">{changedCount}</span>}</div>
        <div className="ac-filter-row">
          <button className={`ac-filter-btn ${filter === 'all' ? 'active' : ''}`} onClick={() => setFilter('all')}>
            전체 {totalResources}
          </button>
          {Object.entries(RESOURCE_META).map(([key, meta]) => counts[key] > 0 && (
            <button key={key} className={`ac-filter-btn ${filter === key ? 'active' : ''}`} onClick={() => setFilter(filter === key ? 'all' : key)}>
              {meta.icon} {meta.label} {counts[key]}
            </button>
          ))}
        </div>
        <div className="ac-filter-row">
          <button className={`ac-filter-btn ${changedOnly ? 'active' : ''}`} onClick={() => setChangedOnly((v) => !v)}>
            변경된 것만 {changedCount}
          </button>
          <input
            className="ac-input ac-search-input"
            placeholder="🔍 이름 또는 ID로 검색"
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
            const meta = RESOURCE_META[latest.resource_type] || { icon: '📦', label: latest.resource_type }
            const isOpen = expanded.has(latest.id)
            const historyOpen = expandedHistory.has(key)
            const prevOf = (item) => {
              const idx = sorted.findIndex((s) => s.id === item.id)
              return idx > 0 ? sorted[idx - 1] : null
            }
            return (
              <div key={key} className={`ac-snapshot ${history.length > 0 ? 'has-changes' : ''}`}>
                <div className="ac-snapshot-top" onClick={() => toggle(latest.id)}>
                  <span className="ac-snapshot-icon">{meta.icon}</span>
                  <span className="ac-snapshot-name">{latest.resource_name || latest.resource_id}</span>
                  <span className="ac-snapshot-type">{meta.label}</span>
                  <span className="ac-snapshot-time">{new Date(latest.collected_at).toLocaleString('ko-KR')}</span>
                  <span className="ac-expand-icon">{isOpen ? '▲' : '▼'}</span>
                </div>
                {isOpen && (
                  <DiffView oldData={prevOf(latest)?.raw_data} newData={latest.raw_data} />
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
                          {hOpen && <DiffView oldData={prevOf(h)?.raw_data} newData={h.raw_data} />}
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
