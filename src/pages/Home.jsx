import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { supabase } from '../lib/supabase'
import { RESOURCE_META, ReqCard } from '../lib/aws'

// 리소스별 최신 스냅샷만 남기고, 변경 이력이 있는 리소스 수를 센다
function countChangedResources(snapshots) {
  const byResource = {}
  for (const s of snapshots) {
    const key = `${s.resource_type}:${s.resource_id}`
    byResource[key] = (byResource[key] || 0) + 1
  }
  return Object.values(byResource).filter((n) => n > 1).length
}

function StatCard({ label, value, unit, tone, onClick }) {
  return (
    <div className={`dash-stat ${tone ? `tone-${tone}` : ''} ${onClick ? 'is-clickable' : ''}`} onClick={onClick}>
      <div className="dash-stat-body">
        <div className="dash-stat-value">{value}<span className="dash-stat-unit">{unit}</span></div>
        <div className="dash-stat-label">{label}</div>
      </div>
    </div>
  )
}

const pad = (n) => String(n).padStart(2, '0')
const dateKey = (y, m, d) => `${y}-${pad(m + 1)}-${pad(d)}`

// DB의 timestamptz는 UTC라 문자열을 자르면 한국 날짜와 어긋난다. 로컬로 변환 후 날짜를 뽑는다.
function localDateKey(ts) {
  const d = new Date(ts)
  return dateKey(d.getFullYear(), d.getMonth(), d.getDate())
}

// 막대 구분 — 그날 무슨 일이 일어났는지 기준
const SERIES = [
  { key: 'requested', label: '신청', color: '#10b981' },
  { key: 'applied', label: '완료', color: '#0284c7' },
  { key: 'rejected', label: '승인 거부', color: '#94a3b8' },
  { key: 'failed', label: '실패', color: '#ef4444' },
]

// 신청 1건이 날짜별로 어떤 사건을 만드는지 펼친다.
// 신청은 신청한 날, 완료/거부/실패는 처리한 날에 잡힌다.
function eventsByDate(rows) {
  const days = {}
  const touch = (key) => {
    if (!days[key]) days[key] = { requested: 0, applied: 0, rejected: 0, failed: 0, ids: new Set() }
    return days[key]
  }
  for (const r of rows) {
    const reqDay = touch(localDateKey(r.requested_at))
    reqDay.requested++
    reqDay.ids.add(r.id)

    const doneAt = r.applied_at || r.reviewed_at
    if (!doneAt) continue
    if (r.status === 'applied' || r.status === 'rejected' || r.status === 'failed') {
      const d = touch(localDateKey(doneAt))
      d[r.status]++
      d.ids.add(r.id)
    }
  }
  return days
}

export default function Home() {
  const navigate = useNavigate()
  // 집계용: 필요한 컬럼만 전부 받아 정확히 센다 (limit 걸린 목록으로 세면 값이 틀림)
  const [rows, setRows] = useState([])
  const [snapshots, setSnapshots] = useState([])
  const [loading, setLoading] = useState(true)
  const [viewMonth, setViewMonth] = useState(() => {
    const t = new Date()
    return new Date(t.getFullYear(), t.getMonth(), 1)
  })
  const [detail, setDetail] = useState(null) // { date, items, loading }

  useEffect(() => {
    const load = async () => {
      const [reqRes, snapRes] = await Promise.all([
        supabase.from('aws_requests').select('id, status, resource_type, requested_at, reviewed_at, applied_at'),
        supabase.from('aws_resource_snapshots').select('resource_type, resource_id, collected_at').order('collected_at', { ascending: false }).limit(200),
      ])
      setRows(reqRes.data || [])
      setSnapshots(snapRes.data || [])
      setLoading(false)
    }
    load()
  }, [])

  // 막대를 눌렀을 때만 그날 신청 상세를 조회한다 (미리 다 받아두지 않음)
  const openDay = async (dateStr, ids) => {
    if (ids.length === 0) return
    setDetail({ date: dateStr, items: [], loading: true })
    const { data } = await supabase.from('aws_requests').select('*')
      .in('id', ids).order('requested_at', { ascending: false })
    setDetail({ date: dateStr, items: data || [], loading: false })
  }

  const pendingCount = rows.filter((r) => r.status === 'pending').length
  const failedCount = rows.filter((r) => r.status === 'failed').length
  const changedCount = countChangedResources(snapshots)
  const totalResources = new Set(snapshots.map((s) => `${s.resource_type}:${s.resource_id}`)).size
  const lastCollected = snapshots[0]?.collected_at

  const days = eventsByDate(rows)
  const year = viewMonth.getFullYear()
  const month = viewMonth.getMonth()
  const daysInMonth = new Date(year, month + 1, 0).getDate()
  const todayKey = localDateKey(new Date())

  const bars = []
  for (let d = 1; d <= daysInMonth; d++) {
    const key = dateKey(year, month, d)
    const e = days[key] || { requested: 0, applied: 0, rejected: 0, failed: 0, ids: new Set() }
    bars.push({ day: d, key, ...e, ids: [...e.ids], total: e.requested + e.applied + e.rejected + e.failed })
  }
  const maxTotal = Math.max(1, ...bars.map((b) => b.total))
  const monthTotals = SERIES.reduce((acc, s) => {
    acc[s.key] = bars.reduce((n, b) => n + b[s.key], 0)
    return acc
  }, {})

  const resourceCounts = Object.keys(RESOURCE_META).map((key) => ({
    key,
    meta: RESOURCE_META[key],
    count: new Set(snapshots.filter((s) => s.resource_type === key).map((s) => s.resource_id)).size,
  })).filter((r) => r.count > 0)

  const shiftMonth = (delta) => setViewMonth(new Date(year, month + delta, 1))

  return (
    <div className="ac-page dash-page">
      <h2 className="ac-title">대시보드</h2>
      <p className="ac-sub">
        {loading ? '불러오는 중...' : lastCollected
          ? `마지막 수집: ${new Date(lastCollected).toLocaleString('ko-KR')}`
          : '아직 수집 이력이 없습니다.'}
      </p>

      <div className="dash-stats">
        <StatCard
          label="승인 대기중" value={pendingCount} unit="건"
          tone={pendingCount > 0 ? 'alert' : null}
          onClick={() => navigate('/cloud-automation')}
        />
        <StatCard
          label="변경된 리소스" value={changedCount} unit="개"
          tone={changedCount > 0 ? 'warn' : null}
          onClick={() => navigate('/aws-status')}
        />
        <StatCard
          label="수집된 리소스" value={totalResources} unit="개"
          onClick={() => navigate('/aws-status')}
        />
        <StatCard
          label="적용 실패" value={failedCount} unit="건"
          tone={failedCount > 0 ? 'error' : null}
          onClick={() => navigate('/cloud-automation')}
        />
      </div>

      <div className="ac-grid">
        <div className="ac-card ac-card-wide">
          <div className="dash-chart-head">
            <div className="dash-month-nav">
              <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => shiftMonth(-1)}>‹</button>
              <span className="dash-month-title">{year}년 {month + 1}월</span>
              <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => shiftMonth(1)}>›</button>
            </div>
            <div className="dash-legend">
              {SERIES.map((s) => (
                <span key={s.key} className="dash-legend-item">
                  <i className="dash-legend-dot" style={{ background: s.color }} />
                  {s.label} {monthTotals[s.key]}
                </span>
              ))}
            </div>
          </div>

          {loading && <div className="ac-empty">불러오는 중...</div>}
          {!loading && (
            <div className="dash-chart">
              {bars.map((b) => (
                <div
                  key={b.key}
                  className={`dash-bar-col ${b.total > 0 ? 'has-data' : ''} ${b.key === todayKey ? 'is-today' : ''}`}
                  onClick={() => openDay(b.key, b.ids)}
                  title={b.total > 0
                    ? `${month + 1}/${b.day} — ${SERIES.filter((s) => b[s.key] > 0).map((s) => `${s.label} ${b[s.key]}`).join(', ')}`
                    : `${month + 1}/${b.day} — 없음`}
                >
                  <div className="dash-bar-stack">
                    {SERIES.map((s) => b[s.key] > 0 && (
                      <div
                        key={s.key}
                        className="dash-bar-seg"
                        style={{ height: `${(b[s.key] / maxTotal) * 100}%`, background: s.color }}
                      />
                    ))}
                  </div>
                  <span className="dash-bar-label">{b.day}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="ac-card ac-card-wide ac-card-muted">
          <div className="ac-card-title">리소스 구성</div>
          {!loading && resourceCounts.length === 0 && <div className="ac-empty">수집된 리소스가 없습니다.</div>}
          <div className="dash-resource-row">
            {resourceCounts.map(({ key, meta, count }) => (
              <div key={key} className="dash-resource" onClick={() => navigate('/aws-status')}>
                <span className="dash-resource-count">{count}</span>
                <span className="dash-resource-label">{meta.label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {detail && (
        <div className="ac-datepop-backdrop" onClick={() => setDetail(null)}>
          <div className="ac-modal" onClick={(e) => e.stopPropagation()}>
            <div className="ac-modal-head">
              <span className="ac-modal-title">{detail.date} <b>{detail.items.length}</b>건</span>
              <button className="ac-btn ac-btn-secondary" onClick={() => setDetail(null)}>닫기</button>
            </div>
            <div className="ac-modal-body">
              {detail.loading && <div className="ac-empty">불러오는 중...</div>}
              {!detail.loading && (
                <div className="ac-snapshot-list">
                  {detail.items.map((r) => <ReqCard key={r.id} r={r} />)}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
