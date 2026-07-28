import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { supabase } from '../lib/supabase'
import { RESOURCE_META, REQ_STATUS_META, ReqCard } from '../lib/aws'

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

// 손이 필요한 상태를 위로
const STATUS_ORDER = ['pending', 'failed', 'approved', 'applied', 'rejected']

const shortType = { security_group: 'SG', waf_web_acl: 'WAF', iam_user: 'IAM' }

function elapsed(ts) {
  const h = Math.floor((Date.now() - new Date(ts).getTime()) / 3600000)
  if (h < 1) return '1시간 미만'
  if (h < 24) return `${h}시간`
  return `${Math.floor(h / 24)}일`
}

const mmdd = (ts) => new Date(ts).toLocaleDateString('ko-KR', { month: '2-digit', day: '2-digit' })

export default function Home() {
  const navigate = useNavigate()
  // 집계용: 컬럼 3개만 전부 받아서 정확히 센다 (limit 걸린 목록으로 세면 값이 틀림)
  const [summaryRows, setSummaryRows] = useState([])
  const [snapshots, setSnapshots] = useState([])
  const [loading, setLoading] = useState(true)

  // 요약 줄을 눌렀을 때만 해당 상태의 상세를 조회 (미리 다 받아두지 않음)
  const [detail, setDetail] = useState(null) // { status, items, loading }

  useEffect(() => {
    const load = async () => {
      const [reqRes, snapRes] = await Promise.all([
        supabase.from('aws_requests').select('status, resource_type, requested_at'),
        supabase.from('aws_resource_snapshots').select('resource_type, resource_id, collected_at').order('collected_at', { ascending: false }).limit(200),
      ])
      setSummaryRows(reqRes.data || [])
      setSnapshots(snapRes.data || [])
      setLoading(false)
    }
    load()
  }, [])

  const openDetail = async (status) => {
    setDetail({ status, items: [], loading: true })
    const { data } = await supabase.from('aws_requests').select('*')
      .eq('status', status).order('requested_at', { ascending: false }).limit(200)
    setDetail({ status, items: data || [], loading: false })
  }

  const pendingCount = summaryRows.filter((r) => r.status === 'pending').length
  const failedCount = summaryRows.filter((r) => r.status === 'failed').length
  const changedCount = countChangedResources(snapshots)
  const totalResources = new Set(snapshots.map((s) => `${s.resource_type}:${s.resource_id}`)).size
  const lastCollected = snapshots[0]?.collected_at

  // 상태별 요약: 건수 + 리소스 타입 분포 + 시간 정보까지 줄에 남긴다
  const statusRows = STATUS_ORDER.map((status) => {
    const items = summaryRows.filter((r) => r.status === status)
    if (items.length === 0) return null
    const byType = {}
    for (const r of items) byType[r.resource_type] = (byType[r.resource_type] || 0) + 1
    const times = items.map((r) => r.requested_at).sort()
    return {
      status,
      meta: REQ_STATUS_META[status] || { label: status, color: '#94a3b8' },
      count: items.length,
      types: Object.entries(byType).map(([t, n]) => `${shortType[t] || t} ${n}`).join(' · '),
      oldest: times[0],
      newest: times[times.length - 1],
      needsAction: status === 'pending' || status === 'failed',
    }
  }).filter(Boolean)

  const resourceCounts = Object.keys(RESOURCE_META).map((key) => ({
    key,
    meta: RESOURCE_META[key],
    count: new Set(snapshots.filter((s) => s.resource_type === key).map((s) => s.resource_id)).size,
  })).filter((r) => r.count > 0)

  const detailMeta = detail ? (REQ_STATUS_META[detail.status] || { label: detail.status }) : null

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
          <div className="ac-card-title">신청 현황</div>
          {loading && <div className="ac-empty">불러오는 중...</div>}
          {!loading && statusRows.length === 0 && <div className="ac-empty">아직 신청 내역이 없습니다.</div>}
          <div className="ac-daylist">
            {statusRows.map((row) => (
              <div
                key={row.status}
                className={`ac-dayrow ${row.needsAction ? 'is-action' : ''}`}
                onClick={() => openDetail(row.status)}
              >
                <span className="ac-req-status" style={{ background: row.meta.color }}>{row.meta.label}</span>
                <span className="ac-dayrow-total">{row.count}건</span>
                <span className="ac-dayrow-breakdown">
                  <span className="ac-dayrow-stat">{row.types}</span>
                  <span className="ac-dayrow-stat ac-dayrow-time">
                    {row.needsAction ? `가장 오래 ${elapsed(row.oldest)}` : `최근 ${mmdd(row.newest)}`}
                  </span>
                </span>
                <span className="ac-dayrow-open">보기</span>
              </div>
            ))}
          </div>
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
              <span className="ac-modal-title">{detailMeta.label} 신청 <b>{detail.items.length}</b>건</span>
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
