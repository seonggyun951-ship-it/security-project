import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { supabase } from '../lib/supabase'
import { RESOURCE_META } from '../lib/aws'

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

export default function Home() {
  const navigate = useNavigate()
  const [requests, setRequests] = useState([])
  const [snapshots, setSnapshots] = useState([])
  const [loading, setLoading] = useState(true)

  // 건수는 목록을 받아서 세지 않고 DB에서 직접 센다.
  // (예전엔 최신 50건만 받아 그중 pending을 세서, 신청이 50건을 넘으면 값이 틀렸음)
  const [statusCounts, setStatusCounts] = useState({ pending: 0, failed: 0 })

  const countByStatus = async (status) => {
    const { count } = await supabase.from('aws_requests')
      .select('id', { count: 'exact', head: true }).eq('status', status)
    return count || 0
  }

  useEffect(() => {
    const load = async () => {
      const [pendingCount, failedCount, reqRes, snapRes] = await Promise.all([
        countByStatus('pending'),
        countByStatus('failed'),
        supabase.from('aws_requests').select('*').order('requested_at', { ascending: false }).limit(50),
        supabase.from('aws_resource_snapshots').select('resource_type, resource_id, collected_at').order('collected_at', { ascending: false }).limit(200),
      ])
      setStatusCounts({ pending: pendingCount, failed: failedCount })
      setRequests(reqRes.data || [])
      setSnapshots(snapRes.data || [])
      setLoading(false)
    }
    load()
  }, [])

  const changedCount = countChangedResources(snapshots)
  const totalResources = new Set(snapshots.map((s) => `${s.resource_type}:${s.resource_id}`)).size
  const lastCollected = snapshots[0]?.collected_at

  // 최근 신청 나열 대신 리소스 타입별 신청 건수 요약
  const requestsByType = Object.keys(RESOURCE_META).map((key) => ({
    key,
    meta: RESOURCE_META[key],
    count: requests.filter((r) => r.resource_type === key).length,
  })).filter((r) => r.count > 0)

  const resourceCounts = Object.keys(RESOURCE_META).map((key) => ({
    key,
    meta: RESOURCE_META[key],
    count: new Set(snapshots.filter((s) => s.resource_type === key).map((s) => s.resource_id)).size,
  })).filter((r) => r.count > 0)

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
          label="승인 대기중" value={statusCounts.pending} unit="건"
          tone={statusCounts.pending > 0 ? 'alert' : null}
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
          label="적용 실패" value={statusCounts.failed} unit="건"
          tone={statusCounts.failed > 0 ? 'error' : null}
          onClick={() => navigate('/cloud-automation')}
        />
      </div>

      <div className="ac-grid">
        <div className="ac-card ac-card-wide">
          <div className="ac-card-title">신청 현황</div>
          {loading && <div className="ac-empty">불러오는 중...</div>}
          {!loading && requestsByType.length === 0 && <div className="ac-empty">아직 신청 내역이 없습니다.</div>}
          <div className="dash-resource-row">
            {requestsByType.map(({ key, meta, count }) => (
              <div key={key} className="dash-resource" onClick={() => navigate('/cloud-automation')}>
                <span className="dash-resource-count">{count}</span>
                <span className="dash-resource-label">{meta.label}</span>
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
    </div>
  )
}
