import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'
import { notify, summarizePayload } from '../lib/discord'
import { requireUser, currentUserId } from '../lib/auth'
import { pendingChanged } from '../lib/pending'
import { fetchRows } from '../lib/db'
import ErrorBanner from '../components/ErrorBanner'
import { MyReqGrouped, MiniCal } from '../components/RequestHistory'
import { localDateKey } from '../lib/date'
import { ACTION_LABEL, ReqCard, reqTitle } from '../lib/aws'
import { SgForm, WafForm, IamUserForm } from './forms/AwsForms'
import { SgDeleteForm, WafDeleteForm, IamDeleteForm } from './forms/DeleteForms'

// 리소스 타입별 신청 페이지 — 라우트에서 resourceType을 넘겨 재사용
const PAGE_META = {
  security_group: { title: 'Security Group 신청', sub: '신규 SG 생성 또는 기존 SG에 인바운드/아웃바운드 규칙 추가를 신청합니다.' },
  waf_web_acl:    { title: 'WAF 신청', sub: '신규 Web ACL 생성 또는 기존 Web ACL에 차단 규칙 추가를 신청합니다.' },
  iam_user:       { title: 'IAM 계정 신청', sub: '읽기 전용 IAM 계정 발급을 신청합니다.' },
}

export default function AwsRequest({ resourceType = 'security_group' }) {
  const [sgOptions, setSgOptions] = useState([])
  const [aclOptions, setAclOptions] = useState([])
  const [myRequests, setMyRequests] = useState([])
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [dateFilter, setDateFilter] = useState('')
  const [calOpen, setCalOpen] = useState(false)
  const [detailReq, setDetailReq] = useState(null)
  const [listError, setListError] = useState(null)
  const [optionsError, setOptionsError] = useState(null)
  const [mode, setMode] = useState('create') // 'create' | 'delete'

  const filteredRequests = dateFilter
    ? myRequests.filter((r) => localDateKey(r.requested_at) === dateFilter)
    : myRequests

  const dedupeByResource = (rows) => {
    const seen = new Set()
    return (rows || []).filter((s) => (seen.has(s.resource_id) ? false : (seen.add(s.resource_id), true)))
  }

  const fetchOptions = async () => {
    const { rows, error } = await fetchRows(
      supabase.from('aws_resource_options')
        .select('resource_id, resource_name, resource_type')
        .order('collected_at', { ascending: false }).limit(400),
      '리소스 목록')
    setSgOptions(dedupeByResource(rows.filter((s) => s.resource_type === 'security_group')))
    setAclOptions(dedupeByResource(rows.filter((s) => s.resource_type === 'waf_web_acl')))
    setOptionsError(error)
  }

  const fetchMyRequests = async () => {
    setLoading(true)
    // 본인이 낸 신청만 보여준다. 관리자는 RLS상 전체가 보이므로 여기서 걸러야 한다.
    const uid = await currentUserId()
    if (!uid) { setMyRequests([]); setLoading(false); return }
    const { rows, error } = await fetchRows(
      supabase.from('aws_requests').select('*')
        .eq('resource_type', resourceType).eq('requester_id', uid)
        .order('requested_at', { ascending: false }).limit(50),
      '신청 현황')
    setMyRequests(rows)
    setListError(error)
    setLoading(false)
  }

  useEffect(() => {
    fetchMyRequests()
    fetchOptions()
  }, [resourceType])

  const submitRequest = async (req) => {
    setSubmitting(true)
    let me
    try {
      me = await requireUser()
    } catch (e) {
      setSubmitting(false); alert(e.message); return false
    }
    const { error } = await supabase.from('aws_requests').insert({
      ...req,
      status: 'pending',
      requester_id: me.id,
      requester_email: me.email,
    })
    setSubmitting(false)
    if (error) { alert('신청 실패: ' + error.message); return false }
    await fetchMyRequests()
    const actionLabel = ACTION_LABEL[req.action] || req.action
    const detail = summarizePayload(req.action, req.payload)
    notify(`📋 **새 신청 접수**\n${actionLabel}: ${req.title || ''}\n신청자: ${me.email}${detail ? `\n내용: ${detail}` : ''}${req.reason ? `\n사유: ${req.reason}` : ''}`)
    pendingChanged() // 관리자 화면의 대기 배지 반영
    alert('신청되었습니다. 승인자 검토 후 반영됩니다.')
    return true
  }

  const meta = PAGE_META[resourceType] || PAGE_META.security_group

  const seenKey = `seen_rejected_${resourceType}`
  const getSeen = () => { try { return JSON.parse(localStorage.getItem(seenKey) || '[]') } catch { return [] } }
  const rejectedItems = myRequests.filter((r) => r.status === 'rejected')
  const unseenRejected = rejectedItems.filter((r) => !getSeen().includes(r.id))

  const dismissOne = (id) => {
    const seen = getSeen()
    seen.push(id)
    localStorage.setItem(seenKey, JSON.stringify(seen))
    setMyRequests([...myRequests])
  }

  const dismissAll = () => {
    localStorage.setItem(seenKey, JSON.stringify(rejectedItems.map((r) => r.id)))
    setMyRequests([...myRequests])
  }

  return (
    <div className="ac-page">
      <h2 className="ac-title">{meta.title}</h2>
      <p className="ac-sub">{meta.sub} 승인자 검토 후 실제 AWS에 반영됩니다.</p>

      <ErrorBanner message={optionsError} onRetry={fetchOptions} />
      <ErrorBanner message={listError} onRetry={fetchMyRequests} />

      {!loading && unseenRejected.length > 0 && (
        <div className="ac-reject-banner">
          <div className="ac-reject-banner-head">
            <span>거부된 신청 {unseenRejected.length}건</span>
            {unseenRejected.length > 1 && <button className="ac-btn ac-btn-secondary" style={{ padding: '2px 8px', fontSize: 11 }} onClick={dismissAll}>전체 확인</button>}
          </div>
          <div className="ac-reject-banner-list">
            {unseenRejected.map((r) => (
              <div key={r.id} className="ac-reject-banner-item" onClick={() => setDetailReq(r)} style={{ cursor: 'pointer' }}>
                <span className="ac-reject-banner-title">{reqTitle(r)}</span>
                {r.error_message && <span className="ac-reject-banner-reason">{r.error_message}</span>}
                <button className="ac-btn ac-btn-secondary" style={{ padding: '2px 6px', fontSize: 10, flexShrink: 0 }} onClick={(e) => { e.stopPropagation(); dismissOne(r.id) }}>확인</button>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="ac-grid">
        <div className="ac-card ac-card-wide">
          <div className="ac-card-title">신청서 작성</div>
          {/* 추가와 삭제는 성격이 반대라 탭으로 분리한다. 실수로 삭제를 누르지 않도록. */}
          <div className="ac-filter-row">
            <button className={`ac-filter-btn ${mode === 'create' ? 'active' : ''}`} onClick={() => setMode('create')}>
              추가 신청
            </button>
            <button className={`ac-filter-btn ${mode === 'delete' ? 'active' : ''}`} onClick={() => setMode('delete')}>
              삭제 신청
            </button>
          </div>

          {mode === 'create' ? (
            <>
              {resourceType === 'security_group' && <SgForm sgOptions={sgOptions} onSubmit={submitRequest} submitting={submitting} />}
              {resourceType === 'waf_web_acl' && <WafForm aclOptions={aclOptions} onSubmit={submitRequest} submitting={submitting} />}
              {resourceType === 'iam_user' && <IamUserForm onSubmit={submitRequest} submitting={submitting} />}
            </>
          ) : (
            <>
              {resourceType === 'security_group' && <SgDeleteForm onSubmit={submitRequest} submitting={submitting} />}
              {resourceType === 'waf_web_acl' && <WafDeleteForm onSubmit={submitRequest} submitting={submitting} />}
              {resourceType === 'iam_user' && <IamDeleteForm onSubmit={submitRequest} submitting={submitting} />}
            </>
          )}
        </div>

        <div className="ac-card ac-card-wide ac-card-muted">
          <div className="ac-card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ flex: 1 }}>내 신청 현황</span>
            <button className="ac-btn ac-btn-secondary" style={{ padding: '2px 8px', fontSize: 11 }} onClick={() => setCalOpen((v) => !v)}>
              {dateFilter || '날짜 선택'}
            </button>
            {dateFilter && <button className="ac-btn ac-btn-secondary" style={{ padding: '2px 8px', fontSize: 11 }} onClick={() => setDateFilter('')}>전체</button>}
          </div>
          {calOpen && <MiniCal requests={myRequests} selected={dateFilter} onSelect={(d) => { setDateFilter(d); setCalOpen(false) }} />}
          {loading && <div className="ac-empty">불러오는 중...</div>}
          {!loading && filteredRequests.length === 0 && <div className="ac-empty">{dateFilter ? '해당 날짜에 신청 내역이 없습니다.' : '아직 신청 내역이 없습니다.'}</div>}
          {!loading && filteredRequests.length > 0 && <MyReqGrouped requests={filteredRequests} />}
        </div>
      </div>

      {detailReq && (
        <div className="ac-datepop-backdrop" onClick={() => setDetailReq(null)}>
          <div className="ac-modal" onClick={(e) => e.stopPropagation()}>
            <div className="ac-modal-head">
              <span className="ac-modal-title">거부된 신청 상세</span>
              <button className="ac-btn ac-btn-secondary" onClick={() => setDetailReq(null)}>닫기</button>
            </div>
            <div className="ac-modal-body">
              <ReqCard r={detailReq} />
              {detailReq.error_message && (
                <div className="ac-reject-box" style={{ marginTop: 12 }}>거부 사유: {detailReq.error_message}</div>
              )}
              <button className="ac-btn" style={{ marginTop: 12, width: '100%' }} onClick={() => { dismissOne(detailReq.id); setDetailReq(null) }}>확인</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
