import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'
import { ACTION_LABEL, ReqCard, reqTitle } from '../lib/aws'
import { notify, summarizePayload } from '../lib/discord'
import { requireUser, currentUserId } from '../lib/auth'
import { pendingChanged } from '../lib/pending'
import { fetchRows, callFunction } from '../lib/db'
import ErrorBanner from '../components/ErrorBanner'
import { MyReqGrouped, MiniCal } from '../components/RequestHistory'
import { localDateKey } from '../lib/date'
import { INFRA_TYPES, PAGE_META, FORM_MAP } from './forms/InfraForms'

export default function InfraRequest({ mode = 'network' }) {
  const types = INFRA_TYPES[mode] || INFRA_TYPES.network
  const meta = PAGE_META[mode] || PAGE_META.network
  const [selected, setSelected] = useState(types[0].key)
  const [myRequests, setMyRequests] = useState([])
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [vpcOptions, setVpcOptions] = useState([])
  const [igwOptions, setIgwOptions] = useState([])
  const [subnetOptions, setSubnetOptions] = useState([])
  const [dateFilter, setDateFilter] = useState('')
  const [calOpen, setCalOpen] = useState(false)
  const [detailReq, setDetailReq] = useState(null)
  const [listError, setListError] = useState(null)
  const [optionsError, setOptionsError] = useState(null)

  const filteredRequests = dateFilter
    ? myRequests.filter((r) => localDateKey(r.requested_at) === dateFilter)
    : myRequests

  const typeKeys = types.map((t) => t.key)

  // 적용 완료된 신청에서 { id, 이름, 소속 VPC } 형태의 선택 옵션을 만든다.
  const optionsFromApplied = (rows, idKey) => rows
    .filter((r) => r.result?.created_id)
    .map((r) => ({
      [idKey]: r.result.created_id,
      name: r.title || r.payload?.name || r.result.created_id,
      vpc_id: r.payload?.vpc_id || '',
    }))

  const fetchVpcOptions = async () => {
    const errors = []
    const vpcMap = new Map()

    // 1) DB: SG 스냅샷에 딸린 VPC ID 추출.
    //    원본 테이블(raw_data)은 SG 규칙 전문이 들어있어 관리자 전용이다.
    //    일반 사용자는 필요한 컬럼만 뽑아둔 aws_resource_options 뷰를 통해 읽는다.
    const sg = await fetchRows(
      supabase.from('aws_resource_options')
        .select('vpc_id').eq('resource_type', 'security_group')
        .order('collected_at', { ascending: false }).limit(200),
      'VPC 목록(스냅샷)')
    if (sg.error) errors.push(sg.error)
    for (const row of sg.rows) {
      const id = row.vpc_id
      if (id && id.startsWith('vpc-') && !vpcMap.has(id)) vpcMap.set(id, { vpc_id: id, name: id })
    }

    // 2) DB: 적용된 VPC 신청에서 이름 보강
    const vpcReqs = await fetchRows(
      supabase.from('aws_requests')
        .select('title, payload, result').eq('resource_type', 'vpc').eq('status', 'applied'),
      'VPC 목록(신청 이력)')
    if (vpcReqs.error) errors.push(vpcReqs.error)
    for (const req of vpcReqs.rows) {
      const id = req.result?.created_id
      if (id) vpcMap.set(id, { vpc_id: id, name: req.title || req.payload?.name || id })
    }

    // 3) AWS API 실시간 조회로 덮어쓰기. 실패해도 위 DB 목록으로 동작해야 하므로 치명적 에러로 보지 않는다.
    const live = await callFunction('aws-list-vpcs')
    if (live.ok) {
      for (const v of (live.vpcs || [])) {
        vpcMap.set(v.vpc_id, { vpc_id: v.vpc_id, name: v.name || v.vpc_id })
      }
    } else {
      console.warn('AWS 실시간 VPC 조회 실패, DB 목록만 사용:', live.error)
    }
    setVpcOptions([...vpcMap.values()])

    const igw = await fetchRows(
      supabase.from('aws_requests')
        .select('title, payload, result').eq('resource_type', 'internet_gateway').eq('status', 'applied'),
      'IGW 목록')
    if (igw.error) errors.push(igw.error)
    setIgwOptions(optionsFromApplied(igw.rows, 'igw_id'))

    const subnet = await fetchRows(
      supabase.from('aws_requests')
        .select('title, payload, result').eq('resource_type', 'subnet').eq('status', 'applied'),
      '서브넷 목록')
    if (subnet.error) errors.push(subnet.error)
    setSubnetOptions(optionsFromApplied(subnet.rows, 'subnet_id'))

    setOptionsError(errors.length ? errors.join(' / ') : null)
  }

  const fetchMyRequests = async () => {
    setLoading(true)
    // 본인이 낸 신청만 보여준다. 관리자는 RLS상 전체가 보이므로 여기서 걸러야 한다.
    const uid = await currentUserId()
    if (!uid) { setMyRequests([]); setLoading(false); return }
    const { rows, error } = await fetchRows(
      supabase.from('aws_requests').select('*')
        .in('resource_type', typeKeys).eq('requester_id', uid)
        .order('requested_at', { ascending: false }).limit(50),
      '신청 현황')
    setMyRequests(rows)
    setListError(error)
    setLoading(false)
  }

  useEffect(() => {
    setSelected(types[0].key)
    fetchMyRequests()
    fetchVpcOptions()
  }, [mode])

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
    notify(`📋 **새 인프라 신청**\n${actionLabel}: ${req.title || ''}\n신청자: ${me.email}${detail ? `\n내용: ${detail}` : ''}${req.reason ? `\n사유: ${req.reason}` : ''}`)
    pendingChanged() // 관리자 화면의 대기 배지 반영
    alert('신청되었습니다. 승인 후 자동 적용됩니다.')
    return true
  }

  const FormComponent = FORM_MAP[selected]

  return (
    <div className="ac-page">
      <h2 className="ac-title">{meta.title}</h2>
      <p className="ac-sub">{meta.sub}</p>

      <ErrorBanner message={optionsError} onRetry={fetchVpcOptions} />
      <ErrorBanner message={listError} onRetry={fetchMyRequests} />

      {!loading && (() => {
        const seenKey = `seen_rejected_infra_${mode}`
        const getSeen = () => { try { return JSON.parse(localStorage.getItem(seenKey) || '[]') } catch { return [] } }
        const rejectedItems = myRequests.filter((r) => r.status === 'rejected' || r.status === 'failed')
        const unseenItems = rejectedItems.filter((r) => !getSeen().includes(r.id))
        if (unseenItems.length === 0) return null
        const dismissOne = (id) => { const s = getSeen(); s.push(id); localStorage.setItem(seenKey, JSON.stringify(s)); setMyRequests([...myRequests]) }
        const dismissAll = () => { localStorage.setItem(seenKey, JSON.stringify(rejectedItems.map((r) => r.id))); setMyRequests([...myRequests]) }
        return (
          <div className="ac-reject-banner">
            <div className="ac-reject-banner-head">
              <span>거부/실패된 신청 {unseenItems.length}건</span>
              {unseenItems.length > 1 && <button className="ac-btn ac-btn-secondary" style={{ padding: '2px 8px', fontSize: 11 }} onClick={dismissAll}>전체 확인</button>}
            </div>
            <div className="ac-reject-banner-list">
              {unseenItems.map((r) => (
                <div key={r.id} className="ac-reject-banner-item" onClick={() => setDetailReq(r)} style={{ cursor: 'pointer' }}>
                  <span className="ac-reject-banner-title">{reqTitle(r)}</span>
                  {r.error_message && <span className="ac-reject-banner-reason">{r.error_message.slice(0, 80)}</span>}
                  <button className="ac-btn ac-btn-secondary" style={{ padding: '2px 6px', fontSize: 10, flexShrink: 0 }} onClick={(e) => { e.stopPropagation(); dismissOne(r.id) }}>확인</button>
                </div>
              ))}
            </div>
          </div>
        )
      })()}

      <div className="ac-grid">
        <div className="ac-card ac-card-wide">
          <div className="ac-card-title">신청서 작성</div>
          {types.length > 1 && (
            <div className="ac-filter-row">
              {types.map((t) => (
                <button key={t.key} className={`ac-filter-btn ${selected === t.key ? 'active' : ''}`} onClick={() => setSelected(t.key)}>
                  {t.label}
                </button>
              ))}
            </div>
          )}
          {FormComponent && <FormComponent onSubmit={submitRequest} submitting={submitting} vpcOptions={vpcOptions} igwOptions={igwOptions} subnetOptions={subnetOptions} />}
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
          {!loading && filteredRequests.length > 0 && <MyReqGrouped requests={filteredRequests} showResult />}
        </div>
      </div>

      {detailReq && (
        <div className="ac-datepop-backdrop" onClick={() => setDetailReq(null)}>
          <div className="ac-modal" onClick={(e) => e.stopPropagation()}>
            <div className="ac-modal-head">
              <span className="ac-modal-title">신청 상세</span>
              <button className="ac-btn ac-btn-secondary" onClick={() => setDetailReq(null)}>닫기</button>
            </div>
            <div className="ac-modal-body">
              <ReqCard r={detailReq} />
              {detailReq.error_message && (
                <div className="ac-reject-box" style={{ marginTop: 12 }}>{detailReq.status === 'rejected' ? '거부 사유' : '에러'}: {detailReq.error_message}</div>
              )}
              <button className="ac-btn" style={{ marginTop: 12, width: '100%' }} onClick={() => setDetailReq(null)}>닫기</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
