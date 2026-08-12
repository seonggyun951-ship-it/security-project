import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'
import { ReqTable, ReqDrawer, ACTION_LABEL, isDeleteAction, reqRisk } from '../lib/aws'
import { notify } from '../lib/discord'
import { fetchRows, runWrite, callFunction } from '../lib/db'
import { approverLine, useIsSuperAdmin } from '../lib/auth'
import { pendingChanged } from '../lib/pending'
import ErrorBanner from '../components/ErrorBanner'

// 발급된 액세스키를 한 번만 보여주는 팝업 (DB에는 저장하지 않음 — 닫으면 다시 못 봄)
function RevealKeyPopup({ result, onClose }) {
  const copy = (text) => navigator.clipboard?.writeText(text)
  return (
    <div className="ac-datepop-backdrop" onClick={onClose}>
      <div className="ac-datepop" onClick={(e) => e.stopPropagation()}>
        <div className="ac-cal-title">{result.user_name} 액세스키 발급됨</div>
        <p className="ac-cred-note">이 화면을 닫으면 Secret Key는 다시 조회할 수 없습니다. 지금 바로 복사해두세요.</p>
        <div className="ac-form-row">
          <div className="ac-field">
            <label className="ac-label">Access Key ID</label>
            <input className="ac-input" readOnly value={result.access_key_id} onFocus={(e) => e.target.select()} />
          </div>
          <button className="ac-btn ac-btn-secondary" onClick={() => copy(result.access_key_id)}>복사</button>
        </div>
        <div className="ac-form-row">
          <div className="ac-field">
            <label className="ac-label">Secret Access Key</label>
            <input className="ac-input" readOnly value={result.secret_access_key} onFocus={(e) => e.target.select()} />
          </div>
          <button className="ac-btn ac-btn-secondary" onClick={() => copy(result.secret_access_key)}>복사</button>
        </div>
        <div className="ac-datepop-actions">
          <button className="ac-btn" onClick={onClose}>확인했습니다, 닫기</button>
        </div>
      </div>
    </div>
  )
}

// 처리 대기중인 신청만 다룬다. 지나간 건은 '승인 이력' 화면으로 분리했다.
function RequestQueue() {
  const [requests, setRequests] = useState([])
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState(null)
  const [revealKey, setRevealKey] = useState(null)
  const [loadError, setLoadError] = useState(null)
  const [openReq, setOpenReq] = useState(null) // 검토 패널에 열린 신청
  const [view, setView] = useState('pending')  // 'pending' | 'risk'
  const isSuper = useIsSuperAdmin()

  // awaiting_super(1차 승인된 삭제)는 최고 관리자만 처리할 수 있다.
  // 1차 승인을 마친 일반 관리자에게는 더 할 일이 없으므로 대기 목록에서 빼고 이력으로 넘긴다.
  const OPEN = isSuper === true ? ['pending', 'awaiting_super'] : ['pending']
  const pendingRequests = requests.filter((r) => OPEN.includes(r.status))

  const fetchRequests = async () => {
    pendingChanged() // 사이드바 대기 배지도 같이 맞춘다 (페이지는 새로고침하지 않음)
    setOpenReq(null) // 처리가 끝나면 드로어를 닫는다 (사라진 신청이 열려 있으면 안 됨)
    setLoading(true)
    // 처리 대기중인 것만 가져온다. 지나간 건은 '승인 이력' 화면이 따로 조회한다.
    const { rows, error } = await fetchRows(
      supabase.from('aws_requests').select('*')
        .in('status', ['pending', 'awaiting_super'])
        .order('requested_at', { ascending: false }).limit(200),
      '신청 목록')
    setRequests(rows)
    setLoadError(error)
    setLoading(false)
  }

  useEffect(() => { fetchRequests() }, [])

  // Terraform 에이전트가 처리할 리소스 타입 — Edge Function 대신 DB 상태만 변경
  const TERRAFORM_TYPES = ['vpc', 'subnet', 'ec2_instance', 'internet_gateway', 'route_table']

  const approve = async (id, opts) => {
    setBusyId(id)
    const req = requests.find((r) => r.id === id)

    const actionLabel = ACTION_LABEL[req?.action] || req?.action || ''
    const reqName = req?.title || req?.target_id || ''
    // 관리자가 여러 명일 수 있으므로 누가 처리했는지 알림에 남긴다.
    const by = await approverLine()

    if (req && TERRAFORM_TYPES.includes(req.resource_type)) {
      // Terraform 대상: DB 상태만 approved로 변경 → 로컬 에이전트가 처리.
      // RLS로 관리자만 update 가능하므로 실패할 수 있다. 조용히 넘기면 승인된 줄 착각한다.
      const { ok, error } = await runWrite(
        supabase.from('aws_requests')
          .update({ status: 'approved', reviewed_at: new Date().toISOString() })
          .eq('id', id).eq('status', 'pending').select(),
        '승인')
      if (!ok) {
        alert(error)
      } else {
        notify(`✅ **승인 (Terraform 대기)**\n${actionLabel}: ${reqName}${by}\n→ 로컬 에이전트가 자동 적용 예정`)
      }
    } else {
      // SG/WAF/IAM: Edge Function으로 즉시 적용
      const data = await callFunction('aws-request-apply', { request_id: id, issue_key: !!opts?.issueKey })
      if (!data.ok) {
        alert('적용 실패: ' + data.error)
        notify(`❌ **적용 실패**\n${actionLabel}: ${reqName}${by}\n오류: ${data.error}`)
      } else if (data.staged) {
        // 삭제 신청을 일반 관리자가 승인한 경우 — 실제 삭제는 아직 일어나지 않았다.
        alert('1차 승인되었습니다. 2차 승인 후 삭제됩니다.')
        notify(`🕓 **삭제 1차 승인**\n${actionLabel}: ${reqName}${by}\n→ 최고 관리자 최종 승인 대기 중`)
      } else {
        // IAM은 신청자가 요청한 것과 다르게 승인할 수 있으므로, 실제 처리 결과를 남긴다.
        const keyLine = req?.resource_type === 'iam_user' && !isDeleteAction(req?.action)
          ? `\n액세스 키: ${opts?.issueKey ? '발급함' : '발급 안 함'}`
          : ''
        const title = isDeleteAction(req?.action) ? '🗑️ **삭제 완료**' : '✅ **승인 + 적용 완료**'
        notify(`${title}\n${actionLabel}: ${reqName}${by}${keyLine}`)
        if (data.result?.access_key_id && data.result?.secret_access_key) setRevealKey(data.result)
      }
    }
    await fetchRequests()
    setBusyId(null)
  }

  const reject = async (id) => {
    const reason = prompt('거부 사유를 입력해주세요.')
    if (reason === null) return
    setBusyId(id)
    const req = requests.find((r) => r.id === id)
    const actionLabel = ACTION_LABEL[req?.action] || req?.action || ''
    const reqName = req?.title || req?.target_id || ''
    const by = await approverLine('거부자')
    const { ok, error } = await runWrite(
      supabase.from('aws_requests').update({
        status: 'rejected',
        reviewed_at: new Date().toISOString(),
        error_message: reason.trim() || null,
      // 1차 승인된 삭제(awaiting_super)도 최종 단계에서 거부할 수 있어야 한다.
      }).eq('id', id).in('status', ['pending', 'awaiting_super']).select(),
      '거부')
    if (!ok) {
      alert(error)
    } else {
      notify(`🚫 **신청 거부**\n${actionLabel}: ${reqName}${by}${reason.trim() ? `\n사유: ${reason.trim()}` : ''}`)
    }
    await fetchRequests()
    setBusyId(null)
  }

  // 위험한 건만 추려 보기 — 삭제 신청이나 전체 개방처럼 먼저 봐야 하는 것들
  const riskyRequests = pendingRequests.filter((r) => reqRisk(r) === 'risk')
  const shown = view === 'risk' ? riskyRequests : pendingRequests

  return (
    <>
      {revealKey && <RevealKeyPopup result={revealKey} onClose={() => setRevealKey(null)} />}

      {/* 목록과 검토 패널이 화면 높이를 채우는 2단.
          카드로 감싸지 않아야 시안처럼 경계가 깔끔하게 떨어진다. */}
      <div className="ap">
        <section className="ap-col">
          <div className="ap-head">
            <div className="ap-h1">관리자 승인</div>
            <div className="ap-h2">
              대기 {pendingRequests.length}건
              {riskyRequests.length > 0 && (
                <> · <span style={{ color: 'var(--fail)', fontWeight: 700 }}>위험 {riskyRequests.length}건</span>
                  <span className="ap-hint">삭제 신청이거나 전체 개방(0.0.0.0/0)</span></>
              )}
            </div>
          </div>

          {/* 이력은 '승인 이력' 메뉴로 분리했다. 여기는 처리할 것만 다룬다. */}
          <div className="ap-chips">
            <button className={`ap-chip ${view === 'pending' ? 'on' : ''}`} onClick={() => setView('pending')}>
              대기 {pendingRequests.length}
            </button>
            <button className={`ap-chip ${view === 'risk' ? 'on' : ''}`} onClick={() => setView('risk')}>
              위험 {riskyRequests.length}
            </button>
          </div>

          <div className="ap-body">
            <ErrorBanner message={loadError} onRetry={fetchRequests} />
            {loading && <div className="ac-empty">불러오는 중...</div>}

            {!loading && shown.length === 0 && (
              <div className="ac-empty">
                {view === 'risk' ? '위험으로 분류된 신청이 없습니다.' : '대기중인 신청이 없습니다.'}
              </div>
            )}

            {!loading && shown.length > 0 && (
              <ReqTable requests={shown} selectedId={openReq?.id} onOpen={setOpenReq} />
            )}
          </div>
        </section>

        <ReqDrawer r={openReq} busyId={busyId} isSuper={isSuper === true}
          onApprove={approve} onReject={reject} onClose={() => setOpenReq(null)} />
      </div>
    </>
  )
}

export default function CloudAutomation() {
  return (
    // 페이지 제목·여백 없이 화면을 꽉 채운다. 제목은 목록 머리에 들어간다.
    <div className="ap-page">
      <RequestQueue />
    </div>
  )
}
