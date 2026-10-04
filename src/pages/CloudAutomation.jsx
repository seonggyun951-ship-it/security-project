import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { supabase } from '../lib/supabase'
import { ReqTable, ReqDrawer, BulkPanel, BulkResult, ACTION_LABEL, isDeleteAction, reqRisk, bulkBlockReason } from '../lib/aws'
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
  const [recent, setRecent] = useState([])     // 방금 처리한 것 확인용 (전체는 '승인 이력')
  const [checked, setChecked] = useState(new Set()) // 한 번에 승인할 신청 id
  const [bulkBusy, setBulkBusy] = useState(false)
  const [bulkResult, setBulkResult] = useState(null) // 한 번에 승인한 뒤의 건별 결과
  const isSuper = useIsSuperAdmin()

  // awaiting_super(1차 승인된 삭제)는 최고 관리자만 처리할 수 있다.
  // 1차 승인을 마친 일반 관리자에게는 더 할 일이 없으므로 대기 목록에서 빼고 이력으로 넘긴다.
  const OPEN = isSuper === true ? ['pending', 'awaiting_super'] : ['pending']
  const pendingRequests = requests.filter((r) => OPEN.includes(r.status))

  // 다른 관리자가 먼저 처리했거나 목록이 바뀌면, 더 이상 대기가 아닌 신청은 선택에서 뺀다.
  // 남겨두면 화면에 없는 신청까지 함께 승인하려 든다.
  useEffect(() => {
    setChecked((prev) => {
      const alive = new Set(requests.filter((r) => r.status === 'pending' && !bulkBlockReason(r)).map((r) => r.id))
      const next = new Set([...prev].filter((id) => alive.has(id)))
      return next.size === prev.size ? prev : next
    })
  }, [requests])
  const checkedRequests = pendingRequests.filter((r) => checked.has(r.id))

  const fetchRequests = async () => {
    pendingChanged() // 사이드바 대기 배지도 같이 맞춘다 (페이지는 새로고침하지 않음)
    setOpenReq(null) // 처리가 끝나면 드로어를 닫는다 (사라진 신청이 열려 있으면 안 됨)
    setLoading(true)
    // 처리 대기중인 것과, 방금 뭘 처리했는지 확인할 최근 이력만 가져온다.
    // 전체 이력은 '승인 이력' 화면이 따로 조회한다.
    const [open, done] = await Promise.all([
      fetchRows(
        supabase.from('aws_requests').select('*')
          .in('status', ['pending', 'awaiting_super'])
          .order('requested_at', { ascending: false }).limit(200),
        '신청 목록'),
      fetchRows(
        supabase.from('aws_requests').select('*')
          .in('status', ['applied', 'rejected', 'failed', 'cancelled'])
          .order('reviewed_at', { ascending: false, nullsFirst: false }).limit(10),
        '최근 처리'),
    ])
    setRequests(open.rows)
    setRecent(done.rows)
    setLoadError(open.error)
    setLoading(false)
  }

  useEffect(() => { fetchRequests() }, [])

  // Terraform 에이전트가 처리할 리소스 타입 — Edge Function 대신 DB 상태만 변경
  const TERRAFORM_TYPES = ['vpc', 'subnet', 'ec2_instance', 'internet_gateway', 'route_table']

  // 신청 한 건을 처리하고 결과를 돌려준다. 알림창은 띄우지 않는다 —
  // 한 건 승인(approve)은 결과를 알림창으로, 한 번에 승인(approveChecked)은 결과 패널로 보여준다.
  // 디스코드 알림은 어느 쪽이든 건마다 여기서 보낸다.
  const applyOne = async (req, opts) => {
    const id = req.id
    const actionLabel = ACTION_LABEL[req.action] || req.action || ''
    const reqName = req.title || req.target_id || ''
    // 관리자가 여러 명일 수 있으므로 누가 처리했는지 알림에 남긴다.
    const by = await approverLine()

    if (TERRAFORM_TYPES.includes(req.resource_type)) {
      // Terraform 대상: DB 상태만 approved로 변경 → 로컬 에이전트가 처리.
      // RLS로 관리자만 update 가능하므로 실패할 수 있다. 조용히 넘기면 승인된 줄 착각한다.
      const { ok, error } = await runWrite(
        supabase.from('aws_requests')
          .update({ status: 'approved', reviewed_at: new Date().toISOString() })
          .eq('id', id).eq('status', 'pending').select(),
        '승인')
      if (!ok) return { ok: false, error, alertText: error, message: error }
      notify(`✅ **승인 (Terraform 대기)**\n${actionLabel}: ${reqName}${by}\n→ 로컬 에이전트가 자동 적용 예정`)
      return { ok: true, message: '승인 · 노트북의 에이전트가 Terraform으로 적용합니다' }
    }

    // SG/WAF/IAM: Edge Function으로 즉시 적용
    const data = await callFunction('aws-request-apply', { request_id: id, issue_key: !!opts?.issueKey })
    if (!data.ok) {
      notify(`❌ **적용 실패**\n${actionLabel}: ${reqName}${by}\n오류: ${data.error}`)
      return { ok: false, error: data.error, alertText: '적용 실패: ' + data.error, message: data.error }
    }
    if (data.staged) {
      // 일반 관리자가 2차 승인 대상(삭제, prod·db 권한 부여)을 승인한 경우.
      // 실제 작업은 아직 일어나지 않았다.
      const what = isDeleteAction(req.action) ? '삭제' : '부여'
      notify(`🕓 **1차 승인**\n${actionLabel}: ${reqName}${by}\n→ 최고 관리자 최종 승인 대기 중`)
      return { ok: true, staged: true, alertText: `1차 승인되었습니다. 2차 승인 후 ${what}됩니다.`, message: `1차 승인 · 2차 승인 후 ${what}됩니다` }
    }
    // IAM은 신청자가 요청한 것과 다르게 승인할 수 있으므로, 실제 처리 결과를 남긴다.
    const keyLine = req.resource_type === 'iam_user' && !isDeleteAction(req.action)
      ? `\n액세스 키: ${opts?.issueKey ? '발급함' : '발급 안 함'}`
      : ''
    // 환경 권한은 처리 후 그 사람이 현재 가진 환경을 함께 남긴다
    const envLine = data.result?.current_env_groups
      ? `\n현재 권한: ${data.result.current_env_groups.join(', ') || '없음'}`
      : ''
    const title = isDeleteAction(req.action) ? '🗑️ **삭제 완료**'
      : req.action === 'grant_env_access' ? '🔑 **환경 권한 부여됨**'
        : req.action === 'revoke_env_access' ? '🔒 **환경 권한 회수됨**'
          : '✅ **승인 + 적용 완료**'
    notify(`${title}\n${actionLabel}: ${reqName}${by}${keyLine}${envLine}`)
    const created = data.result?.created_id ? ` (${data.result.created_id})` : ''
    return { ok: true, result: data.result, message: `승인 · AWS에 적용됨${created}` }
  }

  const approve = async (id, opts) => {
    const req = requests.find((r) => r.id === id)
    if (!req) return
    setBusyId(id)
    const res = await applyOne(req, opts)
    if (res.alertText) alert(res.alertText)
    if (res.result?.access_key_id && res.result?.secret_access_key) setRevealKey(res.result)
    await fetchRequests()
    setBusyId(null)
  }

  // 한 번에 승인 — 고른 순서가 아니라 목록 순서대로 한 건씩 처리한다.
  // 동시에 보내면 AWS 호출과 디스코드 알림이 뒤섞여 무엇이 왜 실패했는지 짚기 어렵다.
  const approveChecked = async () => {
    const targets = pendingRequests.filter((r) => checked.has(r.id) && !bulkBlockReason(r))
    if (targets.length === 0) return
    setBulkBusy(true)
    const results = []
    for (const r of targets) {
      setBusyId(r.id)
      const res = await applyOne(r)
      results.push({ id: r.id, title: r.title || r.target_id || '', label: ACTION_LABEL[r.action] || r.action, ok: res.ok, message: res.message })
    }
    setBusyId(null)
    setBulkBusy(false)
    setChecked(new Set())
    setOpenReq(null)
    setBulkResult(results)
    await fetchRequests()
  }

  const toggleCheck = (id) => {
    setBulkResult(null)
    setChecked((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }
  const setCheckedAll = (ids) => { setBulkResult(null); setChecked(new Set(ids)) }

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
  const shown = view === 'risk' ? riskyRequests
    : view === 'recent' ? recent
      : pendingRequests

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
                <> · <span style={{ color: 'var(--fail)', fontWeight: 700 }}>검토필요 {riskyRequests.length}건</span>
                  <span className="ap-hint">삭제 신청이거나 점검에서 걸린 것</span></>
              )}
            </div>
          </div>

          {/* 전체 이력은 '승인 이력' 메뉴로. 여기 '처리됨'은 최근 것만 보여준다. */}
          <div className="ap-chips">
            <button className={`ap-chip ${view === 'pending' ? 'on' : ''}`} onClick={() => setView('pending')}>
              대기 {pendingRequests.length}
            </button>
            <button className={`ap-chip ${view === 'risk' ? 'on' : ''}`} onClick={() => setView('risk')}>
              검토필요 {riskyRequests.length}
            </button>
            <button className={`ap-chip ${view === 'recent' ? 'on' : ''}`} onClick={() => setView('recent')}>
              승인내역 {recent.length}
            </button>
          </div>

          <div className="ap-body">
            <ErrorBanner message={loadError} onRetry={fetchRequests} />
            {loading && <div className="ac-empty">불러오는 중...</div>}

            {!loading && shown.length === 0 && (
              <div className="ac-empty">
                {view === 'risk' ? '검토가 필요한 신청이 없습니다.'
                  : view === 'recent' ? '승인내역이 없습니다.'
                    : '대기중인 신청이 없습니다.'}
              </div>
            )}

            {/* 하나라도 고르면 표 위에 붙는다. 승인내역(처리된 것)에는 고를 게 없다. */}
            {view !== 'recent' && checkedRequests.length > 0 && (
              <div className="bk-bar">
                <span><b>{checkedRequests.length}</b>건 선택</span>
                <span className="bk-bar-sp" />
                <button className="ac-btn ac-btn-secondary" disabled={bulkBusy} onClick={() => setCheckedAll([])}>선택 해제</button>
                <button className="ac-btn" disabled={bulkBusy} onClick={approveChecked}>
                  {bulkBusy ? '처리 중...' : '선택 승인'}
                </button>
              </div>
            )}

            {!loading && shown.length > 0 && (
              view === 'recent'
                ? <ReqTable requests={shown} selectedId={openReq?.id} onOpen={setOpenReq} />
                : <ReqTable requests={shown} selectedId={openReq?.id} onOpen={setOpenReq}
                    checked={checked} onCheck={toggleCheck} onCheckAll={setCheckedAll} />
            )}

            {/* 최근 처리 탭에서만 — 전체 이력은 '승인 이력' 화면으로 */}
            {!loading && view === 'recent' && recent.length > 0 && (
              <div className="ap-more">
                <Link to="/approval-history" className="ap-recent-more">전체 이력 보기 →</Link>
              </div>
            )}
          </div>
        </section>

        {/* 오른쪽 패널: 방금 한 번에 승인한 결과 → 2건 이상 고른 묶음 → 한 건 상세 */}
        {bulkResult ? (
          <BulkResult results={bulkResult} onClose={() => setBulkResult(null)} />
        ) : checkedRequests.length >= 2 ? (
          <BulkPanel requests={checkedRequests} busyId={busyId} busy={bulkBusy}
            onApprove={approveChecked} onUncheck={toggleCheck} onClear={() => setCheckedAll([])} />
        ) : (
          <ReqDrawer r={openReq || checkedRequests[0] || null} busyId={busyId} isSuper={isSuper === true}
            onApprove={approve} onReject={reject}
            onClose={() => { setOpenReq(null); if (checkedRequests.length === 1) setCheckedAll([]) }} />
        )}
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
