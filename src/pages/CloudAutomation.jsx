import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'
import { ReqCard, ReqTable, ReqDrawer, REQ_STATUS_META, ACTION_LABEL, isDeleteAction, reqRisk } from '../lib/aws'
import { notify } from '../lib/discord'
import { fetchRows, runWrite, callFunction } from '../lib/db'
import { approverLine, useIsSuperAdmin } from '../lib/auth'
import { pendingChanged } from '../lib/pending'
import ErrorBanner from '../components/ErrorBanner'
import {
  WEEKDAYS, dateKey, localDateKey, todayKey, monthCells,
  groupByDate, countsByDate, PERIOD_OPTIONS, periodRange, inRange,
} from '../lib/date'

function DatePickerPopup({ countsByDate, selected, onSelect, onViewAll, onClose }) {
  const today = new Date()
  const base = selected ? new Date(selected + 'T00:00:00') : today
  const [viewDate, setViewDate] = useState(new Date(base.getFullYear(), base.getMonth(), 1))

  const year = viewDate.getFullYear()
  const month = viewDate.getMonth()
  const cells = monthCells(year, month)
  const tKey = todayKey()

  return (
    <div className="ac-datepop-backdrop" onClick={onClose}>
      <div className="ac-datepop" onClick={(e) => e.stopPropagation()}>
        <div className="ac-cal-header">
          <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => setViewDate(new Date(year, month - 1, 1))}>‹</button>
          <span className="ac-cal-title">{year}년 {month + 1}월</span>
          <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => setViewDate(new Date(year, month + 1, 1))}>›</button>
        </div>
        <div className="ac-cal-grid">
          {WEEKDAYS.map((w) => <div key={w} className="ac-cal-weekday">{w}</div>)}
          {cells.map((d, i) => {
            if (d === null) return <div key={i} className="ac-cal-cell ac-cal-empty" />
            const key = dateKey(year, month, d)
            const count = countsByDate[key] || 0
            const isToday = key === tKey
            const isSelected = key === selected
            return (
              <div
                key={i}
                className={`ac-cal-cell ${count > 0 ? 'has-data' : ''} ${isToday ? 'is-today' : ''} ${isSelected ? 'is-selected' : ''}`}
                onClick={() => onSelect(key)}
              >
                <span className="ac-cal-day">{d}</span>
                <span className="ac-cal-count">{count > 0 ? count : ''}</span>
              </div>
            )
          })}
        </div>
        <div className="ac-datepop-actions">
          <button className="ac-btn ac-btn-secondary" onClick={onClose}>닫기</button>
        </div>
      </div>
    </div>
  )
}

const HISTORY_CATEGORIES = [
  { key: 'all', label: '전체' },
  { key: 'security_group', label: ' SG' },
  { key: 'waf_web_acl', label: ' WAF' },
  { key: 'iam_user', label: ' IAM' },
  { key: 'vpc', label: ' VPC' },
  { key: 'subnet', label: ' 서브넷' },
  { key: 'ec2_instance', label: ' EC2' },
  { key: 'internet_gateway', label: ' IGW' },
  { key: 'route_table', label: ' RT' },
]

// 날짜 요약 줄에 표시할 상태 순서
const STATUS_ORDER = ['applied', 'rejected', 'failed', 'approved']

function statusSummary(items) {
  const c = {}
  for (const r of items) c[r.status] = (c[r.status] || 0) + 1
  return STATUS_ORDER.filter((s) => c[s]).map((s) => ({ status: s, count: c[s], meta: REQ_STATUS_META[s] }))
}

// 하루치 처리 내역을 새 창(모달)으로 — 목록을 화면에 펼치지 않기 위해
function DayDetailModal({ date, items, busyId, onRemove, onClose }) {
  return (
    <div className="ac-datepop-backdrop" onClick={onClose}>
      <div className="ac-modal" onClick={(e) => e.stopPropagation()}>
        <div className="ac-modal-head">
          <span className="ac-modal-title">{date} 처리 내역 <b>{items.length}</b>건</span>
          <button className="ac-btn ac-btn-secondary" onClick={onClose}>닫기</button>
        </div>
        <div className="ac-modal-body">
          <div className="ac-snapshot-list">
            {items.map((r) => <ReqCard key={r.id} r={r} busyId={busyId} onRemove={onRemove} />)}
          </div>
        </div>
      </div>
    </div>
  )
}

function HistoryList({ historyRequests, busyId, onRemove }) {
  const tKey = todayKey()

  const [category, setCategory] = useState('all')
  const [period, setPeriod] = useState('day')
  const [periodOffset, setPeriodOffset] = useState(0)
  const [dateFilter, setDateFilter] = useState(tKey)
  const [pickerOpen, setPickerOpen] = useState(false)
  const [openDate, setOpenDate] = useState(null)

  const range = (period === 'month' || period === 'week') ? periodRange(period, periodOffset) : null
  const dayCounts = countsByDate(historyRequests)

  const periodFiltered = period === 'day' && dateFilter
    ? historyRequests.filter((r) => localDateKey(r.requested_at) === dateFilter)
    : period === 'all'
      ? historyRequests
      : historyRequests.filter((r) => inRange(r.requested_at, range))
  const filtered = category === 'all' ? periodFiltered : periodFiltered.filter((r) => r.resource_type === category)
  const grouped = groupByDate(filtered)
  const counts = { all: periodFiltered.length }
  for (const r of periodFiltered) counts[r.resource_type] = (counts[r.resource_type] || 0) + 1

  const changePeriod = (p) => { setPeriod(p); setPeriodOffset(0); setDateFilter(p === 'day' ? tKey : '') }

  return (
    <div>
      <div className="ac-filter-row">
        {PERIOD_OPTIONS.map((p) => (
          <button key={p.key} className={`ac-filter-btn ${period === p.key ? 'active' : ''}`} onClick={() => changePeriod(p.key)}>
            {p.label}
          </button>
        ))}
      </div>
      <div className="ac-filter-row">
        {(period === 'month' || period === 'week') && range && (
          <div className="ac-period-nav">
            <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => setPeriodOffset(periodOffset - 1)}>‹</button>
            <span className="ac-period-label">{range.label}</span>
            <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => setPeriodOffset(periodOffset + 1)}>›</button>
          </div>
        )}
        {period === 'day' && (
          <div className="ac-date-picker">
            <button className="ac-date-trigger" onClick={() => setPickerOpen(true)}>
              {dateFilter || '날짜 선택'}
            </button>
          </div>
        )}
        {pickerOpen && (
          <DatePickerPopup
            countsByDate={dayCounts}
            selected={dateFilter}
            onSelect={(key) => { setDateFilter(key); setPickerOpen(false) }}
            onViewAll={() => { setDateFilter(''); setPickerOpen(false) }}
            onClose={() => setPickerOpen(false)}
          />
        )}
        {HISTORY_CATEGORIES.map((c) => (
          <button key={c.key} className={`ac-filter-btn ${category === c.key ? 'active' : ''}`} onClick={() => setCategory(c.key)}>
            {c.label} {counts[c.key] || 0}
          </button>
        ))}
      </div>
      {grouped.length === 0 && <div className="ac-empty">해당 항목이 없습니다.</div>}
      {/* 날짜당 한 줄만 — 건수가 늘어도 화면 길이가 날짜 수만큼만 늘어남 */}
      <div className="ac-daylist">
        {grouped.map(([date, items]) => (
          <div key={date} className="ac-dayrow" onClick={() => setOpenDate(date)}>
            <span className="ac-dayrow-date">{date}</span>
            <span className="ac-dayrow-total">{items.length}건</span>
            <span className="ac-dayrow-breakdown">
              {statusSummary(items).map(({ status, count, meta }) => (
                <span key={status} className="ac-dayrow-stat">
                  <i className="ac-dayrow-dot" style={{ background: meta.color }} />
                  {meta.label} {count}
                </span>
              ))}
            </span>
            <span className="ac-dayrow-open">보기</span>
          </div>
        ))}
      </div>

      {openDate && (
        <DayDetailModal
          date={openDate}
          items={grouped.find(([d]) => d === openDate)?.[1] || []}
          busyId={busyId}
          onRemove={onRemove}
          onClose={() => setOpenDate(null)}
        />
      )}
    </div>
  )
}

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

// 신청 대기/이력 관리 (통합 큐)
function RequestQueue() {
  const [requests, setRequests] = useState([])
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState(null)
  const [revealKey, setRevealKey] = useState(null)
  const [loadError, setLoadError] = useState(null)
  const [openReq, setOpenReq] = useState(null) // 검토 패널에 열린 신청
  const [view, setView] = useState('pending')  // 'pending' | 'risk' | 'history'
  const isSuper = useIsSuperAdmin()

  // awaiting_super(1차 승인된 삭제)는 최고 관리자만 처리할 수 있다.
  // 1차 승인을 마친 일반 관리자에게는 더 할 일이 없으므로 대기 목록에서 빼고 이력으로 넘긴다.
  const OPEN = isSuper === true ? ['pending', 'awaiting_super'] : ['pending']
  const pendingRequests = requests.filter((r) => OPEN.includes(r.status))
  const historyRequests = requests.filter((r) => !OPEN.includes(r.status))

  const fetchRequests = async () => {
    pendingChanged() // 사이드바 대기 배지도 같이 맞춘다 (페이지는 새로고침하지 않음)
    setOpenReq(null) // 처리가 끝나면 드로어를 닫는다 (사라진 신청이 열려 있으면 안 됨)
    setLoading(true)
    const { rows, error } = await fetchRows(
      supabase.from('aws_requests').select('*').order('requested_at', { ascending: false }).limit(100),
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

  const removeRequest = async (id) => {
    if (!confirm('이 신청을 목록에서 삭제할까요?')) return
    setBusyId(id)
    const { ok, error } = await runWrite(
      supabase.from('aws_requests').delete().eq('id', id).select(), '삭제')
    setBusyId(null)
    if (!ok) return alert(error)
    await fetchRequests()
  }

  // 위험한 건만 추려 보기 — 삭제 신청이나 전체 개방처럼 먼저 봐야 하는 것들
  const riskyRequests = pendingRequests.filter((r) => reqRisk(r) === 'risk')
  const shown = view === 'history' ? [] : view === 'risk' ? riskyRequests : pendingRequests

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
                <> · <span style={{ color: 'var(--fail)', fontWeight: 700 }}>먼저 볼 것 {riskyRequests.length}건</span>
                  <span className="ap-hint">삭제 신청이거나 전체 개방(0.0.0.0/0)입니다</span></>
              )}
            </div>
          </div>

          <div className="ap-chips">
            <button className={`ap-chip ${view === 'pending' ? 'on' : ''}`} onClick={() => setView('pending')}>
              대기 {pendingRequests.length}
            </button>
            <button className={`ap-chip ${view === 'risk' ? 'on' : ''}`} onClick={() => setView('risk')}>
              위험 {riskyRequests.length}
            </button>
            <button className={`ap-chip ${view === 'history' ? 'on' : ''}`} onClick={() => setView('history')}>
              이력
            </button>
          </div>

          <div className="ap-body">
            <ErrorBanner message={loadError} onRetry={fetchRequests} />
            {loading && <div className="ac-empty">불러오는 중...</div>}

            {!loading && view === 'history' && (
              historyRequests.length === 0
                ? <div className="ac-empty">이력이 없습니다.</div>
                : <HistoryList historyRequests={historyRequests} busyId={busyId} onRemove={removeRequest} />
            )}

            {!loading && view !== 'history' && shown.length === 0 && (
              <div className="ac-empty">
                {view === 'risk' ? '위험으로 분류된 신청이 없습니다.' : '대기중인 신청이 없습니다.'}
              </div>
            )}

            {!loading && view !== 'history' && shown.length > 0 && (
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
