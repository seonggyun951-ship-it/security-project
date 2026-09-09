import { useState, useEffect, useMemo } from 'react'

// 신청 화면의 '대상 고르기'.
//
// 계정 → VPC → SG 로 눌러 들어간다. 신청하는 사람이 아는 것에서 출발해
// 모르는 것으로 좁혀 가야 하기 때문이다.
//
// 다만 VPC를 모르는 사람도 많다. 자기가 쓰는 SG 이름만 아는 경우가 흔하다.
// VPC와 SG는 서로 이어져 있으므로 어느 쪽으로 들어가도 같은 곳에 닿는다.
// 그래서 두 번째 단계에서 무엇으로 찾을지 신청자가 고르게 한다.
//
//   계정 고르기
//     └ VPC로 찾기 → VPC 고름 → 그 안의 SG
//     └ SG로 찾기  → SG 바로 고름 (어느 VPC 것인지는 줄에 붙는다)
//
// 어느 단계든 한 번에 25개씩만 그린다. 목록을 통째로 쏟으면
// 리소스가 늘었을 때 고를 수가 없다.

const PAGE_SIZE = 25

/** 계정 번호 열두 자리를 네 자리씩 끊는다. 170420138507 → 1704 2013 8507 */
const fourDigits = (s) => String(s || '').replace(/(\d{4})(?=\d)/g, '$1 ')

/** 검색어가 걸린 자리를 표시한다. 어디가 걸렸는지 보여야 고를 수 있다. */
function Hit({ text, q }) {
  if (!q) return text
  const i = String(text).toLowerCase().indexOf(q.toLowerCase())
  if (i < 0) return text
  return (
    <>
      {text.slice(0, i)}
      <mark>{text.slice(i, i + q.length)}</mark>
      {text.slice(i + q.length)}
    </>
  )
}

/**
 * 줄에 붙일 한 줄 요약. 종류마다 '몇 개'의 뜻이 달라서 여기서 문구를 정한다.
 * 숫자는 aws_resource_options 뷰가 계산해서 보내준다 — 화면이 raw_data를
 * 통째로 받아 세면 목록 한 번에 수백 KB가 오간다.
 */
function metaOf(o) {
  const t = o.resource_type
  if (t === 'security_group') {
    return `인바운드 ${o.rule_count ?? 0}${o.sub_count != null ? ` · 아웃바운드 ${o.sub_count}` : ''}`
  }
  if (t === 'network_acl') {
    const sub = o.sub_count ?? 0
    return `규칙 ${o.rule_count ?? 0} · ${sub === 0 ? '미적용' : `서브넷 ${sub}`}`
  }
  if (t === 'waf_web_acl') return o.sub_count != null ? `${o.sub_count} WCU` : ''
  if (t === 'iam_user') {
    if (o.is_admin) return '관리자 권한'
    if (o.env_groups) return `환경 ${o.env_groups}`
    return o.rule_count ? `정책 ${o.rule_count}개` : '권한 없음'
  }
  return ''
}

export default function ResourcePicker({
  options = [],
  value,
  onChange,
  recentIds = [],
  vpcs = [],
  accountId = '',       // 계정 번호. 지금은 하나뿐이다
  accountName = '',
  label = '대상',
  emptyHint = '수집된 리소스가 없습니다. AWS 현황에서 수집을 먼저 돌려주세요.',
}) {
  // 어디까지 들어왔는지.
  //   null      계정 고르기
  //   'pick'    무엇으로 찾을지 고르기
  //   'vpcs'    VPC 목록
  //   'items'   대상 목록 (VPC를 골랐으면 그 안만)
  const [step, setStep] = useState(null)
  const [vpc, setVpc] = useState(null)
  const [q, setQ] = useState('')
  const [page, setPage] = useState(0)
  const [open, setOpen] = useState(false)

  const chosen = options.find((o) => o.resource_id === value) || null

  const vpcMap = useMemo(() => {
    const m = {}
    for (const v of vpcs) m[v.resource_id] = v
    return m
  }, [vpcs])
  const vpcOf = (id) => (id ? vpcMap[id] : null)
  const vpcLabel = (id) => {
    const v = vpcOf(id)
    if (!v) return id || ''
    return `${v.resource_name || v.resource_id}${v.cidr ? ` · ${v.cidr}` : ''}`
  }

  // 이 종류가 VPC에 속하는가. IAM 사용자처럼 아닌 것도 있다.
  const hasVpc = options.some((o) => o.vpc_id)
  // VPC 목록은 실제로 대상이 들어 있는 것만 낸다 — 빈 VPC를 골라 들어가면
  // 아무것도 없는 화면을 만나게 된다.
  const usedVpcs = useMemo(() => {
    const ids = [...new Set(options.map((o) => o.vpc_id).filter(Boolean))]
    return ids.map((id) => ({
      id,
      v: vpcOf(id),
      n: options.filter((o) => o.vpc_id === id).length,
    })).sort((a, b) => (a.v?.resource_name || a.id).localeCompare(b.v?.resource_name || b.id))
  }, [options, vpcMap])

  const needle = q.trim().toLowerCase()

  // 지금 단계에 뿌릴 줄들
  const rows = useMemo(() => {
    if (step === 'vpcs') {
      return usedVpcs.filter((x) => !needle
        || `${x.v?.resource_name || ''} ${x.id} ${x.v?.cidr || ''}`.toLowerCase().includes(needle))
    }
    if (step === 'items') {
      return options
        .filter((o) => !vpc || o.vpc_id === vpc)
        .filter((o) => !needle
          || `${o.resource_name || ''} ${o.resource_id} ${o.vpc_id || ''}`.toLowerCase().includes(needle))
    }
    return []
  }, [step, vpc, options, usedVpcs, needle])

  const recent = useMemo(
    () => (step === 'items' && !vpc && !needle
      ? options.filter((o) => recentIds.includes(o.resource_id))
      : []),
    [step, vpc, needle, options, recentIds])

  const body = rows.filter((r) => !recent.includes(r))
  const pageCount = Math.max(1, Math.ceil(body.length / PAGE_SIZE))
  const shown = body.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  useEffect(() => { setPage(0) }, [step, vpc, q])

  const start = () => {
    setOpen(true); setQ(''); setPage(0); setVpc(null)
    setStep(null)
  }
  const close = () => { setOpen(false); setQ(''); setPage(0); setStep(null); setVpc(null) }
  const pick = (o) => { onChange(o.resource_id, o); close() }

  // 한 단계 뒤로
  const back = () => {
    setQ(''); setPage(0)
    if (step === 'items' && vpc) { setVpc(null); setStep('vpcs'); return }
    if (step === 'items' || step === 'vpcs') { setStep('pick'); return }
    if (step === 'pick') { setStep(null); return }
  }

  const title = step === null ? '계정 고르기'
    : step === 'pick' ? '무엇으로 찾을까요'
      : step === 'vpcs' ? 'VPC 고르기'
        : `${label} 고르기`

  const crumb = step === null ? null
    : step === 'pick' ? (accountName || accountId || '계정')
      : step === 'vpcs' ? `${accountName || accountId || '계정'} · VPC로 찾기`
        : vpc ? vpcLabel(vpc) : `${accountName || accountId || '계정'} · ${label}로 찾기`

  return (
    <>
      <button type="button" className={`rp-field ${chosen ? 'has' : ''}`} onClick={start}>
        {chosen ? (
          <>
            <span className="rp-chosen-main">
              <span className="rp-chosen-nm">{chosen.resource_name || chosen.resource_id}</span>
              <span className="rp-chosen-id">
                {chosen.vpc_id && `${vpcLabel(chosen.vpc_id)} · `}
                {chosen.resource_id}
              </span>
            </span>
            <span className="rp-chosen-meta">{metaOf(chosen)}</span>
            <span className="rp-change">바꾸기</span>
          </>
        ) : (
          <>
            <span className="rp-ph">{label}을(를) 고르세요</span>
            <span className="rp-chosen-meta">{options.length}개</span>
            <span className="rp-change">고르기</span>
          </>
        )}
      </button>

      {open && (
        <div className="rp-backdrop" onClick={close}>
          <div className="rp-modal" onClick={(e) => e.stopPropagation()}>
            <div className="rp-head">
              <span className="rp-title">{title}</span>
              <button type="button" className="rp-x" onClick={close} aria-label="닫기">×</button>
            </div>

            {/* 어디까지 들어왔는지와 나갈 길 */}
            {crumb && (
              <div className="rp-crumb">
                <button type="button" className="rp-back" onClick={back}>‹ 뒤로</button>
                <span className="rp-crumb-t">{crumb}</span>
              </div>
            )}

            {/* 검색은 목록을 보는 단계에서만 */}
            {(step === 'vpcs' || step === 'items') && (
              <div className="rp-search">
                <input className="rp-in" value={q} autoFocus
                  placeholder={step === 'vpcs' ? 'VPC 이름 · 대역으로 검색' : `${label} 이름 · ID로 검색`}
                  onChange={(e) => setQ(e.target.value)} />
              </div>
            )}

            <div className="rp-list">
              {options.length === 0 && <div className="rp-none">{emptyHint}</div>}

              {/* 1단계 — 계정 */}
              {options.length > 0 && step === null && (
                <>
                  <div className="rp-grp">어느 계정인가요<span className="c">1개</span></div>
                  <button type="button" className="rp-row rp-bucket"
                    onClick={() => setStep(hasVpc ? 'pick' : 'items')}>
                    <span className="rp-r-main">
                      {/* 계정 번호 열두 자리는 붙여 두면 못 읽는다. 네 자리씩 끊는다. */}
                      <span className="nm">{accountName || (accountId ? fourDigits(accountId) : 'AWS 계정')}</span>
                      {accountName && accountId && (
                        <span className="sub"><span className="id">{fourDigits(accountId)}</span></span>
                      )}
                    </span>
                    <span className="rl">
                      {hasVpc && `VPC ${usedVpcs.length} · `}{label} {options.length}
                    </span>
                    <span className="rp-arrow">›</span>
                  </button>
                </>
              )}

              {/* 2단계 — 무엇으로 찾을지.
                  VPC와 대상은 서로 이어져 있어 어느 쪽으로 들어가도 같은 곳에 닿는다.
                  VPC를 모르고 자기가 쓰는 SG 이름만 아는 사람이 흔하다. */}
              {options.length > 0 && step === 'pick' && (
                <>
                  <div className="rp-grp">무엇으로 찾을까요<span className="c">둘 다 같은 곳에 닿습니다</span></div>
                  <button type="button" className="rp-row rp-bucket" onClick={() => setStep('vpcs')}>
                    <span className="rp-r-main">
                      <span className="nm">VPC로 찾기</span>
                      <span className="sub"><span className="place">VPC를 먼저 고르고 그 안에서 찾습니다</span></span>
                    </span>
                    <span className="rl">VPC {usedVpcs.length}개</span>
                    <span className="rp-arrow">›</span>
                  </button>
                  <button type="button" className="rp-row rp-bucket" onClick={() => setStep('items')}>
                    <span className="rp-r-main">
                      <span className="nm">{label}로 찾기</span>
                      <span className="sub"><span className="place">VPC를 몰라도 됩니다. 어느 VPC 것인지 함께 나옵니다</span></span>
                    </span>
                    <span className="rl">{label} {options.length}개</span>
                    <span className="rp-arrow">›</span>
                  </button>
                </>
              )}

              {/* 3단계 — VPC 목록 */}
              {step === 'vpcs' && (
                shown.length === 0
                  ? <div className="rp-none">{needle ? `"${q.trim()}"에 걸리는 VPC가 없습니다.` : 'VPC가 없습니다.'}</div>
                  : shown.map((x) => (
                    <button type="button" key={x.id} className="rp-row rp-bucket"
                      onClick={() => { setVpc(x.id); setStep('items'); setQ('') }}>
                      <span className="rp-r-main">
                        <span className="nm"><Hit text={x.v?.resource_name || x.id} q={q.trim()} /></span>
                        <span className="sub">
                          {x.v?.cidr && <span className="place">{x.v.cidr}</span>}
                          <span className="id">{x.id}</span>
                        </span>
                      </span>
                      <span className="rl">{label} {x.n}개</span>
                      <span className="rp-arrow">›</span>
                    </button>
                  ))
              )}

              {/* 4단계 — 대상 목록 */}
              {step === 'items' && (
                <>
                  {recent.length > 0 && (
                    <>
                      <div className="rp-grp">최근에 신청한 것<span className="c">{recent.length}개</span></div>
                      {recent.map((o) => (
                        <button type="button" key={o.resource_id}
                          className={`rp-row ${o.resource_id === value ? 'on' : ''}`}
                          onClick={() => pick(o)}>
                          <span className="rp-r-main">
                            <span className="nm">{o.resource_name || o.resource_id}</span>
                            <span className="sub">
                              {o.vpc_id && <span className="place">{vpcLabel(o.vpc_id)}</span>}
                              <span className="id">{o.resource_id}</span>
                            </span>
                          </span>
                          <span className="rl">{metaOf(o)}</span>
                        </button>
                      ))}
                      {shown.length > 0 && (
                        <div className="rp-grp">그 밖에<span className="c">{body.length}개</span></div>
                      )}
                    </>
                  )}

                  {shown.length === 0 && recent.length === 0 && (
                    <div className="rp-none">
                      {needle ? `"${q.trim()}"에 걸리는 게 없습니다.` : `${label}이(가) 없습니다.`}
                    </div>
                  )}

                  {shown.map((o) => (
                    <button type="button" key={o.resource_id}
                      className={`rp-row ${o.resource_id === value ? 'on' : ''}`}
                      onClick={() => pick(o)}>
                      <span className="rp-r-main">
                        <span className="nm"><Hit text={o.resource_name || o.resource_id} q={q.trim()} /></span>
                        <span className="sub">
                          {/* VPC 안에 들어와 있으면 위 빵부스러기에 이미 적혀 있다 */}
                          {o.vpc_id && !vpc && <span className="place">{vpcLabel(o.vpc_id)}</span>}
                          <span className="id">{o.resource_id}</span>
                        </span>
                      </span>
                      <span className="rl">{metaOf(o)}</span>
                    </button>
                  ))}
                </>
              )}
            </div>

            {/* 어느 단계든 25개씩. 통째로 쏟으면 리소스가 늘었을 때 고를 수 없다. */}
            {(step === 'vpcs' || step === 'items') && body.length > PAGE_SIZE && (
              <div className="rp-foot">
                <span>{body.length}개 중 {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, body.length)}개</span>
                <span className="pg">
                  <span>{page + 1} / {pageCount}</span>
                  <button type="button" className="pgb" disabled={page === 0}
                    onClick={() => setPage((p) => p - 1)}>‹</button>
                  <button type="button" className="pgb" disabled={page + 1 >= pageCount}
                    onClick={() => setPage((p) => p + 1)}>›</button>
                </span>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  )
}
