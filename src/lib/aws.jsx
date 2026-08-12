// AWS 자동화 신청/승인 공통 모듈 — 신청자 페이지와 승인자 페이지가 함께 사용

export const RESOURCE_META = {
  security_group:   { label: 'Security Group' },
  waf_web_acl:      { label: 'WAF Web ACL' },
  iam_role:         { label: 'IAM Role' },
  iam_policy:       { label: 'IAM Policy' },
  iam_user:         { label: 'IAM 읽기전용 계정' },
  vpc:              { label: 'VPC' },
  subnet:           { label: '서브넷' },
  ec2_instance:     { label: 'EC2 인스턴스' },
  internet_gateway: { label: 'Internet Gateway' },
  route_table:      { label: '라우팅 테이블' },
}

export const ACTION_LABEL = {
  create_sg:            '신규 SG 생성',
  add_rules:            'SG 규칙 추가',
  create_acl:           '신규 WAF 생성',
  add_waf_rules:        'WAF 규칙 추가',
  create_readonly_user: '읽기전용 계정 생성',
  create_vpc:           'VPC 생성',
  create_subnet:        '서브넷 생성',
  create_ec2:           'EC2 인스턴스 생성',
  create_igw:           'Internet Gateway 생성',
  create_route_table:   '라우팅 테이블 생성',
  delete_iam_user:      'IAM 계정 삭제',
  delete_sg_rules:      'SG 규칙 삭제',
  delete_waf_rules:     'WAF 규칙 삭제',
}

// 되돌릴 수 없어 최고 관리자 승인을 반드시 거치는 액션
export const DELETE_ACTIONS = ['delete_iam_user', 'delete_sg_rules', 'delete_waf_rules']
export const isDeleteAction = (a) => DELETE_ACTIONS.includes(a)

// 배포된 IAM 정책이 딱 이 두 관리형 정책으로만 AttachUserPolicy 하도록 제한되어 있음
export const IAM_READONLY_POLICIES = [
  { arn: 'arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess', label: 'S3 읽기 전용' },
  { arn: 'arn:aws:iam::aws:policy/ReadOnlyAccess', label: '전체 서비스 읽기 전용 (ReadOnlyAccess)' },
]

export const REQ_STATUS_META = {
  pending:        { label: '대기중', color: '#f59e0b' },
  awaiting_super: { label: '최고관리자 승인 대기', color: '#a855f7' },
  approved:       { label: '승인 처리중', color: '#38bdf8' },
  applied:  { label: '적용 완료', color: '#10b981' },
  rejected: { label: '거절됨', color: '#64748b' },
  failed:   { label: '적용 실패', color: '#ef4444' },
}

// WAF 신규 생성 시 선택 가능한 AWS 관리형 규칙 그룹
export const WAF_MANAGED_RULE_GROUPS = [
  { name: 'AWSManagedRulesCommonRuleSet',          label: '공통 규칙 (Common)' },
  { name: 'AWSManagedRulesKnownBadInputsRuleSet',  label: '알려진 악성 입력' },
  { name: 'AWSManagedRulesSQLiRuleSet',            label: 'SQL 인젝션' },
  { name: 'AWSManagedRulesAmazonIpReputationList', label: 'IP 평판 목록' },
  { name: 'AWSManagedRulesLinuxRuleSet',           label: 'Linux OS' },
]

// ---- SG 규칙 헬퍼 ----
export const emptyRule = () => ({ direction: 'ingress', protocol: 'tcp', port: '', cidr: '' })

// "22" -> {from:22,to:22} / "1000-2000" -> {from:1000,to:2000} / "" -> {from:null,to:null}(전체)
export function parsePortRange(str) {
  const s = (str || '').trim()
  if (!s) return { from_port: null, to_port: null }
  const [a, b] = s.split('-').map((v) => v.trim())
  const from = Number(a)
  const to = b ? Number(b) : from
  return { from_port: from, to_port: to }
}

// CIDR에 마스크(/)가 없으면 단일 IP로 보고 /32를 붙임. 이미 있으면 그대로.
export function normalizeCidr(str) {
  const s = (str || '').trim()
  if (!s || s.includes('/')) return s
  return `${s}/32`
}

export function sgRuleLabel(r) {
  const port = r.from_port ? `${r.from_port}${r.to_port && r.to_port != r.from_port ? '-' + r.to_port : ''}` : '전체'
  const dir = r.direction === 'ingress' ? '인바운드' : '아웃바운드'
  return `${dir} ${r.protocol}:${port} ↔ ${r.cidr}`
}

// ---- WAF 규칙 헬퍼 ----
// 패턴 매칭 검사 대상
export const WAF_FIELDS = [
  { key: 'uri_path', label: 'URI 경로' },
  { key: 'query_string', label: '쿼리스트링' },
  { key: 'header', label: '헤더' },
  { key: 'body', label: '본문' },
]
// 문자열 매칭 위치 조건
export const WAF_POSITIONS = [
  { key: 'CONTAINS', label: '포함' },
  { key: 'STARTS_WITH', label: '시작' },
  { key: 'ENDS_WITH', label: '끝' },
  { key: 'EXACTLY', label: '정확히 일치' },
]
const wafFieldLabel = (k) => WAF_FIELDS.find((f) => f.key === k)?.label || k
const wafPosLabel = (k) => WAF_POSITIONS.find((p) => p.key === k)?.label || k

export const emptyWafRule = () => ({
  type: 'ip_block', name: '', cidrs: '', limit: '2000',
  field: 'uri_path', position: 'CONTAINS', header_name: '', pattern: '',
})

export function wafRuleLabel(r) {
  const target = `${wafFieldLabel(r.field)}${r.field === 'header' && r.header_name ? `(${r.header_name})` : ''}`
  if (r.type === 'rate_limit') return `속도제한 ${r.name}: ${r.limit}건/5분 초과 차단`
  if (r.type === 'string_match') return `문자열차단 ${r.name}: ${target} ${wafPosLabel(r.position)} "${r.pattern}"`
  if (r.type === 'regex_match') return `정규식차단 ${r.name}: ${target} =~ /${r.pattern}/`
  return `IP차단 ${r.name}: ${(r.cidrs || []).join(', ')}`
}

// ---- 신청 표시 헬퍼 ----
export function reqTitle(r) {
  const action = ACTION_LABEL[r.action] || r.action
  const name = r.title || r.target_id || ''
  const created = r.result?.created_id || r.result?.web_acl_id
  return `${action}: ${name}${created ? ` (${created})` : ''}`
}

export function reqDetailLines(r) {
  const p = r.payload || {}
  if (r.action === 'create_sg' || r.action === 'add_rules') {
    return (p.rules || []).map(sgRuleLabel)
  }
  if (r.action === 'create_acl') {
    const names = (p.managed_rule_groups || []).map((n) => {
      const g = WAF_MANAGED_RULE_GROUPS.find((x) => x.name === n)
      return g ? g.label : n
    })
    return [
      `적용 범위: ${p.scope === 'CLOUDFRONT' ? '글로벌 (CloudFront)' : '리전'}`,
      `관리형 규칙: ${names.join(', ') || '없음'}`,
      `기본 액션: ${p.default_action === 'block' ? '차단' : '허용'}`,
    ]
  }
  if (r.action === 'add_waf_rules') {
    return (p.rules || []).map(wafRuleLabel)
  }
  if (r.action === 'create_readonly_user') {
    const policy = IAM_READONLY_POLICIES.find((x) => x.arn === p.policy_arn)
    return [
      `계정: ${p.user_name}`,
      `권한: ${policy ? policy.label : p.policy_arn}`,
      `액세스 키: ${p.issue_key ? '발급 요청함' : '요청 안 함 (콘솔 로그인만)'}`,
    ]
  }
  if (r.action === 'create_vpc') {
    return [`CIDR: ${p.cidr_block || '10.0.0.0/16'}`, `DNS 호스트네임: ${p.dns_hostnames !== false ? 'ON' : 'OFF'}`]
  }
  if (r.action === 'create_subnet') {
    return [`VPC: ${p.vpc_id}`, `CIDR: ${p.cidr_block}`, `AZ: ${p.availability_zone}`, `퍼블릭 IP: ${p.public_ip ? 'ON' : 'OFF'}`]
  }
  if (r.action === 'create_ec2') {
    return [`타입: ${p.instance_type || 't3.micro'}`, `서브넷: ${p.subnet_id}`, `SG: ${(p.security_group_ids || []).join(', ')}`]
  }
  if (r.action === 'create_igw') {
    return [`VPC: ${p.vpc_id}`]
  }
  if (r.action === 'delete_iam_user') {
    return [`삭제 대상 계정: ${p.user_name}`, '연결된 액세스 키와 정책도 함께 제거됩니다']
  }
  if (r.action === 'delete_sg_rules') {
    return [`대상 SG: ${p.sg_name || p.sg_id}`, ...(p.rules || []).map(sgRuleLabel)]
  }
  if (r.action === 'delete_waf_rules') {
    return [
      `대상 Web ACL: ${p.web_acl_name}`,
      `적용 범위: ${p.scope === 'CLOUDFRONT' ? '글로벌 (CloudFront)' : '리전'}`,
      `삭제할 규칙: ${(p.rule_names || []).join(', ')}`,
    ]
  }
  if (r.action === 'create_route_table') {
    const routes = (p.routes || []).map((rt) => `${rt.cidr_block} → ${rt.gateway_id}`)
    return [`VPC: ${p.vpc_id}`, ...routes, `연결 서브넷: ${(p.subnet_ids || []).join(', ')}`]
  }
  return []
}

// 승인 전에 관리자가 알아야 할 점. 신청을 막지는 않고 판단 재료만 제공한다.
export function reqWarnings(r) {
  const p = r.payload || {}
  const out = []

  if (isDeleteAction(r.action)) {
    out.push('삭제 신청입니다. 되돌릴 수 없으며 최고 관리자 승인이 필요합니다.')
    if (r.action === 'delete_waf_rules') {
      out.push('차단 규칙을 제거하는 작업이라 보안이 느슨해집니다.')
    }
  }

  if (r.action === 'create_acl' && p.default_action !== 'block') {
    const n = (p.managed_rule_groups || []).length
    out.push(
      n === 0
        ? '기본 허용 + 규칙 없음 — 아무 요청도 차단하지 않는 Web ACL입니다.'
        : `기본 허용 규칙입니다 — 선택한 관리형 규칙 ${n}개에 걸리는 요청만 차단됩니다.`
    )
  }
  return out
}

// 신청 1건 카드 — 승인자는 onApprove/onReject/onRemove 전달, 신청자는 미전달(상태만 표시)
// isSuper: 최고 관리자 여부. 삭제 신청은 최고 관리자만 최종 실행할 수 있다.
export function ReqCard({ r, busyId, onApprove, onReject, onRemove, isSuper = false }) {
  const meta = REQ_STATUS_META[r.status] || { label: r.status, color: '#94a3b8' }
  const detail = reqDetailLines(r)
  const warnings = reqWarnings(r)
  const busy = busyId === r.id
  const isDelete = isDeleteAction(r.action)
  // 삭제는 pending(신청 직후)과 awaiting_super(1차 승인됨) 두 상태에서 처리 대상이다.
  const actionable = r.status === 'pending' || (isDelete && r.status === 'awaiting_super')
  return (
    <div className="ac-req">
      <div className="ac-req-top">
        <span className="ac-req-status" style={{ background: meta.color }}>{meta.label}</span>
        <span className="ac-req-title">{reqTitle(r)}</span>
      </div>
      {detail.map((line, i) => <div key={i} className="ac-req-reason">{line}</div>)}
      {warnings.map((w, i) => <div key={i} className="ac-req-warn">⚠️ {w}</div>)}
      {r.reason && <div className="ac-req-reason">사유: {r.reason}</div>}
      {r.payload?.expires_at && <div className="ac-req-meta">만료: {new Date(r.payload.expires_at).toLocaleDateString('ko-KR')}</div>}
      {r.requester_email && <div className="ac-req-meta">신청자: {r.requester_email}</div>}
      {r.first_approver_email && (
        <div className="ac-req-meta">
          1차 승인: {r.first_approver_email}
          {r.first_approved_at && ` (${new Date(r.first_approved_at).toLocaleString('ko-KR')})`}
        </div>
      )}
      {r.error_message && <div className="ac-req-error">{r.error_message}</div>}
      <div className="ac-req-meta">{new Date(r.requested_at).toLocaleString('ko-KR')}</div>

      {/* 삭제 신청 — 최고 관리자만 최종 실행. 일반 관리자는 1차 승인까지만 가능하다. */}
      {actionable && onApprove && isDelete && (
        <div className="ac-req-actions">
          {isSuper ? (
            <button className="ac-btn ac-btn-danger" disabled={busy} onClick={() => onApprove(r.id)}>
              {busy ? '처리 중...' : r.status === 'awaiting_super' ? '최종 승인 후 삭제' : '승인 후 삭제 (최고관리자)'}
            </button>
          ) : r.status === 'awaiting_super' ? (
            <span className="ac-req-meta">최고 관리자 승인을 기다리는 중입니다.</span>
          ) : (
            <button className="ac-btn" disabled={busy} onClick={() => onApprove(r.id)}>
              {busy ? '처리 중...' : '1차 승인 (실제 삭제는 최고관리자가)'}
            </button>
          )}
          <button className="ac-btn ac-btn-secondary" disabled={busy} onClick={() => onReject(r.id)}>거절</button>
        </div>
      )}

      {/* 키 발급은 신청자가 요청한 대로를 기본(강조) 버튼으로 두되, 최종 결정은 승인자가 한다. */}
      {r.status === 'pending' && !isDelete && onApprove && r.resource_type === 'iam_user' && (
        <div className="ac-req-actions">
          {r.payload?.issue_key ? (
            <>
              <button className="ac-btn" disabled={busy} onClick={() => onApprove(r.id, { issueKey: true })}>
                {busy ? '처리 중...' : '승인 (키 발급) — 신청대로'}
              </button>
              <button className="ac-btn ac-btn-secondary" disabled={busy} onClick={() => onApprove(r.id, { issueKey: false })}>
                키 없이 승인
              </button>
            </>
          ) : (
            <>
              <button className="ac-btn" disabled={busy} onClick={() => onApprove(r.id, { issueKey: false })}>
                {busy ? '처리 중...' : '승인 (키 없이) — 신청대로'}
              </button>
              <button className="ac-btn ac-btn-secondary" disabled={busy} onClick={() => onApprove(r.id, { issueKey: true })}>
                키까지 발급해서 승인
              </button>
            </>
          )}
          <button className="ac-btn ac-btn-secondary" disabled={busy} onClick={() => onReject(r.id)}>거절</button>
        </div>
      )}
      {r.status === 'pending' && !isDelete && onApprove && r.resource_type !== 'iam_user' && (
        <div className="ac-req-actions">
          <button className="ac-btn" disabled={busy} onClick={() => onApprove(r.id)}>{busy ? '처리 중...' : '승인'}</button>
          <button className="ac-btn ac-btn-secondary" disabled={busy} onClick={() => onReject(r.id)}>거절</button>
        </div>
      )}
      {(r.status === 'failed' || r.status === 'rejected') && onRemove && (
        <div className="ac-req-actions">
          <button className="ac-btn ac-btn-secondary" disabled={busy} onClick={() => onRemove(r.id)}>{busy ? '삭제 중...' : '목록에서 삭제'}</button>
        </div>
      )}
    </div>
  )
}
