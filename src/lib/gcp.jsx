// GCP 자동화 신청/승인 공통 모듈

export const GCP_RESOURCE_META = {
  firewall_rule: { label: 'Firewall Rule' },
  cloud_armor: { label: 'Cloud Armor Policy' },
  service_account: { label: 'IAM 서비스 계정' },
}

export const GCP_ACTION_LABEL = {
  create_firewall: '방화벽 규칙 생성',
  create_armor_policy: 'Cloud Armor 정책 생성',
  add_armor_rules: 'Cloud Armor 규칙 추가',
  create_service_account: '서비스 계정 생성',
}

export const GCP_REQ_STATUS_META = {
  // 색은 index.css의 토큰을 그대로 쓴다 (AWS 쪽과 동일 기준).
  pending:        { label: '대기중', color: 'var(--wait)' },
  awaiting_super: { label: '최고관리자 승인 대기', color: 'var(--super)' },
  approved:       { label: '승인 처리중', color: 'var(--accent-2)' },
  applied:        { label: '적용 완료', color: 'var(--done)' },
  rejected:       { label: '거절됨', color: 'var(--off)' },
  failed:         { label: '적용 실패', color: 'var(--fail)' },
  cancelled:      { label: '신청 취소', color: 'var(--ink-3)' },
}

export const GCP_PROTOCOLS = [
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
  { value: 'icmp', label: 'ICMP' },
  { value: 'all', label: '전체' },
]

export const GCP_ARMOR_RULE_TYPES = [
  { value: 'ip_deny', label: 'IP 차단' },
  { value: 'ip_allow', label: 'IP 허용' },
  { value: 'rate_limit', label: '요청 속도 제한' },
  { value: 'expression', label: 'CEL 표현식' },
]

export const GCP_IAM_ROLES = [
  { value: 'roles/viewer', label: 'Viewer (전체 읽기 전용)' },
  { value: 'roles/storage.objectViewer', label: 'Storage Object Viewer' },
  { value: 'roles/bigquery.dataViewer', label: 'BigQuery Data Viewer' },
  { value: 'roles/logging.viewer', label: 'Logging Viewer' },
]

export function emptyFirewallRule() {
  return { direction: 'ingress', protocol: 'tcp', port: '', cidr: '', priority: '1000' }
}

export function emptyArmorRule() {
  return { type: 'ip_deny', expression: '', cidrs: '', priority: '1000', rate_limit: '500' }
}

export function gcpReqTitle(r) {
  const action = GCP_ACTION_LABEL[r.action] || r.action
  const name = r.title || r.target_id || ''
  return `${action}: ${name}`
}

export function gcpReqDetailLines(r) {
  const p = r.payload || {}
  if (r.action === 'create_firewall') {
    return (p.rules || []).map((rule) => {
      const dir = rule.direction === 'ingress' ? 'IN' : 'OUT'
      return `${dir} ${rule.protocol} ${rule.port || '*'} ${rule.cidr}`
    })
  }
  if (r.action === 'create_armor_policy') {
    return [`기본 액션: ${p.default_action === 'deny' ? '차단' : '허용'}`]
  }
  if (r.action === 'add_armor_rules') {
    return (p.rules || []).map((rule) => {
      if (rule.type === 'ip_deny') return `IP 차단: ${rule.cidrs}`
      if (rule.type === 'ip_allow') return `IP 허용: ${rule.cidrs}`
      if (rule.type === 'rate_limit') return `속도 제한: ${rule.rate_limit}/min`
      return `CEL: ${rule.expression}`
    })
  }
  if (r.action === 'create_service_account') {
    const role = GCP_IAM_ROLES.find((x) => x.value === p.role)
    return [`계정: ${p.account_id}`, `역할: ${role ? role.label : p.role}`]
  }
  return []
}

export function GcpReqCard({ r }) {
  const meta = GCP_REQ_STATUS_META[r.status] || { label: r.status, color: 'var(--ink-3)' }
  const detail = gcpReqDetailLines(r)
  return (
    <div className="ac-req">
      <div className="ac-req-top">
        <span className="ac-req-status" style={{ background: meta.color }}>{meta.label}</span>
        <span className="ac-req-title">{gcpReqTitle(r)}</span>
      </div>
      {detail.map((line, i) => <div key={i} className="ac-req-reason">{line}</div>)}
      {r.reason && <div className="ac-req-reason">사유: {r.reason}</div>}
      {r.payload?.expires_at && <div className="ac-req-meta">만료: {new Date(r.payload.expires_at).toLocaleDateString('ko-KR')}</div>}
      {r.requester_email && <div className="ac-req-meta">신청자: {r.requester_email}</div>}
      {r.error_message && <div className="ac-req-error">{r.error_message}</div>}
      <div className="ac-req-meta">{new Date(r.requested_at).toLocaleString('ko-KR')}</div>
    </div>
  )
}
