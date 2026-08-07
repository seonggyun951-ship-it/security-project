const WEBHOOK_URL = 'https://discordapp.com/api/webhooks/1535279854721966153/Qb6htpTyiTN1QcI0-QBlf2v92C9X7qKuYSSsuIYf8D6lZNq_Ez3r_78n39fD0eix-Dny'

export async function notify(message) {
  try {
    await fetch(WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: message }),
    })
  } catch (_) {
    // 알림 실패해도 본 기능에 영향 없도록
  }
}

/** 신청 payload에서 핵심 내용 한줄 요약 */
export function summarizePayload(action, payload) {
  const p = payload || {}
  // SG
  if (action === 'add_rules' || action === 'create_sg') {
    const rules = p.rules || []
    return rules.map((r) => {
      const dir = r.direction === 'ingress' ? '인바운드' : '아웃바운드'
      const proto = (r.protocol === '-1' ? '전체' : r.protocol || '').toUpperCase()
      const port = r.from_port != null ? (r.from_port === r.to_port ? `${r.from_port}` : `${r.from_port}-${r.to_port}`) : ''
      return `${dir} ${proto} ${port} ${r.cidr || ''}`
    }).join(', ')
  }
  // WAF
  if (action === 'create_acl') {
    const groups = (p.managed_rule_groups || []).length
    return `기본: ${p.default_action === 'block' ? '차단' : '허용'}, 관리형 규칙 ${groups}개`
  }
  if (action === 'add_waf_rules') {
    const rules = p.rules || []
    return rules.map((r) => {
      if (r.type === 'ip_block') return `IP차단: ${r.cidrs?.join(', ') || ''}`
      if (r.type === 'rate_limit') return `속도제한: ${r.limit}/5분`
      if (r.type === 'string_match') return `문자열: ${r.pattern || ''}`
      if (r.type === 'regex_match') return `정규식: ${r.pattern || ''}`
      return r.type
    }).join(', ')
  }
  // IAM
  if (action === 'create_readonly_user') return `계정: ${p.user_name || ''}`
  // VPC
  if (action === 'create_vpc') return `CIDR: ${p.cidr_block || ''}`
  // Subnet
  if (action === 'create_subnet') return `VPC: ${p.vpc_id || ''}, CIDR: ${p.cidr_block || ''}, AZ: ${p.availability_zone || ''}`
  // EC2
  if (action === 'create_ec2') return `타입: ${p.instance_type || ''}, 서브넷: ${p.subnet_id || ''}`
  // IGW
  if (action === 'create_igw') return `VPC: ${p.vpc_id || ''}`
  // Route Table
  if (action === 'create_route_table') return `VPC: ${p.vpc_id || ''}${p.routes?.length ? `, 라우트 ${p.routes.length}개` : ''}`
  // GCP Firewall
  if (action === 'create_firewall') {
    const rules = p.rules || []
    return rules.map((r) => {
      const dir = r.direction === 'ingress' ? 'IN' : 'OUT'
      return `${dir} ${(r.protocol || '').toUpperCase()} ${r.port || '*'} ${r.cidr || ''}`
    }).join(', ')
  }
  // GCP Cloud Armor
  if (action === 'create_armor_policy') return `기본: ${p.default_action === 'deny' ? '차단' : '허용'}`
  if (action === 'add_armor_rules') {
    return (p.rules || []).map((r) => `${r.type}: ${r.cidrs || r.expression || ''}`).join(', ')
  }
  // GCP IAM
  if (action === 'create_service_account') return `계정: ${p.account_id || ''}, 역할: ${p.role || ''}`
  return ''
}
