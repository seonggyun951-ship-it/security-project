import { callFunction } from './db'

// 웹훅 URL은 프론트에 두지 않는다.
// 이 앱은 GitHub Pages(정적 사이트)로 배포되고 소스도 공개 저장소라,
// 번들에 URL을 넣으면 누구나 꺼내서 채널에 글을 쓸 수 있다.
// URL은 Supabase 시크릿(DISCORD_WEBHOOK)에만 두고 notify-discord 함수를 거친다.
//
// 알림 실패가 본 기능(신청/승인)을 막으면 안 되므로 throw하지 않는다.
// 다만 조용히 삼키면 "알림이 안 온다"는 제보를 받았을 때 원인을 알 수 없으므로 콘솔에는 반드시 남긴다.
export async function notify(message) {
  const res = await callFunction('notify-discord', { content: message })
  if (!res.ok) console.error('Discord 알림 실패:', res.error)
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
    const scope = p.scope === 'CLOUDFRONT' ? '글로벌' : '리전'
    return `${scope}, 기본: ${p.default_action === 'block' ? '차단' : '허용'}, 관리형 규칙 ${groups}개`
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
  if (action === 'create_readonly_user') {
    return `계정: ${p.user_name || ''}, 액세스 키: ${p.issue_key ? '발급 요청' : '요청 안 함'}`
  }
  // 삭제
  if (action === 'delete_iam_user') return `삭제 대상 계정: ${p.user_name || ''}`
  if (action === 'delete_sg_rules') {
    return `대상 SG: ${p.sg_name || p.sg_id || ''}, 규칙 ${(p.rules || []).length}개 제거`
  }
  if (action === 'delete_waf_rules') {
    return `대상 ACL: ${p.web_acl_name || ''}, 규칙 제거: ${(p.rule_names || []).join(', ')}`
  }
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
