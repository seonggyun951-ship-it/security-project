// 수집한 원본을 사람이 읽을 수 있는 형태로 바꾼다.
//
// 그동안 화면이 raw_data를 JSON 그대로 뿌리고 있었다. 그건 화면이 아니라 로그다 —
// 보는 사람이 중괄호를 헤치며 필요한 값을 직접 찾아야 한다.
//
// 리소스마다 실제로 볼 값은 정해져 있다. 그것만 뽑아 이름을 붙여 내보낸다.
// 원본은 버리지 않고 화면에서 접어 둔다. 수집이 잘못됐는지 따질 때는 원본이 필요하다.

// aws.jsx의 naclRuleLabel을 끌어다 쓰지 않는다. 그쪽은 신청서 payload 형식을 받고
// 여기는 AWS가 준 원본(Entries) 형식이라 필드가 다르다. 게다가 .jsx를 참조하면
// 이 파일을 Node에서 실행해 볼 수 없어 값이 맞는지 확인할 방법이 사라진다.

/** '2026-08-07T16:38:49.000Z' → '2026-08-07' */
const day = (v) => (typeof v === 'string' ? v.slice(0, 10) : '')

/** ARN에서 뒷부분만. 앞은 계정·리전이라 화면에서 되풀이할 값이 아니다. */
const tailOf = (arn) => String(arn || '').split('/').pop() || ''

/** 태그 배열에서 Name을 찾는다. AWS는 이름을 태그로 단다. */
const nameTag = (tags) =>
  (Array.isArray(tags) ? tags.find((t) => t?.Key === 'Name')?.Value : '') || ''

/**
 * 보안 그룹 규칙 한 줄.
 *   { FromPort: 22, ToPort: 22, IpProtocol: 'tcp', IpRanges: [{ CidrIp: '0.0.0.0/0' }] }
 *   → 'TCP 22 ← 0.0.0.0/0'
 *
 * 포트가 -1이거나 프로토콜이 -1이면 전체를 뜻한다. 그대로 '-1'을 보여주면
 * 무슨 뜻인지 알 수 없어 '전체'로 옮긴다.
 */
function sgRuleLabel(r, dir = 'in') {
  const proto = r.IpProtocol === '-1' ? '전체' : String(r.IpProtocol || '').toUpperCase()
  const port = r.IpProtocol === '-1' || r.FromPort == null
    ? '전체'
    : r.FromPort === r.ToPort ? String(r.FromPort) : `${r.FromPort}-${r.ToPort}`
  const targets = [
    ...(r.IpRanges || []).map((x) => x.CidrIp),
    ...(r.Ipv6Ranges || []).map((x) => x.CidrIpv6),
    ...(r.UserIdGroupPairs || []).map((x) => x.GroupId),
  ].filter(Boolean)
  const arrow = dir === 'in' ? '←' : '→'
  return `${proto} ${port} ${arrow} ${targets.join(', ') || '(대상 없음)'}`
}

/**
 * NACL 규칙 한 줄. AWS가 주는 Entries 항목을 그대로 받는다.
 *   { RuleNumber: 90, RuleAction: 'deny', Protocol: '6',
 *     PortRange: { From: 3389, To: 3389 }, CidrBlock: '0.0.0.0/0' }
 *   → '#90 거부 TCP 3389 ← 0.0.0.0/0'
 *
 * 번호를 맨 앞에 둔다. 낮은 번호부터 먼저 맞는 하나만 적용되므로 순서가 곧 의미다.
 * 프로토콜은 숫자로 온다(6=TCP, 17=UDP, 1=ICMP, -1=전체). 그대로 두면 못 읽는다.
 */
const PROTO = { '-1': '전체', 1: 'ICMP', 6: 'TCP', 17: 'UDP' }
function naclEntryLabel(e) {
  const proto = PROTO[String(e.Protocol)] || `프로토콜 ${e.Protocol}`
  const port = e.PortRange
    ? (e.PortRange.From === e.PortRange.To ? String(e.PortRange.From) : `${e.PortRange.From}-${e.PortRange.To}`)
    : '전체'
  const act = e.RuleAction === 'deny' ? '거부' : '허용'
  const arrow = e.Egress ? '→' : '←'
  // 32767은 AWS가 기본 NACL 마지막에 넣는 '나머지 전부' 규칙이다. 번호로 쓰면 헷갈린다.
  const no = e.RuleNumber === 32767 ? '기본' : `#${e.RuleNumber}`
  return `${no} ${act} ${proto} ${port} ${arrow} ${e.CidrBlock || e.Ipv6CidrBlock || ''}`
}

/**
 * 리소스 하나를 { fields, rules, warn } 로 정리한다.
 *   fields  이름표가 붙은 값들. 화면이 표로 그린다
 *   rules   규칙 목록(SG·NACL). 없으면 빈 배열
 *   warn    눈에 띄어야 할 것. 인터넷 전체 개방 등
 */
export function summarize(type, raw) {
  const d = raw || {}

  if (type === 'iam_user') {
    // 이름과 날짜만으로는 사용자끼리 구별이 안 된다. 실제로 궁금한 건
    // "이 사람이 무엇을 할 수 있는가"이므로 붙은 정책과 그룹을 앞에 세운다.
    const attached = d.AttachedPolicies || ''
    const inline = d.InlinePolicies || ''
    const groups = d.Groups || ''
    const warn = []
    // 관리자 권한은 이 계정에서 가장 위험한 상태다. 목록에서 바로 보여야 한다.
    if (/Administrator/i.test(attached)) warn.push('관리자 권한이 직접 붙어 있습니다')
    if (inline) warn.push(`이 사용자에게만 쓴 정책 ${inline.split(',').length}개`)
    return {
      fields: [
        ['사용자', d.UserName],
        ['붙은 정책', attached || '없음'],
        ['직접 쓴 정책', inline || '없음'],
        ['소속 그룹', groups || '없음'],
        ['만든 날', day(d.CreateDate)],
      ],
      rules: [],
      warn,
    }
  }

  if (type === 'iam_policy') {
    const attached = Number(d.AttachmentCount || 0)
    return {
      fields: [
        ['정책', d.PolicyName],
        ['붙어 있는 대상', attached === 0 ? '없음' : `${attached}곳`],
        ['만든 날', day(d.CreateDate)],
        ['마지막 수정', day(d.UpdateDate)],
      ],
      rules: [],
      // 아무 데도 안 붙은 정책은 지워도 되는 후보다.
      warn: attached === 0 ? ['어디에도 붙어 있지 않습니다'] : [],
    }
  }

  if (type === 'vpc') {
    return {
      fields: [
        ['이름', nameTag(d.Tags) || d.VpcId],
        ['대역', d.CidrBlock],
        ['상태', d.State === 'available' ? '사용 중' : d.State],
        ['기본 VPC', d.IsDefault ? '예' : '아니오'],
      ],
      rules: [],
      warn: d.IsDefault ? ['AWS가 만들어 둔 기본 VPC입니다'] : [],
    }
  }

  if (type === 'security_group') {
    const inb = (d.IpPermissions || []).map((r) => sgRuleLabel(r, 'in'))
    const out = (d.IpPermissionsEgress || []).map((r) => sgRuleLabel(r, 'out'))
    // 인터넷 전체에서 들어오는 규칙만 따로 센다. 이게 대부분의 지적 사항이다.
    const open = (d.IpPermissions || []).filter((r) =>
      (r.IpRanges || []).some((x) => x.CidrIp === '0.0.0.0/0'))
    return {
      fields: [
        ['이름', d.GroupName],
        ['ID', d.GroupId],
        ['VPC', d.VpcId],
        ['설명', d.Description],
      ],
      rules: [
        ...inb.map((t) => ({ dir: '인바운드', text: t })),
        ...out.map((t) => ({ dir: '아웃바운드', text: t })),
      ],
      warn: open.length ? [`인터넷 전체에서 들어오는 규칙 ${open.length}개`] : [],
    }
  }

  if (type === 'network_acl') {
    // Entries는 인바운드·아웃바운드가 Egress 값으로 섞여 있다. 번호 순으로 세운다 —
    // NACL은 번호가 낮은 규칙부터 먼저 맞는 하나만 적용되므로 순서가 곧 의미다.
    const entries = [...(d.Entries || [])].sort((a, b) => a.RuleNumber - b.RuleNumber)
    const rules = entries.map((e) => ({
      dir: e.Egress ? '아웃바운드' : '인바운드',
      text: naclEntryLabel(e),
    }))
    const subnets = (d.Associations || []).length
    return {
      fields: [
        ['이름', nameTag(d.Tags) || d.NetworkAclId],
        ['VPC', d.VpcId],
        ['붙은 서브넷', subnets === 0 ? '없음' : `${subnets}개`],
        ['기본 NACL', d.IsDefault ? '예' : '아니오'],
      ],
      rules,
      warn: [],
    }
  }

  if (type === 'waf_web_acl') {
    return {
      fields: [
        ['이름', d.Name],
        ['용량(WCU)', d.Capacity != null ? String(d.Capacity) : ''],
        ['설명', d.Description],
        ['ID', d.Id],
      ],
      rules: [],
      warn: [],
    }
  }

  // 모르는 종류. 값을 통째로 늘어놓되 객체·배열은 접어 둔다 —
  // 그것까지 펴면 다시 JSON 덩어리가 된다.
  return {
    fields: Object.entries(d)
      .filter(([, v]) => v == null || typeof v !== 'object')
      .map(([k, v]) => [k, String(v)]),
    rules: [],
    warn: [],
  }
}

/** 목록 한 줄에 곁들일 짧은 요약. 펼치지 않아도 무엇인지 알 수 있게. */
export function briefOf(type, raw) {
  const d = raw || {}
  if (type === 'iam_user') {
    // 목록에서 훑을 때 가장 먼저 알아야 할 것은 권한 수준이다.
    const a = d.AttachedPolicies || ''
    if (/Administrator/i.test(a)) return '관리자 권한'
    const n = [a, d.InlinePolicies || ''].filter(Boolean).join(',').split(',').filter(Boolean).length
    if (n > 0) return `정책 ${n}개`
    return d.EnvGroups ? `환경 권한 ${d.EnvGroups}` : '권한 없음'
  }
  if (type === 'iam_policy') {
    const n = Number(d.AttachmentCount || 0)
    return n === 0 ? '어디에도 안 붙음' : `${n}곳에 붙음`
  }
  if (type === 'vpc') return d.CidrBlock || ''
  if (type === 'security_group') {
    const n = (d.IpPermissions || []).length
    return n === 0 ? '인바운드 규칙 없음' : `인바운드 규칙 ${n}개`
  }
  if (type === 'network_acl') {
    const n = (d.Entries || []).length
    return `규칙 ${n}개 · 서브넷 ${(d.Associations || []).length}개`
  }
  if (type === 'waf_web_acl') return d.Capacity != null ? `용량 ${d.Capacity} WCU` : ''
  return ''
}

export { tailOf }
