import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import {
  EC2Client,
  AuthorizeSecurityGroupIngressCommand,
  AuthorizeSecurityGroupEgressCommand,
  RevokeSecurityGroupIngressCommand,
  RevokeSecurityGroupEgressCommand,
  CreateSecurityGroupCommand,
  CreateTagsCommand,
  CreateNetworkAclEntryCommand,
  DeleteNetworkAclEntryCommand,
} from 'npm:@aws-sdk/client-ec2@3'
import {
  WAFV2Client,
  CreateWebACLCommand,
  GetWebACLCommand,
  UpdateWebACLCommand,
  CreateIPSetCommand,
} from 'npm:@aws-sdk/client-wafv2@3'
import {
  IAMClient,
  CreateUserCommand,
  AttachUserPolicyCommand,
  CreateAccessKeyCommand,
  DeleteUserCommand,
  ListAccessKeysCommand,
  DeleteAccessKeyCommand,
  ListAttachedUserPoliciesCommand,
  DetachUserPolicyCommand,
  AddUserToGroupCommand,
  RemoveUserFromGroupCommand,
  ListGroupsForUserCommand,
  GetUserCommand,
} from 'npm:@aws-sdk/client-iam@3'

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type'
}

const json = (body, status = 200) => new Response(JSON.stringify(body), {
  headers: { ...cors, 'Content-Type': 'application/json' }, status
})

// WAF 이름/메트릭은 [a-zA-Z0-9-_] 만 허용
const safeName = (s) => (s || '').replace(/[^A-Za-z0-9_-]/g, '') || 'rule'

// ---- SG 가드레일 (최종 방어선) ----
//
// 같은 규칙을 신청 화면(src/lib/rules.js)이 접수 시점에 먼저 검사한다.
// 여기 있는 것은 그걸 우회해 직접 DB에 넣었을 때를 대비한 마지막 방어선이므로,
// 두 곳의 판정이 어긋나면 안 된다. 신청 화면이 '위험'으로 막는 것과 같은 항목만 둔다.
//
// 민감 포트(22 등)는 여기서 막지 않는다. 신청 화면이 '주의'로 표시해 관리자에게
// 넘기고, 관리자가 승인 버튼을 누른 것이 곧 수동 승인이다. 여기서 또 막으면
// 관리자가 승인한 신청이 적용 단계에서 실패한다.
const MAX_RULES_PER_SG = 50
const MIN_CIDR_PREFIX = 24 // /24 이상만 허용 (/0~/23 차단)
const WEB_PORTS = [80, 443] // 외부 공개 서비스의 정상 포트 — 전체 개방을 허용한다

function validateSgRules(rules) {
  const errors = []
  for (const r of (rules || [])) {
    // 아웃바운드 전체 허용은 AWS 기본값이라 막지 않는다. 들어오는 쪽만 본다.
    if (r.direction !== 'ingress') continue

    // 웹 포트 하나만 여는 것은 통과. 신청 화면이 '주의'로 표시해 관리자가 이미 보고 승인한다.
    const onlyWebPort = r.from_port != null
      && r.from_port === (r.to_port ?? r.from_port)
      && WEB_PORTS.includes(r.from_port)

    if ((r.cidr === '0.0.0.0/0' || r.cidr === '::/0') && !onlyWebPort) {
      errors.push(`전체 개방(${r.cidr})은 허용되지 않습니다`)
      continue
    }
    if (onlyWebPort) continue
    const prefix = parseInt((r.cidr || '').split('/')[1])
    if (!isNaN(prefix) && prefix < MIN_CIDR_PREFIX) {
      errors.push(`CIDR ${r.cidr}: /${MIN_CIDR_PREFIX} 이상만 허용됩니다 (현재 /${prefix})`)
    }
  }
  if ((rules || []).length > MAX_RULES_PER_SG) {
    errors.push(`규칙 수가 ${MAX_RULES_PER_SG}개를 초과합니다`)
  }
  return errors
}

// ---- 네트워크 ACL 가드레일 ----
//
// SG와 판정이 다른 부분만 둔다 (같은 규칙은 src/lib/rules.js의 checkNaclRules와 짝을 이룬다):
//   · deny 규칙은 막는 쪽이라 검사하지 않는다. 넓을수록 좋다.
//   · 임시 포트(1024-65535) 허용은 스테이트리스 NACL에 반드시 필요해 막지 않는다.
//     대신 그 범위에 딸려 들어오는 3389는 신청 화면이 '주의'로 관리자에게 넘긴다.
function validateNaclRules(rules) {
  const errors = []
  for (const r of (rules || [])) {
    if (r.action === 'deny') continue
    if (r.direction !== 'ingress') continue

    const from = r.from_port ?? 0
    const to = r.to_port ?? from
    const isPublic = r.cidr === '0.0.0.0/0' || r.cidr === '::/0'
    const allPorts = r.protocol === '-1' || (from <= 0 && to >= 65535)

    if (isPublic && allPorts) {
      errors.push(`#${r.rule_no}: 모든 포트를 인터넷에 허용할 수 없습니다`)
      continue
    }
    if (isPublic) continue // 포트가 지정된 전체 개방은 신청 화면 판정에 맡긴다

    const prefix = parseInt((r.cidr || '').split('/')[1])
    if (!isNaN(prefix) && prefix < MIN_CIDR_PREFIX) {
      errors.push(`#${r.rule_no}: CIDR ${r.cidr}은 /${MIN_CIDR_PREFIX} 이상만 허용됩니다`)
    }
  }
  if ((rules || []).length > MAX_RULES_PER_SG) {
    errors.push(`규칙 수가 ${MAX_RULES_PER_SG}개를 초과합니다`)
  }
  return errors
}

// AWS는 프로토콜을 번호로 받는다. '-1'은 전체.
const NACL_PROTO_NUM = { tcp: '6', udp: '17', icmp: '1', '-1': '-1' }

const toNaclEntry = (naclId, r) => ({
  NetworkAclId: naclId,
  RuleNumber: Number(r.rule_no),
  Egress: r.direction === 'egress',
  RuleAction: r.action === 'deny' ? 'deny' : 'allow',
  Protocol: NACL_PROTO_NUM[r.protocol] ?? String(r.protocol),
  CidrBlock: r.cidr,
  // 프로토콜이 전체(-1)면 포트 개념이 없다. PortRange를 함께 보내면 AWS가 거부한다.
  PortRange: r.protocol === '-1' || r.from_port == null
    ? undefined
    : { From: Number(r.from_port), To: Number(r.to_port ?? r.from_port) },
})

async function handleNaclRules(ec2, req) {
  const p = req.payload || {}
  const naclId = p.nacl_id
  if (!naclId) throw new Error('nacl_id가 없습니다')

  const errors = validateNaclRules(p.rules)
  if (errors.length > 0) throw new Error('가드레일 위반: ' + errors.join('; '))

  const rules = p.rules || []
  if (rules.length === 0) throw new Error('추가할 규칙이 없습니다')

  const added = []
  for (const r of rules) {
    try {
      await ec2.send(new CreateNetworkAclEntryCommand(toNaclEntry(naclId, r)))
      added.push(r.rule_no)
    } catch (e) {
      // 같은 번호가 이미 있으면 AWS가 거부한다. 무엇을 고쳐야 하는지 알려준다 —
      // 규칙 번호는 방향별로 하나씩이라 덮어쓰려면 Replace를 써야 하는데,
      // 있는 규칙을 말없이 바꾸면 승인한 내용과 실제가 달라진다.
      if (String(e).includes('NetworkAclEntryAlreadyExists')) {
        throw new Error(`#${r.rule_no}(${r.direction}) 번호가 이미 사용 중입니다. 다른 번호로 신청하거나 기존 규칙을 먼저 삭제하세요.`)
      }
      throw e
    }
  }
  return { nacl_id: naclId, added_rule_numbers: added }
}

async function handleDeleteNaclRules(ec2, req) {
  const p = req.payload || {}
  const naclId = p.nacl_id
  if (!naclId) throw new Error('nacl_id가 없습니다')
  const rules = p.rules || []
  if (rules.length === 0) throw new Error('삭제할 규칙이 없습니다')

  // 기본 NACL의 마지막 거부 규칙(32767)은 지울 수 없고, 지워서도 안 된다.
  for (const r of rules) {
    if (Number(r.rule_no) === 32767) throw new Error('32767번은 AWS가 관리하는 기본 거부 규칙이라 삭제할 수 없습니다')
  }

  const deleted = []
  const missing = []
  for (const r of rules) {
    try {
      await ec2.send(new DeleteNetworkAclEntryCommand({
        NetworkAclId: naclId,
        RuleNumber: Number(r.rule_no),
        Egress: r.direction === 'egress',
      }))
      deleted.push(r.rule_no)
    } catch (e) {
      // 이미 없는 규칙이면 목적(그 규칙이 없는 상태)은 달성돼 있다. 실패로 보지 않는다.
      if (String(e).includes('InvalidNetworkAclEntry.NotFound')) { missing.push(r.rule_no); continue }
      throw e
    }
  }
  return { nacl_id: naclId, deleted_rule_numbers: deleted, already_absent: missing }
}

// ---- Security Group ----
const toPermission = (rule) => ({
  IpProtocol: rule.protocol,
  FromPort: rule.from_port ?? undefined,
  ToPort: rule.to_port ?? undefined,
  IpRanges: [{ CidrIp: rule.cidr, Description: rule.description || undefined }],
})

async function applySgRules(ec2, sgId, rules) {
  const ingress = (rules || []).filter((r) => r.direction === 'ingress')
  const egress = (rules || []).filter((r) => r.direction === 'egress')
  if (ingress.length > 0) {
    await ec2.send(new AuthorizeSecurityGroupIngressCommand({ GroupId: sgId, IpPermissions: ingress.map(toPermission) }))
  }
  if (egress.length > 0) {
    await ec2.send(new AuthorizeSecurityGroupEgressCommand({ GroupId: sgId, IpPermissions: egress.map(toPermission) }))
  }
}

async function handleSg(ec2, req) {
  const p = req.payload || {}
  const sgErrors = validateSgRules(p.rules)
  if (sgErrors.length > 0) throw new Error('가드레일 위반: ' + sgErrors.join('; '))

  if (req.action === 'create_sg') {
    const { GroupId } = await ec2.send(new CreateSecurityGroupCommand({
      GroupName: p.sg_name,
      Description: p.description || p.sg_name,
      VpcId: p.vpc_id,
    }))
    await ec2.send(new CreateTagsCommand({ Resources: [GroupId], Tags: [{ Key: 'Name', Value: p.sg_name }] }))
    if (p.rules?.length) await applySgRules(ec2, GroupId, p.rules)
    return { created_id: GroupId }
  }
  // add_rules
  await applySgRules(ec2, req.target_id, p.rules)
  return {}
}

// ---- WAF ----
const vis = (metric) => ({ SampledRequestsEnabled: true, CloudWatchMetricsEnabled: true, MetricName: safeName(metric) })

// 패턴 매칭 검사 대상 -> WAF FieldToMatch
function wafFieldToMatch(r) {
  switch (r.field) {
    case 'query_string': return { QueryString: {} }
    case 'header': return { SingleHeader: { Name: (r.header_name || '').toLowerCase() } }
    case 'body': return { Body: { OversizeHandling: 'CONTINUE' } }
    case 'uri_path':
    default: return { UriPath: {} }
  }
}

// WAF 일시적 오류 재시도 (WAFUnavailableEntityException 등)
async function wafRetry(fn, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      return await fn()
    } catch (e) {
      const msg = String(e)
      if (i < retries - 1 && (msg.includes('WAFUnavailableEntity') || msg.includes('Retry your request'))) {
        await new Promise((r) => setTimeout(r, 1000 * (i + 1)))
        continue
      }
      throw e
    }
  }
}

// WAFv2 스코프
//   REGIONAL   : ALB, API Gateway, AppSync 등. 리소스가 있는 리전에서 호출한다.
//   CLOUDFRONT : CloudFront 배포용. 리소스 위치와 무관하게 반드시 us-east-1에서 호출해야 한다.
// 스코프에 맞지 않는 리전으로 호출하면 만들어지지 않으므로 클라이언트를 따로 만든다.
const CLOUDFRONT_REGION = 'us-east-1'
const wafScopeOf = (p) => (p?.scope === 'CLOUDFRONT' ? 'CLOUDFRONT' : 'REGIONAL')
const wafRegionFor = (scope, defaultRegion) => (scope === 'CLOUDFRONT' ? CLOUDFRONT_REGION : defaultRegion)

async function handleWaf(req, credentials, defaultRegion) {
  const p = req.payload || {}
  const Scope = wafScopeOf(p)
  const waf = new WAFV2Client({ region: wafRegionFor(Scope, defaultRegion), credentials })

  if (req.action === 'create_acl') {
    const rules = (p.managed_rule_groups || []).map((name, i) => ({
      Name: name,
      Priority: i,
      OverrideAction: { None: {} },
      Statement: { ManagedRuleGroupStatement: { VendorName: 'AWS', Name: name } },
      VisibilityConfig: vis(name),
    }))
    const res = await wafRetry(() => waf.send(new CreateWebACLCommand({
      Name: p.acl_name,
      Scope,
      DefaultAction: p.default_action === 'block' ? { Block: {} } : { Allow: {} },
      Rules: rules,
      VisibilityConfig: vis(p.acl_name || 'webacl'),
    })))
    return { web_acl_id: res.Summary?.Id }
  }

  // add_waf_rules — 기존 Web ACL을 읽어 규칙을 합쳐 업데이트
  const aclName = p.web_acl_name || req.title
  const get = await wafRetry(() => waf.send(new GetWebACLCommand({ Name: aclName, Id: req.target_id, Scope })))
  const acl = get.WebACL
  const existing = acl.Rules || []
  let priority = existing.reduce((max, r) => Math.max(max, r.Priority ?? 0), -1)

  const newRules = []
  for (const r of (p.rules || [])) {
    priority += 1
    if (r.type === 'ip_block') {
      const ipset = await wafRetry(() => waf.send(new CreateIPSetCommand({
        Name: safeName(`${r.name}-ipset-${Date.now()}`).slice(0, 128),
        Scope,
        IPAddressVersion: 'IPV4',
        Addresses: r.cidrs,
      })))
      newRules.push({
        Name: r.name,
        Priority: priority,
        Action: { Block: {} },
        Statement: { IPSetReferenceStatement: { ARN: ipset.Summary.ARN } },
        VisibilityConfig: vis(r.name),
      })
    } else if (r.type === 'string_match') {
      newRules.push({
        Name: r.name,
        Priority: priority,
        Action: { Block: {} },
        Statement: {
          ByteMatchStatement: {
            SearchString: new TextEncoder().encode(r.pattern || ''),
            FieldToMatch: wafFieldToMatch(r),
            TextTransformations: [{ Priority: 0, Type: 'NONE' }],
            PositionalConstraint: r.position || 'CONTAINS',
          },
        },
        VisibilityConfig: vis(r.name),
      })
    } else if (r.type === 'regex_match') {
      newRules.push({
        Name: r.name,
        Priority: priority,
        Action: { Block: {} },
        Statement: {
          RegexMatchStatement: {
            RegexString: r.pattern || '',
            FieldToMatch: wafFieldToMatch(r),
            TextTransformations: [{ Priority: 0, Type: 'NONE' }],
          },
        },
        VisibilityConfig: vis(r.name),
      })
    } else {
      newRules.push({
        Name: r.name,
        Priority: priority,
        Action: { Block: {} },
        Statement: { RateBasedStatement: { Limit: Number(r.limit) || 2000, AggregateKeyType: 'IP' } },
        VisibilityConfig: vis(r.name),
      })
    }
  }

  await wafRetry(() => waf.send(new UpdateWebACLCommand({
    Name: aclName,
    Id: req.target_id,
    Scope,
    DefaultAction: acl.DefaultAction,
    Rules: [...existing, ...newRules],
    VisibilityConfig: acl.VisibilityConfig,
    LockToken: get.LockToken,
  })))
  return { web_acl_id: req.target_id }
}

// ---- IAM 읽기전용 계정 ----
async function handleIam(iam, req, issueKey) {
  const p = req.payload || {}
  await iam.send(new CreateUserCommand({ UserName: p.user_name }))
  await iam.send(new AttachUserPolicyCommand({ UserName: p.user_name, PolicyArn: p.policy_arn }))
  const result = { user_name: p.user_name, policy_arn: p.policy_arn }
  if (issueKey) {
    const keyRes = await iam.send(new CreateAccessKeyCommand({ UserName: p.user_name }))
    result.access_key_id = keyRes.AccessKey.AccessKeyId
    result.secret_access_key = keyRes.AccessKey.SecretAccessKey // DB에는 저장하지 않고 응답으로만 1회 반환
  }
  return result
}

// ---- 환경 권한 부여/회수 ----
//
// Terraform으로 만들어 둔 그룹(env-dev 등)에 사용자를 넣고 뺀다.
// 그룹에 들어가면 그 환경의 역할(env-dev-role)을 맡을 수 있고, 역할을 맡으면
// 1시간짜리 임시 자격증명을 받는다. 영구 키를 사람마다 쥐어주지 않아도 된다.
//
// 어떤 환경이 있는지는 여기서 못 박는다. 화면에서 넘어온 값을 그대로 믿고
// 그룹 이름을 만들면, 신청서에 임의의 그룹명을 넣어 다른 그룹에 들어갈 수 있다.
const ENV_ACCESS_ACTIONS = ['grant_env_access', 'revoke_env_access']
const ENVIRONMENTS = ['dev', 'qa', 'prod', 'db']

// prod와 db는 최고 관리자 승인까지 받아야 한다.
// IAM만으로는 "db는 소수에게만"을 표현할 수 없어, 승인 절차로 지킨다.
const SUPER_ENVS = ['prod', 'db']

const groupNameOf = (env) => `env-${env}`

async function handleEnvAccess(iam, req) {
  const p = req.payload || {}
  const env = String(p.environment || '')
  const UserName = String(p.user_name || '')

  if (!ENVIRONMENTS.includes(env)) throw new Error(`알 수 없는 환경입니다: ${env}`)
  if (!UserName) throw new Error('user_name이 없습니다')

  const GroupName = groupNameOf(env)
  const grant = req.action === 'grant_env_access'

  // 없는 사용자에게 부여하면 IAM이 NoSuchEntity를 던진다. 먼저 확인해 메시지를 분명히 한다.
  try {
    await iam.send(new GetUserCommand({ UserName }))
  } catch (e) {
    if (String(e).includes('NoSuchEntity')) throw new Error(`IAM 사용자를 찾을 수 없습니다: ${UserName}`)
    throw e
  }

  if (grant) {
    await iam.send(new AddUserToGroupCommand({ GroupName, UserName }))
  } else {
    // 이미 빠져 있어도 목적은 달성된 상태다. 실패로 처리하면 재시도만 반복된다.
    try {
      await iam.send(new RemoveUserFromGroupCommand({ GroupName, UserName }))
    } catch (e) {
      if (!String(e).includes('NoSuchEntity')) throw e
    }
  }

  // 처리 후 실제로 어떤 환경 권한을 갖고 있는지 남긴다. 승인 이력에서 바로 확인된다.
  const groups = await iam.send(new ListGroupsForUserCommand({ UserName }))
  const envGroups = (groups.Groups || [])
    .map((g) => g.GroupName)
    .filter((n) => n.startsWith('env-'))

  return {
    user_name: UserName,
    environment: env,
    group_name: GroupName,
    action: grant ? 'granted' : 'revoked',
    current_env_groups: envGroups,
  }
}

// ---- 삭제 ----
// 삭제는 되돌릴 수 없어 최고 관리자만 실행할 수 있다(아래 serve에서 검사).
// 신청 시점에 원본 신청의 payload를 그대로 복사해두므로, 무엇을 지울지가 정확히 특정된다.

const DELETE_ACTIONS = ['delete_iam_user', 'delete_sg_rules', 'delete_waf_rules', 'delete_nacl_rules']

async function handleDeleteIamUser(iam, req) {
  const p = req.payload || {}
  const UserName = p.user_name
  if (!UserName) throw new Error('user_name이 없습니다')

  // 이미 없는 계정이면 목적은 달성된 상태다. 실패로 처리하면 재시도만 반복된다.
  const gone = (e) => String(e).includes('NoSuchEntity')

  // IAM은 액세스 키와 정책이 붙어 있으면 사용자를 지울 수 없다. 먼저 떼어낸다.
  let keys
  try {
    keys = await iam.send(new ListAccessKeysCommand({ UserName }))
  } catch (e) {
    if (gone(e)) return { deleted_user: UserName, note: '이미 삭제된 계정입니다' }
    throw e
  }
  for (const k of (keys.AccessKeyMetadata || [])) {
    await iam.send(new DeleteAccessKeyCommand({ UserName, AccessKeyId: k.AccessKeyId }))
  }
  const attached = await iam.send(new ListAttachedUserPoliciesCommand({ UserName }))
  for (const pol of (attached.AttachedPolicies || [])) {
    await iam.send(new DetachUserPolicyCommand({ UserName, PolicyArn: pol.PolicyArn }))
  }
  await iam.send(new DeleteUserCommand({ UserName }))

  return {
    deleted_user: UserName,
    removed_access_keys: (keys.AccessKeyMetadata || []).length,
    detached_policies: (attached.AttachedPolicies || []).length,
  }
}

async function handleDeleteSgRules(ec2, req) {
  const p = req.payload || {}
  const sgId = p.sg_id
  if (!sgId) throw new Error('sg_id가 없습니다')

  const ingress = (p.rules || []).filter((r) => r.direction === 'ingress')
  const egress = (p.rules || []).filter((r) => r.direction === 'egress')
  if (ingress.length === 0 && egress.length === 0) throw new Error('삭제할 규칙이 없습니다')

  // 이미 없는 규칙을 지우려 하면 InvalidPermission.NotFound가 난다.
  // 목적(그 규칙이 없는 상태)은 이미 달성된 것이므로 실패로 보지 않는다.
  const skipIfMissing = async (fn) => {
    try {
      await fn()
      return true
    } catch (e) {
      if (String(e).includes('InvalidPermission.NotFound')) return false
      throw e
    }
  }

  let removed = 0
  if (ingress.length > 0) {
    const ok = await skipIfMissing(() => ec2.send(new RevokeSecurityGroupIngressCommand({
      GroupId: sgId, IpPermissions: ingress.map(toPermission),
    })))
    if (ok) removed += ingress.length
  }
  if (egress.length > 0) {
    const ok = await skipIfMissing(() => ec2.send(new RevokeSecurityGroupEgressCommand({
      GroupId: sgId, IpPermissions: egress.map(toPermission),
    })))
    if (ok) removed += egress.length
  }
  return { sg_id: sgId, removed_rules: removed }
}

async function handleDeleteWafRules(req, credentials, defaultRegion) {
  const p = req.payload || {}
  const Scope = wafScopeOf(p)
  const waf = new WAFV2Client({ region: wafRegionFor(Scope, defaultRegion), credentials })

  const aclName = p.web_acl_name
  const aclId = p.web_acl_id || req.target_id
  if (!aclName || !aclId) throw new Error('대상 Web ACL 정보가 없습니다')

  const names = new Set((p.rule_names || []).filter(Boolean))
  if (names.size === 0) throw new Error('삭제할 규칙 이름이 없습니다')

  const get = await wafRetry(() => waf.send(new GetWebACLCommand({ Name: aclName, Id: aclId, Scope })))
  const acl = get.WebACL
  const kept = (acl.Rules || []).filter((r) => !names.has(r.Name))
  const removed = (acl.Rules || []).length - kept.length

  // 지울 규칙이 이미 없으면 업데이트를 건너뛴다(LockToken 낭비 방지).
  if (removed === 0) return { web_acl_id: aclId, removed_rules: 0, note: '이미 없는 규칙입니다' }

  await wafRetry(() => waf.send(new UpdateWebACLCommand({
    Name: aclName,
    Id: aclId,
    Scope,
    DefaultAction: acl.DefaultAction,
    Rules: kept,
    VisibilityConfig: acl.VisibilityConfig,
    LockToken: get.LockToken,
  })))
  return { web_acl_id: aclId, removed_rules: removed }
}

// 관리자가 승인 누른 신청을 실제 AWS에 반영. status='pending'인 요청만 처리(중복 승인 방지).
serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })
  try {
    const authHeader = req.headers.get('Authorization') || ''
    const token = authHeader.replace('Bearer ', '')
    const userClient = createClient(Deno.env.get('SUPABASE_URL'), Deno.env.get('SUPABASE_ANON_KEY'), {
      global: { headers: { Authorization: authHeader } }
    })
    const { data: { user }, error: authError } = await userClient.auth.getUser(token)
    if (authError || !user) return json({ ok: false, error: '로그인이 필요합니다' }, 401)

    const supabase = createClient(Deno.env.get('SUPABASE_URL'), Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'))

    // 승인은 관리자만. 프론트에서 메뉴를 감추는 것만으로는 이 함수를 직접 호출하는 걸 막지 못한다.
    const { data: adminRow, error: adminErr } = await supabase
      .from('admins').select('user_id, is_super').eq('user_id', user.id).maybeSingle()
    if (adminErr) throw adminErr
    if (!adminRow) return json({ ok: false, error: '관리자만 승인할 수 있습니다' }, 403)
    const isSuper = !!adminRow.is_super

    const { request_id, issue_key } = await req.json()
    if (!request_id) throw new Error('request_id가 필요합니다')

    // 어떤 신청인지 먼저 확인한다. 삭제면 승인 경로가 달라진다.
    const { data: target, error: targetErr } = await supabase
      .from('aws_requests').select('*').eq('id', request_id).maybeSingle()
    if (targetErr) throw targetErr
    if (!target) return json({ ok: false, error: '존재하지 않는 신청입니다' }, 400)

    const isDelete = DELETE_ACTIONS.includes(target.action)

    // prod·db 환경 권한을 새로 주는 것도 최고 관리자까지 거친다.
    // 회수는 권한이 줄어드는 방향이라 1차 승인으로 끝낸다 — 급할 때 막지 못하면 안 된다.
    const isSensitiveGrant = target.action === 'grant_env_access'
      && SUPER_ENVS.includes(String(target.payload?.environment || ''))

    const needsSuper = isDelete || isSensitiveGrant

    // 최고 관리자가 아니면 실제 AWS 작업을 하지 않고 1차 승인으로만 넘긴다.
    if (needsSuper && !isSuper) {
      const { data: staged, error: stageErr } = await supabase
        .from('aws_requests')
        .update({
          status: 'awaiting_super',
          reviewed_at: new Date().toISOString(),
          first_approver_id: user.id,
          first_approver_email: user.email,
          first_approved_at: new Date().toISOString(),
        })
        .eq('id', request_id)
        .eq('status', 'pending')
        .select()
        .maybeSingle()
      if (stageErr) throw stageErr
      if (!staged) return json({ ok: false, error: '이미 처리된 신청이거나 존재하지 않습니다' }, 400)
      return json({ ok: true, staged: true, message: '1차 승인 완료. 최고 관리자 승인이 필요합니다.' })
    }

    // 실행 대상 상태: 일반 신청은 pending, 삭제는 pending 또는 1차 승인된 것.
    // 2차 승인이 필요한 건은 awaiting_super 상태에서 넘어온다.
    const fromStatuses = needsSuper ? ['pending', 'awaiting_super'] : ['pending']

    // 원자적 전환 (동시 승인 중복 적용 방지)
    const { data: claimed, error: claimErr } = await supabase
      .from('aws_requests')
      .update({ status: 'approved', reviewed_at: new Date().toISOString() })
      .eq('id', request_id)
      .in('status', fromStatuses)
      .select()
      .maybeSingle()

    if (claimErr) throw claimErr
    if (!claimed) return json({ ok: false, error: '이미 처리된 신청이거나 존재하지 않습니다' }, 400)

    const accessKeyId = Deno.env.get('AWS_ACCESS_KEY')
    const secretAccessKey = Deno.env.get('AWS_ACCESS_SECRET_KEY')
    const region = Deno.env.get('AWS_REGION') || 'ap-northeast-2'

    if (!accessKeyId || !secretAccessKey) {
      await supabase.from('aws_requests').update({ status: 'failed', error_message: 'AWS 자격증명이 설정되지 않았습니다' }).eq('id', request_id)
      return json({ ok: false, error: 'AWS 자격증명이 설정되지 않았습니다' }, 400)
    }

    const credentials = { accessKeyId, secretAccessKey }

    try {
      let result = {}
      // 삭제는 action으로 먼저 분기한다 (resource_type은 생성과 같은 값을 쓰므로).
      if (claimed.action === 'delete_iam_user') {
        result = await handleDeleteIamUser(new IAMClient({ region, credentials }), claimed)
      } else if (claimed.action === 'delete_sg_rules') {
        result = await handleDeleteSgRules(new EC2Client({ region, credentials }), claimed)
      } else if (claimed.action === 'delete_waf_rules') {
        result = await handleDeleteWafRules(claimed, credentials, region)
      } else if (claimed.action === 'delete_nacl_rules') {
        result = await handleDeleteNaclRules(new EC2Client({ region, credentials }), claimed)
      } else if (claimed.action === 'add_nacl_rules') {
        result = await handleNaclRules(new EC2Client({ region, credentials }), claimed)
      } else if (ENV_ACCESS_ACTIONS.includes(claimed.action)) {
        result = await handleEnvAccess(new IAMClient({ region, credentials }), claimed)
      } else if (claimed.resource_type === 'security_group') {
        result = await handleSg(new EC2Client({ region, credentials }), claimed)
      } else if (claimed.resource_type === 'waf_web_acl') {
        result = await handleWaf(claimed, credentials, region)
      } else if (claimed.resource_type === 'iam_user') {
        result = await handleIam(new IAMClient({ region, credentials }), claimed, !!issue_key)
      } else {
        throw new Error('지원하지 않는 resource_type: ' + claimed.resource_type)
      }
      // secret_access_key는 응답으로만 1회 반환하고 DB에는 절대 저장하지 않음
      const { secret_access_key, ...resultForDb } = result
      await supabase.from('aws_requests').update({ status: 'applied', applied_at: new Date().toISOString(), result: resultForDb }).eq('id', request_id)
      return json({ ok: true, result })
    } catch (awsErr) {
      await supabase.from('aws_requests').update({ status: 'failed', error_message: String(awsErr) }).eq('id', request_id)
      return json({ ok: false, error: String(awsErr) }, 500)
    }
  } catch (e) {
    console.error('aws-request-apply error:', e)
    return json({ ok: false, error: String(e) }, 500)
  }
})
