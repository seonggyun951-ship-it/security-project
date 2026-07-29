import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import {
  EC2Client,
  AuthorizeSecurityGroupIngressCommand,
  AuthorizeSecurityGroupEgressCommand,
  CreateSecurityGroupCommand,
  CreateTagsCommand,
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

// ---- SG 가드레일 ----
const SENSITIVE_PORTS = [22, 3389, 3306, 5432, 1433, 6379, 27017]
const MAX_RULES_PER_SG = 50
const MIN_CIDR_PREFIX = 24 // /24 이상만 허용 (/0~/23 차단)

function validateSgRules(rules) {
  const errors = []
  for (const r of (rules || [])) {
    if (r.cidr === '0.0.0.0/0' || r.cidr === '::/0') {
      errors.push(`전체 개방(${r.cidr})은 허용되지 않습니다`)
    }
    const prefix = parseInt((r.cidr || '').split('/')[1])
    if (!isNaN(prefix) && prefix < MIN_CIDR_PREFIX) {
      errors.push(`CIDR ${r.cidr}: /${MIN_CIDR_PREFIX} 이상만 허용됩니다 (현재 /${prefix})`)
    }
    const ports = [r.from_port, r.to_port].filter((p) => p != null)
    for (const port of ports) {
      if (SENSITIVE_PORTS.includes(port) && r.direction === 'ingress') {
        errors.push(`포트 ${port}은 인바운드 자동 승인이 불가합니다 (수동 승인 필요)`)
      }
    }
  }
  if ((rules || []).length > MAX_RULES_PER_SG) {
    errors.push(`규칙 수가 ${MAX_RULES_PER_SG}개를 초과합니다`)
  }
  return errors
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

async function handleWaf(waf, req) {
  const p = req.payload || {}
  if (req.action === 'create_acl') {
    const rules = (p.managed_rule_groups || []).map((name, i) => ({
      Name: name,
      Priority: i,
      OverrideAction: { None: {} },
      Statement: { ManagedRuleGroupStatement: { VendorName: 'AWS', Name: name } },
      VisibilityConfig: vis(name),
    }))
    const res = await waf.send(new CreateWebACLCommand({
      Name: p.acl_name,
      Scope: 'REGIONAL',
      DefaultAction: p.default_action === 'block' ? { Block: {} } : { Allow: {} },
      Rules: rules,
      VisibilityConfig: vis(p.acl_name || 'webacl'),
    }))
    return { web_acl_id: res.Summary?.Id }
  }

  // add_waf_rules — 기존 Web ACL을 읽어 규칙을 합쳐 업데이트
  const aclName = p.web_acl_name || req.title
  const get = await waf.send(new GetWebACLCommand({ Name: aclName, Id: req.target_id, Scope: 'REGIONAL' }))
  const acl = get.WebACL
  const existing = acl.Rules || []
  let priority = existing.reduce((max, r) => Math.max(max, r.Priority ?? 0), -1)

  const newRules = []
  for (const r of (p.rules || [])) {
    priority += 1
    if (r.type === 'ip_block') {
      const ipset = await waf.send(new CreateIPSetCommand({
        Name: safeName(`${r.name}-ipset-${Date.now()}`).slice(0, 128),
        Scope: 'REGIONAL',
        IPAddressVersion: 'IPV4',
        Addresses: r.cidrs,
      }))
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

  await waf.send(new UpdateWebACLCommand({
    Name: aclName,
    Id: req.target_id,
    Scope: 'REGIONAL',
    DefaultAction: acl.DefaultAction,
    Rules: [...existing, ...newRules],
    VisibilityConfig: acl.VisibilityConfig,
    LockToken: get.LockToken,
  }))
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

    const { request_id, issue_key } = await req.json()
    if (!request_id) throw new Error('request_id가 필요합니다')

    const supabase = createClient(Deno.env.get('SUPABASE_URL'), Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'))

    // pending -> approved로 원자적 전환 (동시 승인 중복 적용 방지)
    const { data: claimed, error: claimErr } = await supabase
      .from('aws_requests')
      .update({ status: 'approved', reviewed_at: new Date().toISOString() })
      .eq('id', request_id)
      .eq('status', 'pending')
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
      if (claimed.resource_type === 'security_group') {
        result = await handleSg(new EC2Client({ region, credentials }), claimed)
      } else if (claimed.resource_type === 'waf_web_acl') {
        result = await handleWaf(new WAFV2Client({ region, credentials }), claimed)
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
