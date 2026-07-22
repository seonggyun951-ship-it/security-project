import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { EC2Client, DescribeSecurityGroupsCommand } from 'npm:@aws-sdk/client-ec2@3'
import { IAMClient, ListRolesCommand, ListPoliciesCommand } from 'npm:@aws-sdk/client-iam@3'
import { WAFV2Client, ListWebACLsCommand, GetWebACLCommand } from 'npm:@aws-sdk/client-wafv2@3'

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type'
}

// 객체 키 순서에 상관없이 비교하기 위한 정규화된 문자열화 (Postgres JSONB는 키 순서를 보존하지 않음)
function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort()
    return `{${keys.map((k) => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',')}}`
  }
  return JSON.stringify(value)
}

// 페이지네이션이 있는 AWS API 전체 결과 수집
async function paginate(fn, extractItems, extractToken) {
  const items = []
  let token
  do {
    const res = await fn(token)
    items.push(...extractItems(res))
    token = extractToken(res)
  } while (token)
  return items
}

async function collectSecurityGroups(ec2) {
  const groups = await paginate(
    (token) => ec2.send(new DescribeSecurityGroupsCommand({ NextToken: token })),
    (res) => res.SecurityGroups || [],
    (res) => res.NextToken
  )
  return groups.map((sg) => ({
    resource_type: 'security_group',
    resource_id: sg.GroupId,
    resource_name: sg.GroupName || sg.GroupId,
    region: null,
    raw_data: sg,
  }))
}

async function collectIamRoles(iam) {
  const roles = await paginate(
    (token) => iam.send(new ListRolesCommand({ Marker: token })),
    (res) => res.Roles || [],
    (res) => res.IsTruncated ? res.Marker : undefined
  )
  return roles.map((r) => ({
    resource_type: 'iam_role',
    resource_id: r.RoleId,
    resource_name: r.RoleName,
    region: null,
    raw_data: r,
  }))
}

async function collectIamPolicies(iam) {
  const policies = await paginate(
    (token) => iam.send(new ListPoliciesCommand({ Scope: 'Local', Marker: token })),
    (res) => res.Policies || [],
    (res) => res.IsTruncated ? res.Marker : undefined
  )
  return policies.map((p) => ({
    resource_type: 'iam_policy',
    resource_id: p.PolicyId,
    resource_name: p.PolicyName,
    region: null,
    raw_data: p,
  }))
}

// WAF는 REGIONAL 스코프만 수집 (CLOUDFRONT는 us-east-1 고정 호출이 필요해 추후 별도 처리)
async function collectWaf(waf, region) {
  const { WebACLs } = await waf.send(new ListWebACLsCommand({ Scope: 'REGIONAL' }))
  const results = []
  for (const acl of WebACLs || []) {
    const detail = await waf.send(new GetWebACLCommand({ Scope: 'REGIONAL', Id: acl.Id, Name: acl.Name }))
    results.push({
      resource_type: 'waf_web_acl',
      resource_id: acl.Id,
      resource_name: acl.Name,
      region,
      raw_data: detail.WebACL,
    })
  }
  return results
}

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })
  try {
    const authHeader = req.headers.get('Authorization') || ''
    const token = authHeader.replace('Bearer ', '')
    const userClient = createClient(Deno.env.get('SUPABASE_URL'), Deno.env.get('SUPABASE_ANON_KEY'), {
      global: { headers: { Authorization: authHeader } }
    })
    const { data: { user }, error: authError } = await userClient.auth.getUser(token)
    if (authError || !user) {
      return new Response(JSON.stringify({ ok: false, error: '로그인이 필요합니다' }), {
        headers: { ...cors, 'Content-Type': 'application/json' }, status: 401
      })
    }

    const accessKeyId = Deno.env.get('AWS_ACCESS_KEY')
    const secretAccessKey = Deno.env.get('AWS_ACCESS_SECRET_KEY')
    const region = Deno.env.get('AWS_REGION') || 'ap-northeast-2'

    if (!accessKeyId || !secretAccessKey) {
      return new Response(JSON.stringify({ ok: false, error: 'AWS 자격증명이 아직 설정되지 않았습니다 (AWS_ACCESS_KEY / AWS_ACCESS_SECRET_KEY)' }), {
        headers: { ...cors, 'Content-Type': 'application/json' }, status: 400
      })
    }

    const credentials = { accessKeyId, secretAccessKey }
    const ec2 = new EC2Client({ region, credentials })
    const iam = new IAMClient({ region, credentials })
    const waf = new WAFV2Client({ region, credentials })

    const [sgResults, roleResults, policyResults, wafResults] = await Promise.all([
      collectSecurityGroups(ec2).catch((e) => { console.error('SG 수집 실패:', e); return [] }),
      collectIamRoles(iam).catch((e) => { console.error('IAM Role 수집 실패:', e); return [] }),
      collectIamPolicies(iam).catch((e) => { console.error('IAM Policy 수집 실패:', e); return [] }),
      collectWaf(waf, region).catch((e) => { console.error('WAF 수집 실패:', e); return [] }),
    ])

    const rows = [...sgResults, ...roleResults, ...policyResults, ...wafResults]

    const supabase = createClient(Deno.env.get('SUPABASE_URL'), Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'))

    // 리소스별 마지막 스냅샷과 비교해서, 실제로 바뀐 것만 새로 기록 (변화 이력 유지, 불필요한 중복 방지)
    let changed = 0
    for (const row of rows) {
      const { data: last } = await supabase
        .from('aws_resource_snapshots')
        .select('raw_data')
        .eq('resource_type', row.resource_type)
        .eq('resource_id', row.resource_id)
        .order('collected_at', { ascending: false })
        .limit(1)
        .maybeSingle()

      if (last && stableStringify(last.raw_data) === stableStringify(row.raw_data)) continue

      const { error } = await supabase.from('aws_resource_snapshots').insert(row)
      if (error) throw error
      changed++
    }

    return new Response(JSON.stringify({
      ok: true,
      changed,
      counts: {
        security_group: sgResults.length,
        iam_role: roleResults.length,
        iam_policy: policyResults.length,
        waf_web_acl: wafResults.length,
      }
    }), { headers: { ...cors, 'Content-Type': 'application/json' } })
  } catch (e) {
    console.error('aws-collect error:', e)
    return new Response(JSON.stringify({ ok: false, error: String(e) }), { headers: { ...cors, 'Content-Type': 'application/json' }, status: 500 })
  }
})
