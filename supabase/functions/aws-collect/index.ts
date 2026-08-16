import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { EC2Client, DescribeSecurityGroupsCommand, DescribeVpcsCommand } from 'npm:@aws-sdk/client-ec2@3'
import { IAMClient, ListRolesCommand, ListPoliciesCommand, ListUsersCommand, ListGroupsForUserCommand } from 'npm:@aws-sdk/client-iam@3'
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

async function collectVpcs(ec2) {
  const vpcs = await paginate(
    (token) => ec2.send(new DescribeVpcsCommand({ NextToken: token })),
    (res) => res.Vpcs || [],
    (res) => res.NextToken
  )
  return vpcs.map((v) => ({
    resource_type: 'vpc',
    resource_id: v.VpcId,
    resource_name: (v.Tags || []).find((t) => t.Key === 'Name')?.Value || v.VpcId,
    region: null,
    raw_data: v,
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

// IAM 사용자 — 환경 권한 신청 화면의 드롭다운에 쓴다.
// 어떤 환경 그룹에 이미 속해 있는지도 함께 담아, 승인자가 화면에서 바로 판단할 수 있게 한다.
async function collectIamUsers(iam) {
  const users = await paginate(
    (token) => iam.send(new ListUsersCommand({ Marker: token })),
    (res) => res.Users || [],
    (res) => res.IsTruncated ? res.Marker : undefined
  )

  // 사용자마다 그룹을 한 번씩 더 조회한다. 규모가 크지 않아 이 정도면 충분하다.
  // 한 명이 실패해도 나머지 목록은 살린다.
  return await Promise.all(users.map(async (u) => {
    let envGroups = []
    try {
      const g = await iam.send(new ListGroupsForUserCommand({ UserName: u.UserName }))
      envGroups = (g.Groups || []).map((x) => x.GroupName).filter((n) => n.startsWith('env-'))
    } catch (e) {
      console.error(`그룹 조회 실패 (${u.UserName}):`, e)
    }
    return {
      resource_type: 'iam_user',
      resource_id: u.UserId,
      resource_name: u.UserName,
      region: null,
      // EnvGroups는 뷰(aws_resource_options)가 꺼내 쓴다
      raw_data: { ...u, EnvGroups: envGroups.join(', ') },
    }
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

// WAFv2는 스코프별로 API 엔드포인트가 다르다.
//   REGIONAL   : 해당 리전에서 조회
//   CLOUDFRONT : 반드시 us-east-1에서 조회 (리소스 위치와 무관)
// 한쪽을 빼먹으면 신청 화면의 Web ACL 목록에 그 스코프가 통째로 안 나온다.
// region 컬럼에 스코프를 구분해 넣어두면, 규칙 추가 시 어떤 스코프로 호출할지 알 수 있다.
async function collectWafScope(waf, scope, region) {
  const { WebACLs } = await waf.send(new ListWebACLsCommand({ Scope: scope }))
  const results = []
  for (const acl of WebACLs || []) {
    const detail = await waf.send(new GetWebACLCommand({ Scope: scope, Id: acl.Id, Name: acl.Name }))
    results.push({
      resource_type: 'waf_web_acl',
      resource_id: acl.Id,
      resource_name: acl.Name,
      region: scope === 'CLOUDFRONT' ? 'CLOUDFRONT' : region,
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

    // 수집은 AWS 설정 전반(SG 규칙/IAM/WAF)을 읽어 저장하므로 관리자만 실행한다.
    // 화면에서 메뉴를 감추는 것만으로는 이 함수를 직접 호출하는 걸 막지 못한다.
    const adminCheck = createClient(Deno.env.get('SUPABASE_URL'), Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'))
    const { data: adminRow, error: adminErr } = await adminCheck
      .from('admins').select('user_id').eq('user_id', user.id).maybeSingle()
    if (adminErr) throw adminErr
    if (!adminRow) {
      return new Response(JSON.stringify({ ok: false, error: '관리자만 수집할 수 있습니다' }), {
        headers: { ...cors, 'Content-Type': 'application/json' }, status: 403
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
    // CLOUDFRONT 스코프는 us-east-1 엔드포인트로만 조회된다.
    const wafGlobal = new WAFV2Client({ region: 'us-east-1', credentials })

    const [sgResults, vpcResults, roleResults, policyResults, userResults, wafRegional, wafCloudfront] = await Promise.all([
      collectSecurityGroups(ec2).catch((e) => { console.error('SG 수집 실패:', e); return [] }),
      collectVpcs(ec2).catch((e) => { console.error('VPC 수집 실패:', e); return [] }),
      collectIamRoles(iam).catch((e) => { console.error('IAM Role 수집 실패:', e); return [] }),
      collectIamPolicies(iam).catch((e) => { console.error('IAM Policy 수집 실패:', e); return [] }),
      collectIamUsers(iam).catch((e) => { console.error('IAM User 수집 실패:', e); return [] }),
      collectWafScope(waf, 'REGIONAL', region).catch((e) => { console.error('WAF(REGIONAL) 수집 실패:', e); return [] }),
      collectWafScope(wafGlobal, 'CLOUDFRONT', region).catch((e) => { console.error('WAF(CLOUDFRONT) 수집 실패:', e); return [] }),
    ])
    const wafResults = [...wafRegional, ...wafCloudfront]

    const rows = [...sgResults, ...vpcResults, ...roleResults, ...policyResults, ...userResults, ...wafResults]

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
        vpc: vpcResults.length,
        iam_role: roleResults.length,
        iam_policy: policyResults.length,
        iam_user: userResults.length,
        waf_web_acl: wafResults.length,
      }
    }), { headers: { ...cors, 'Content-Type': 'application/json' } })
  } catch (e) {
    console.error('aws-collect error:', e)
    return new Response(JSON.stringify({ ok: false, error: String(e) }), { headers: { ...cors, 'Content-Type': 'application/json' }, status: 500 })
  }
})
