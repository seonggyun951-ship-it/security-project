import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { EC2Client, DescribeSecurityGroupsCommand, DescribeVpcsCommand, DescribeNetworkAclsCommand } from 'npm:@aws-sdk/client-ec2@3'
import { IAMClient, ListRolesCommand, ListPoliciesCommand, ListUsersCommand, ListGroupsForUserCommand } from 'npm:@aws-sdk/client-iam@3'
import { WAFV2Client, ListWebACLsCommand, GetWebACLCommand } from 'npm:@aws-sdk/client-wafv2@3'

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-cron-secret'
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

// 네트워크 ACL — NACL 규칙 신청 화면의 드롭다운에 쓴다.
// NACL은 이름 태그가 거의 없어 ID만 남는 경우가 많다. 어느 VPC의 기본 NACL인지가
// 사실상의 이름이므로 그걸 만들어 넣는다 (acl-0123 만 보면 어느 환경인지 알 수 없다).
async function collectNetworkAcls(ec2, vpcRows) {
  const acls = await paginate(
    (token) => ec2.send(new DescribeNetworkAclsCommand({ NextToken: token })),
    (res) => res.NetworkAcls || [],
    (res) => res.NextToken
  )
  const vpcName = Object.fromEntries(vpcRows.map((v) => [v.resource_id, v.resource_name]))
  return acls.map((a) => {
    const tag = (a.Tags || []).find((t) => t.Key === 'Name')?.Value
    const where = vpcName[a.VpcId] || a.VpcId
    return {
      resource_type: 'network_acl',
      resource_id: a.NetworkAclId,
      resource_name: tag || `${where}${a.IsDefault ? ' 기본' : ''} (${a.NetworkAclId})`,
      region: null,
      raw_data: a,
    }
  })
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
    // 부르는 쪽이 둘이다: 화면에서 관리자가 누르거나, pg_cron이 정기적으로 부르거나.
    // 크론에는 로그인한 사람이 없으므로 CRON_SECRET 헤더로 대신 확인한다
    // (expire-access와 같은 방식).
    const cronSecret = Deno.env.get('CRON_SECRET')
    const byCron = !!cronSecret && req.headers.get('x-cron-secret') === cronSecret

    if (!byCron) {
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

    // NACL 이름은 VPC 이름을 붙여 만들므로 VPC 수집이 끝난 뒤에 돈다.
    const naclResults = await collectNetworkAcls(ec2, vpcResults)
      .catch((e) => { console.error('NACL 수집 실패:', e); return [] })

    const rows = [...sgResults, ...vpcResults, ...roleResults, ...policyResults, ...userResults, ...wafResults, ...naclResults]

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

    // 이번 수집에서 실제로 보인 리소스를 기록한다. 스냅샷은 덧붙이기만 하는 이력이라
    // 삭제된 리소스도 마지막 행이 남는데, 이 표가 없으면 뷰가 그걸 계속 내보낸다.
    // 시각은 한 번만 구해 전부에 같은 값을 넣는다 — 뷰가 '종류별 최대 시각과 같은 것'을
    // 현재로 보므로, 수집 도중 초가 넘어가면 같은 회차가 둘로 갈린다.
    if (rows.length > 0) {
      const seenAt = new Date().toISOString()
      const seen = rows.map((r) => ({
        resource_type: r.resource_type, resource_id: r.resource_id, last_seen_at: seenAt,
      }))
      // 한 번에 다 보내면 payload가 커진다. 200개씩 나눈다.
      for (let i = 0; i < seen.length; i += 200) {
        const { error } = await supabase.from('aws_resource_seen')
          .upsert(seen.slice(i, i + 200), { onConflict: 'resource_type,resource_id' })
        if (error) throw error
      }
    }

    // 수집이 끝났음을 남긴다. 승인 트리거가 세워둔 '수집 필요' 표시를 여기서 내린다.
    // 실패하면 dirty가 남아 다음 주기에 다시 시도한다 — 그게 맞는 동작이라 위에서
    // throw로 빠져나가면 이 줄에 오지 않는다.
    await supabase.from('collect_state')
      .update({ last_collected_at: new Date().toISOString(), dirty: false })
      .eq('id', 1)

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
