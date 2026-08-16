import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import {
  EC2Client,
  RevokeSecurityGroupIngressCommand,
  RevokeSecurityGroupEgressCommand,
} from 'npm:@aws-sdk/client-ec2@3'
import { IAMClient, RemoveUserFromGroupCommand } from 'npm:@aws-sdk/client-iam@3'

// 만료된 권한을 회수하는 배치. pg_cron이 하루 한 번 호출한다.
//
// 사람이 부르는 함수가 아니라 로그인 검사를 할 수 없다. 대신 CRON_SECRET 헤더로 막는다.
// 설령 호출되더라도 하는 일은 "이미 만료된 것을 회수"뿐이라 앞당겨 지워지는 건 없다.

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-cron-secret',
}
const json = (body, status = 200) => new Response(JSON.stringify(body), {
  headers: { ...cors, 'Content-Type': 'application/json' }, status,
})

async function notifyDiscord(content) {
  const url = Deno.env.get('DISCORD_WEBHOOK')
  if (!url) return
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: content.slice(0, 1900) }),
    })
  } catch (e) {
    console.error('Discord 전송 실패:', e)
  }
}

// 이미 없는 것을 지우려 할 때 나는 오류들. 목적("그게 없는 상태")은 달성됐으므로
// 실패로 보지 않는다. 실패로 두면 매일 같은 건을 다시 시도하게 된다.
//   NoSuchEntity              IAM 사용자·그룹이 없음
//   InvalidPermission.NotFound 그 규칙이 이미 없음
//   InvalidGroup.NotFound      SG 자체가 삭제됨 (그 안의 규칙도 함께 사라진 것)
const alreadyGone = (e) => {
  const s = String(e)
  return s.includes('NoSuchEntity')
    || s.includes('InvalidPermission.NotFound')
    || s.includes('InvalidGroup.NotFound')
    || s.includes('InvalidGroupId.Malformed')
}

const toPermission = (r) => ({
  IpProtocol: r.protocol,
  FromPort: r.from_port,
  ToPort: r.to_port ?? r.from_port,
  IpRanges: [{ CidrIp: r.cidr }],
})

async function revokeEnvAccess(iam, req) {
  const p = req.payload || {}
  const GroupName = `env-${p.environment}`
  try {
    await iam.send(new RemoveUserFromGroupCommand({ GroupName, UserName: p.user_name }))
  } catch (e) {
    if (!alreadyGone(e)) throw e
  }
  return `${p.user_name} → ${GroupName} 회수`
}

async function revokeSgRules(ec2, req) {
  const p = req.payload || {}
  // create_sg는 만들면서 규칙을 넣었고, add_rules는 기존 SG에 넣었다.
  // 어느 쪽이든 만료 시 되돌릴 대상은 그때 넣은 규칙이다.
  const sgId = p.sg_id || req.target_id || req.result?.created_id
  if (!sgId) throw new Error('대상 SG를 알 수 없습니다')

  const ingress = (p.rules || []).filter((r) => r.direction === 'ingress')
  const egress = (p.rules || []).filter((r) => r.direction === 'egress')

  const skip = async (fn) => {
    try { await fn() } catch (e) { if (!alreadyGone(e)) throw e }
  }
  if (ingress.length > 0) {
    await skip(() => ec2.send(new RevokeSecurityGroupIngressCommand({
      GroupId: sgId, IpPermissions: ingress.map(toPermission),
    })))
  }
  if (egress.length > 0) {
    await skip(() => ec2.send(new RevokeSecurityGroupEgressCommand({
      GroupId: sgId, IpPermissions: egress.map(toPermission),
    })))
  }
  return `${sgId} 규칙 ${ingress.length + egress.length}건 회수`
}

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })

  const secret = Deno.env.get('CRON_SECRET')
  if (!secret) return json({ ok: false, error: 'CRON_SECRET이 설정되지 않았습니다' }, 500)
  if (req.headers.get('x-cron-secret') !== secret) {
    return json({ ok: false, error: '허용되지 않은 호출입니다' }, 401)
  }

  const supabase = createClient(
    Deno.env.get('SUPABASE_URL'),
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'),
  )

  try {
    const nowIso = new Date().toISOString()

    // 적용이 끝났고, 만료일이 지났고, 아직 회수하지 않은 건.
    const { data: rows, error } = await supabase
      .from('aws_requests')
      .select('*')
      .eq('status', 'applied')
      .is('expired_at', null)
      .in('action', ['grant_env_access', 'create_sg', 'add_rules'])
      .not('payload->>expires_at', 'is', null)
      .lt('payload->>expires_at', nowIso)
      .limit(100)
    if (error) throw error

    if (!rows || rows.length === 0) return json({ ok: true, expired: 0 })

    // 변수 이름은 aws-request-apply와 같아야 한다 (같은 자격증명을 쓴다)
    const accessKeyId = Deno.env.get('AWS_ACCESS_KEY')
    const secretAccessKey = Deno.env.get('AWS_ACCESS_SECRET_KEY')
    const region = Deno.env.get('AWS_REGION') || 'ap-northeast-2'
    if (!accessKeyId || !secretAccessKey) {
      throw new Error('AWS 자격증명이 설정되지 않았습니다')
    }
    const credentials = { accessKeyId, secretAccessKey }
    const iam = new IAMClient({ region, credentials })
    const ec2 = new EC2Client({ region, credentials })

    const done = []
    const failed = []

    for (const r of rows) {
      try {
        const summary = r.action === 'grant_env_access'
          ? await revokeEnvAccess(iam, r)
          : await revokeSgRules(ec2, r)

        // 회수에 성공한 건만 expired_at을 찍는다. 실패한 건은 다음 회차에 다시 시도된다.
        await supabase.from('aws_requests')
          .update({ expired_at: new Date().toISOString() })
          .eq('id', r.id)

        done.push({ id: r.id, action: r.action, summary })
      } catch (e) {
        console.error(`만료 회수 실패 (${r.id}):`, e)
        failed.push({ id: r.id, action: r.action, error: String(e).slice(0, 200) })
      }
    }

    if (done.length > 0 || failed.length > 0) {
      const lines = [
        `⏰ **만료 권한 회수** — 성공 ${done.length}건${failed.length ? `, 실패 ${failed.length}건` : ''}`,
        ...done.map((d) => `· ${d.summary}`),
        ...failed.map((f) => `· ❌ ${f.action}: ${f.error}`),
      ]
      await notifyDiscord(lines.join('\n'))
    }

    return json({ ok: true, expired: done.length, failed: failed.length, done, failed })
  } catch (e) {
    console.error('expire-access error:', e)
    await notifyDiscord(`❌ **만료 회수 배치 실패**\n${String(e).slice(0, 300)}`)
    return json({ ok: false, error: String(e) }, 500)
  }
})
