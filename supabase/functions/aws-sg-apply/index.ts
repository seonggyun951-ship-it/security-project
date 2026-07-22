import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import {
  EC2Client,
  AuthorizeSecurityGroupIngressCommand,
  AuthorizeSecurityGroupEgressCommand,
  CreateSecurityGroupCommand,
  CreateTagsCommand,
} from 'npm:@aws-sdk/client-ec2@3'

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type'
}

const toPermission = (rule) => ({
  IpProtocol: rule.protocol,
  FromPort: rule.from_port ?? undefined,
  ToPort: rule.to_port ?? undefined,
  IpRanges: [{ CidrIp: rule.cidr, Description: rule.description || undefined }],
})

async function applyRules(ec2, sgId, rules) {
  const ingress = rules.filter((r) => r.direction === 'ingress')
  const egress = rules.filter((r) => r.direction === 'egress')
  if (ingress.length > 0) {
    await ec2.send(new AuthorizeSecurityGroupIngressCommand({ GroupId: sgId, IpPermissions: ingress.map(toPermission) }))
  }
  if (egress.length > 0) {
    await ec2.send(new AuthorizeSecurityGroupEgressCommand({ GroupId: sgId, IpPermissions: egress.map(toPermission) }))
  }
}

// 관리자가 승인 누른 SG 신청을 실제 AWS에 반영. status='pending'인 요청만 처리(중복 승인 방지). 삭제/취소 기능은 의도적으로 없음.
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

    const { request_id } = await req.json()
    if (!request_id) throw new Error('request_id가 필요합니다')

    const supabase = createClient(Deno.env.get('SUPABASE_URL'), Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'))

    // pending -> approved로 원자적 전환 (동시 승인 중복 적용 방지)
    const { data: claimed, error: claimErr } = await supabase
      .from('aws_sg_requests')
      .update({ status: 'approved', reviewed_at: new Date().toISOString() })
      .eq('id', request_id)
      .eq('status', 'pending')
      .select()
      .maybeSingle()

    if (claimErr) throw claimErr
    if (!claimed) {
      return new Response(JSON.stringify({ ok: false, error: '이미 처리된 신청이거나 존재하지 않습니다' }), {
        headers: { ...cors, 'Content-Type': 'application/json' }, status: 400
      })
    }

    const accessKeyId = Deno.env.get('AWS_ACCESS_KEY')
    const secretAccessKey = Deno.env.get('AWS_ACCESS_SECRET_KEY')
    const region = Deno.env.get('AWS_REGION') || 'ap-northeast-2'

    if (!accessKeyId || !secretAccessKey) {
      await supabase.from('aws_sg_requests').update({ status: 'failed', error_message: 'AWS 자격증명이 설정되지 않았습니다' }).eq('id', request_id)
      return new Response(JSON.stringify({ ok: false, error: 'AWS 자격증명이 설정되지 않았습니다' }), {
        headers: { ...cors, 'Content-Type': 'application/json' }, status: 400
      })
    }

    const ec2 = new EC2Client({ region, credentials: { accessKeyId, secretAccessKey } })

    try {
      if (claimed.request_type === 'create_sg') {
        const { GroupId } = await ec2.send(new CreateSecurityGroupCommand({
          GroupName: claimed.sg_name,
          Description: claimed.description || claimed.sg_name,
          VpcId: claimed.vpc_id,
        }))
        await ec2.send(new CreateTagsCommand({ Resources: [GroupId], Tags: [{ Key: 'Name', Value: claimed.sg_name }] }))
        if (claimed.rules?.length) await applyRules(ec2, GroupId, claimed.rules)
        await supabase.from('aws_sg_requests').update({ status: 'applied', applied_at: new Date().toISOString(), created_sg_id: GroupId }).eq('id', request_id)
      } else {
        await applyRules(ec2, claimed.sg_id, claimed.rules)
        await supabase.from('aws_sg_requests').update({ status: 'applied', applied_at: new Date().toISOString() }).eq('id', request_id)
      }
      return new Response(JSON.stringify({ ok: true }), { headers: { ...cors, 'Content-Type': 'application/json' } })
    } catch (awsErr) {
      await supabase.from('aws_sg_requests').update({ status: 'failed', error_message: String(awsErr) }).eq('id', request_id)
      return new Response(JSON.stringify({ ok: false, error: String(awsErr) }), { headers: { ...cors, 'Content-Type': 'application/json' }, status: 500 })
    }
  } catch (e) {
    console.error('aws-sg-apply error:', e)
    return new Response(JSON.stringify({ ok: false, error: String(e) }), { headers: { ...cors, 'Content-Type': 'application/json' }, status: 500 })
  }
})
