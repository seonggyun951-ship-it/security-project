import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { EC2Client, DescribeVpcsCommand } from 'npm:@aws-sdk/client-ec2@3'

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type'
}

const json = (body, status = 200) => new Response(JSON.stringify(body), {
  headers: { ...cors, 'Content-Type': 'application/json' }, status
})

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

    const accessKeyId = Deno.env.get('AWS_ACCESS_KEY')
    const secretAccessKey = Deno.env.get('AWS_ACCESS_SECRET_KEY')
    const region = Deno.env.get('AWS_REGION') || 'ap-northeast-2'

    if (!accessKeyId || !secretAccessKey) {
      return json({ ok: false, error: 'AWS 자격증명이 설정되지 않았습니다' }, 400)
    }

    const ec2 = new EC2Client({ region, credentials: { accessKeyId, secretAccessKey } })
    const { Vpcs } = await ec2.send(new DescribeVpcsCommand({}))

    const vpcs = (Vpcs || []).map((v) => ({
      vpc_id: v.VpcId,
      name: (v.Tags || []).find((t) => t.Key === 'Name')?.Value || v.VpcId,
      cidr: v.CidrBlock,
      is_default: v.IsDefault || false,
    }))

    return json({ ok: true, vpcs })
  } catch (e) {
    console.error('aws-list-vpcs error:', e)
    return json({ ok: false, error: String(e) }, 500)
  }
})
