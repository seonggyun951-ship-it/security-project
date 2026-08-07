import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { EC2Client, DescribeVpcsCommand } from 'npm:@aws-sdk/client-ec2@3'

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type'
}

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })

  const headers = { ...cors, 'Content-Type': 'application/json' }

  try {
    // 인증 확인
    const authHeader = req.headers.get('Authorization') || ''
    const token = authHeader.replace('Bearer ', '')

    if (!token) {
      return new Response(JSON.stringify({ ok: false, error: '로그인이 필요합니다' }), { headers, status: 401 })
    }

    const userClient = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_ANON_KEY')!,
      { global: { headers: { Authorization: authHeader } } }
    )
    const { data: { user }, error: authError } = await userClient.auth.getUser(token)
    if (authError || !user) {
      return new Response(JSON.stringify({ ok: false, error: '로그인이 필요합니다' }), { headers, status: 401 })
    }

    // AWS 자격증명
    const accessKeyId = Deno.env.get('AWS_ACCESS_KEY')
    const secretAccessKey = Deno.env.get('AWS_ACCESS_SECRET_KEY')
    const region = Deno.env.get('AWS_REGION') || 'ap-northeast-2'

    if (!accessKeyId || !secretAccessKey) {
      return new Response(JSON.stringify({ ok: false, error: 'AWS 자격증명 미설정' }), { headers, status: 400 })
    }

    // VPC 목록 조회
    const ec2 = new EC2Client({ region, credentials: { accessKeyId, secretAccessKey } })
    const result = await ec2.send(new DescribeVpcsCommand({}))
    const vpcs = (result.Vpcs || []).map((v: any) => ({
      vpc_id: v.VpcId,
      name: (v.Tags || []).find((t: any) => t.Key === 'Name')?.Value || v.VpcId,
      cidr: v.CidrBlock,
      is_default: v.IsDefault || false,
    }))

    return new Response(JSON.stringify({ ok: true, vpcs }), { headers })
  } catch (e) {
    console.error('aws-list-vpcs error:', e)
    return new Response(
      JSON.stringify({ ok: false, error: String(e) }),
      { headers, status: 500 }
    )
  }
})
