import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type'
}
const json = (body, status = 200) => new Response(JSON.stringify(body), {
  headers: { ...cors, 'Content-Type': 'application/json' }, status
})

// Discord 웹훅 URL을 프론트 번들에서 없애기 위한 프록시.
// GitHub Pages는 정적 사이트라 번들에 넣으면 누구나 URL을 꺼내 채널에 글을 쓸 수 있다.
// 여기서는 URL을 서버 환경변수로만 두고, 로그인한 사용자만 전송할 수 있게 한다.
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

    const webhook = Deno.env.get('DISCORD_WEBHOOK')
    if (!webhook) return json({ ok: false, error: 'DISCORD_WEBHOOK이 설정되지 않았습니다' }, 500)

    const { content } = await req.json()
    if (!content || typeof content !== 'string') return json({ ok: false, error: 'content가 필요합니다' }, 400)

    // Discord 제한(2000자)을 넘으면 통째로 실패하므로 잘라서 보낸다.
    const body = content.length > 1900 ? content.slice(0, 1900) + '\n…(생략)' : content

    const res = await fetch(webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: body }),
    })
    if (!res.ok) {
      const detail = await res.text().catch(() => '')
      console.error('Discord 전송 실패:', res.status, detail)
      return json({ ok: false, error: `Discord 전송 실패 (${res.status})` }, 502)
    }
    return json({ ok: true })
  } catch (e) {
    console.error('notify-discord error:', e)
    return json({ ok: false, error: String(e) }, 500)
  }
})
