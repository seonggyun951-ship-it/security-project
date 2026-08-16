import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

// 질문과 비슷한 자료를 지식 베이스에서 찾아온다.
//
// 검색어는 input_type을 'query'로 넣어야 한다. 문서는 'passage'로 넣어뒀다.
// embedqa 계열은 이 구분이 검색 품질에 직접 영향을 준다.

const NIM_EMBED = 'https://integrate.api.nvidia.com/v1/embeddings'
const MODEL = 'nvidia/llama-nemotron-embed-1b-v2'
const DIMENSIONS = 1024

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}
const json = (body, status = 200) => new Response(JSON.stringify(body), {
  headers: { ...cors, 'Content-Type': 'application/json' }, status,
})

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })

  try {
    const url = Deno.env.get('SUPABASE_URL')!
    const authHeader = req.headers.get('Authorization') || ''
    const token = authHeader.replace('Bearer ', '')
    if (!token) return json({ ok: false, error: '로그인이 필요합니다' }, 401)

    // 검색은 로그인만 하면 된다. 담긴 자료가 공개 보안 문서와 우리 규칙 엔진의 판정이라
    // 계정별로 가릴 내용이 없다. 받은 키로 클라이언트를 만들어 권한 판단을 맡긴다 —
    // match_knowledge는 authenticated에게만 실행 권한이 있다.
    const db = createClient(url, Deno.env.get('SUPABASE_ANON_KEY')!, {
      global: { headers: { Authorization: authHeader } },
    })
    const { data: { user } } = await db.auth.getUser(token)
    const client = user ? db : createClient(url, token)

    const key = Deno.env.get('NIM_API_KEY')
    if (!key) return json({ ok: false, error: 'NIM_API_KEY가 설정되지 않았습니다' }, 500)

    const { query, limit = 5, sources = null, min_similarity = 0 } = await req.json()
    if (!query || typeof query !== 'string') {
      return json({ ok: false, error: 'query가 필요합니다' }, 400)
    }

    const res = await fetch(NIM_EMBED, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: MODEL,
        input: [query],
        input_type: 'query',
        dimensions: DIMENSIONS,
        encoding_format: 'float',
        truncate: 'END',
      }),
    })
    if (!res.ok) {
      const detail = await res.text().catch(() => '')
      throw new Error(`임베딩 실패 (${res.status}): ${detail.slice(0, 200)}`)
    }
    const embedding = (await res.json()).data[0].embedding

    const { data, error } = await client.rpc('match_knowledge', {
      query_embedding: JSON.stringify(embedding),
      match_count: Math.min(Number(limit) || 5, 20),
      filter_sources: sources,
      min_similarity: Number(min_similarity) || 0,
    })
    if (error) throw error

    return json({ ok: true, query, count: data?.length ?? 0, results: data ?? [] })
  } catch (e) {
    console.error('rag-search error:', e)
    return json({ ok: false, error: String(e) }, 500)
  }
})
