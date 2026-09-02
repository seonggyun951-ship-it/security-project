import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

// 질문과 비슷한 자료를 지식 베이스에서 찾아온다.
//
// 검색어는 앞에 'query: '를, 문서는 'passage: '를 붙여 임베딩한다.
// nemotron-3는 이 접두사로 둘을 구분한다(이전 embedqa 계열의 input_type 파라미터를 대신한다).
// 빠뜨리면 검색 품질이 떨어진다.

const NIM_EMBED = 'https://integrate.api.nvidia.com/v1/embeddings'
const MODEL = 'nvidia/nemotron-3-embed-1b'
const DIMENSIONS = 2048

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

    const {
      query, limit = 5, sources = null, min_similarity = 0,
      probe_model = null, probe_dimensions = null, probe_list = false, probe_chat = null,
      probe_rerank = null,
    } = await req.json()

    // 모델 점검용 경로. 모델 이름과 차원을 받아 임베딩만 한 번 해보고 결과를 돌려준다.
    // NVIDIA가 모델을 종료하거나 이름을 바꿨을 때 어느 이름이 살아 있고 차원이 몇으로
    // 나오는지는 문서로 갈라내기 어렵다. 실제로 불러보는 게 유일하게 확실하다.
    // DB는 건드리지 않는다.
    // 모델 목록. 문서 페이지는 종료된 모델도 그대로 남아 있어 믿을 수 없다.
    if (probe_list) {
      const r = await fetch('https://integrate.api.nvidia.com/v1/models', {
        headers: { Authorization: `Bearer ${key}` },
      })
      const text = await r.text()
      if (!r.ok) return json({ ok: false, status: r.status, error: text.slice(0, 300) })
      const ids = (JSON.parse(text).data || []).map((m) => m.id).sort()
      return json({ ok: true, count: ids.length, models: ids })
    }

    // 리랭킹 점검.
    //
    // 임베딩은 질의와 문서를 따로 벡터로 만들어 거리를 잰다. 그래서 층위가 다르면
    // 뜻이 통해도 점수가 안 나온다 — MITRE·OWASP가 그렇다. 리랭커는 질의와 문서를
    // 한 쌍으로 함께 넣어 채점하므로 그 한계를 넘는다.
    //
    // 모델 목록(/v1/models)에는 안 잡힌다. 리랭커는 /v1/ranking이라는 다른 문을 쓴다.
    // 문서에 적혀 있어도 죽은 모델이 있으니 실제로 불러 봐야 안다.
    if (probe_rerank) {
      // 리랭커는 integrate.api가 아니라 ai.api 쪽 모델별 경로에 있다.
      // 어느 형태가 맞는지는 불러 봐야 알아서 URL을 받게 해 뒀다.
      const url = probe_rerank.url ||
        'https://ai.api.nvidia.com/v1/retrieval/nvidia/reranking'
      const r = await fetch(url, {
        method: 'POST',
        headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: probe_rerank.model,
          query: { text: probe_rerank.query || 'SSH 22번 포트를 인터넷 전체에 여는 것의 위험' },
          passages: (probe_rerank.passages || [
            'MITRE ATT&CK T1021.004 Remote Services: SSH — 공격자가 유효한 계정으로 SSH에 접속해 측면 이동한다',
            'OWASP A10:2021 서버 측 요청 위조(SSRF) — 서버가 공격자가 지정한 주소로 요청을 보낸다',
          ]).map((t) => ({ text: t })),
        }),
      })
      const text = await r.text()
      return json({ ok: r.ok, status: r.status, model: probe_rerank.model, body: text.slice(0, 800) })
    }

    // 생성 모델 점검. 응답 구조를 그대로 돌려준다 — 추론형 모델은 본문이 비고
    // reasoning_content에만 값이 오거나, 토큰 상한에 걸려 잘리는 경우가 있다.
    if (probe_chat) {
      const r = await fetch('https://integrate.api.nvidia.com/v1/chat/completions', {
        method: 'POST',
        headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: probe_chat.model,
          messages: [
            { role: 'system', content: '한국어로 두 문장만 쓰세요.' },
            { role: 'user', content: probe_chat.prompt || '보안 그룹에 SSH를 외부에 여는 것이 왜 위험한가요?' },
          ],
          temperature: 0.2,
          max_tokens: Number(probe_chat.max_tokens) || 400,
        }),
      })
      const text = await r.text()
      if (!r.ok) return json({ ok: false, status: r.status, error: text.slice(0, 300) })
      const j = JSON.parse(text)
      const m = j.choices?.[0]?.message || {}
      return json({
        ok: true,
        finish_reason: j.choices?.[0]?.finish_reason,
        message_keys: Object.keys(m),
        content_len: (m.content || '').length,
        content: (m.content || '').slice(0, 300),
        reasoning_len: (m.reasoning_content || '').length,
        usage: j.usage,
      })
    }

    if (probe_model) {
      const body = {
        model: probe_model,
        input: ['보안 그룹에 SSH 포트를 여는 신청'],
        input_type: 'query',
        encoding_format: 'float',
        truncate: 'END',
      }
      if (probe_dimensions) body.dimensions = Number(probe_dimensions)

      const t0 = Date.now()
      const r = await fetch(NIM_EMBED, {
        method: 'POST',
        headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const text = await r.text()
      if (!r.ok) return json({ ok: false, probe_model, status: r.status, error: text.slice(0, 300) })
      const got = JSON.parse(text).data?.[0]?.embedding
      return json({
        ok: true,
        probe_model,
        asked_dimensions: probe_dimensions,
        got_dimensions: Array.isArray(got) ? got.length : null,
        elapsed_ms: Date.now() - t0,
      })
    }

    if (!query || typeof query !== 'string') {
      return json({ ok: false, error: 'query가 필요합니다' }, 400)
    }

    const res = await fetch(NIM_EMBED, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: MODEL,
        input: [`query: ${query}`],
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
