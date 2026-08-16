import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

// 지식 베이스에 자료를 넣는다(임베딩 후 저장).
//
// NIM 무료 티어가 분당 40회라 한 건씩 보내면 수천 조각에 몇 시간이 걸린다.
// 임베딩 API는 한 번에 여러 개를 받으므로 묶어서 보낸다 — 호출 수가 수십 분의 1로 준다.

const NIM_EMBED = 'https://integrate.api.nvidia.com/v1/embeddings'
const MODEL = 'nvidia/llama-nemotron-embed-1b-v2'
const DIMENSIONS = 1024        // pgvector 인덱스 한계(2000)에 맞춘 값
const BATCH_SIZE = 32          // 한 번에 임베딩할 조각 수
const RATE_GAP_MS = 1600       // 분당 40회 제한을 넘지 않도록 호출 사이 간격

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}
const json = (body, status = 200) => new Response(JSON.stringify(body), {
  headers: { ...cors, 'Content-Type': 'application/json' }, status,
})

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// Deno의 WebCrypto는 MD5를 지원하지 않는다. 중복 판별용이라 SHA-256이면 충분하다.
async function hashOf(text: string) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

// 문서를 넣을 때는 'passage', 검색어는 'query'로 넣어야 한다.
// embedqa 계열은 이 구분이 성능에 직접 영향을 준다.
async function embed(key: string, texts: string[], inputType: 'passage' | 'query') {
  const res = await fetch(NIM_EMBED, {
    method: 'POST',
    headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: MODEL,
      input: texts,
      input_type: inputType,
      dimensions: DIMENSIONS,
      encoding_format: 'float',
      truncate: 'END',
    }),
  })
  if (!res.ok) {
    const detail = await res.text().catch(() => '')
    throw new Error(`임베딩 실패 (${res.status}): ${detail.slice(0, 200)}`)
  }
  const j = await res.json()
  return j.data.map((d: { embedding: number[] }) => d.embedding)
}

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })

  try {
    // 적재는 관리자만. 지식 베이스가 곧 LLM이 근거로 삼는 자료라 아무나 넣으면 안 된다.
    //
    // 두 경로를 받는다:
    //   관리자 로그인 토큰 — 화면에서 부르는 경우
    //   service_role 키   — 자료를 대량으로 밀어넣는 배치 스크립트
    // MITRE/OWASP 적재는 수천 건짜리 배치라 브라우저에서 돌릴 일이 아니다.
    const url = Deno.env.get('SUPABASE_URL')!
    const authHeader = req.headers.get('Authorization') || ''
    const token = authHeader.replace('Bearer ', '')

    const userClient = createClient(url, Deno.env.get('SUPABASE_ANON_KEY')!, {
      global: { headers: { Authorization: authHeader } },
    })
    const { data: { user } } = await userClient.auth.getUser(token)

    let admin
    if (user) {
      // 사람이 화면에서 부른 경우 — 관리자인지 확인한다
      admin = createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!)
      const { data: adminRow } = await admin
        .from('admins').select('user_id').eq('user_id', user.id).maybeSingle()
      if (!adminRow) return json({ ok: false, error: '관리자만 사용할 수 있습니다' }, 403)
    } else {
      // 사용자 토큰이 아니면 배치 스크립트의 서비스 키로 본다.
      // 키 문자열을 직접 비교하지 않고, 받은 키로 클라이언트를 만들어 RLS가 판단하게 한다.
      // knowledge에는 insert 정책이 없어 service_role이 아니면 아래 upsert에서 막힌다.
      if (!token) return json({ ok: false, error: '인증이 필요합니다' }, 401)
      admin = createClient(url, token)
    }

    const key = Deno.env.get('NIM_API_KEY')
    if (!key) return json({ ok: false, error: 'NIM_API_KEY가 설정되지 않았습니다' }, 500)

    // documents: [{ content, source, ref?, meta? }]
    const { documents } = await req.json()
    if (!Array.isArray(documents) || documents.length === 0) {
      return json({ ok: false, error: 'documents 배열이 필요합니다' }, 400)
    }

    const prepared = []
    for (const d of documents) {
      if (!d?.content || !d?.source) continue
      prepared.push({
        content: String(d.content),
        source: String(d.source),
        ref: d.ref ? String(d.ref) : null,
        meta: d.meta ?? {},
        model: MODEL,
        content_hash: await hashOf(String(d.content)),
      })
    }
    if (prepared.length === 0) return json({ ok: false, error: '넣을 자료가 없습니다' }, 400)

    let inserted = 0
    const failures = []

    for (let i = 0; i < prepared.length; i += BATCH_SIZE) {
      const batch = prepared.slice(i, i + BATCH_SIZE)
      try {
        const vectors = await embed(key, batch.map((b) => b.content), 'passage')
        const rows = batch.map((b, n) => ({ ...b, embedding: JSON.stringify(vectors[n]) }))

        // 같은 자료를 다시 넣으면 새로 만들지 않고 갱신한다.
        // 적재 스크립트를 여러 번 돌려도 중복이 쌓이지 않아야 한다.
        const { error } = await admin
          .from('knowledge')
          .upsert(rows, { onConflict: 'source,content_hash' })
        if (error) throw error
        inserted += rows.length
      } catch (e) {
        console.error(`배치 실패 (${i}~${i + batch.length}):`, e)
        failures.push({ from: i, count: batch.length, error: String(e).slice(0, 200) })
      }

      // 마지막 배치 뒤에는 쉴 필요가 없다
      if (i + BATCH_SIZE < prepared.length) await sleep(RATE_GAP_MS)
    }

    return json({
      ok: failures.length === 0,
      model: MODEL,
      dimensions: DIMENSIONS,
      received: documents.length,
      inserted,
      failures,
    })
  } catch (e) {
    console.error('rag-index error:', e)
    return json({ ok: false, error: String(e) }, 500)
  }
})
