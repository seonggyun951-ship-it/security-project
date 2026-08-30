import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

// 지식 베이스에 자료를 넣는다(임베딩 후 저장).
//
// NIM 무료 티어가 분당 40회라 한 건씩 보내면 수천 조각에 몇 시간이 걸린다.
// 임베딩 API는 한 번에 여러 개를 받으므로 묶어서 보낸다 — 호출 수가 수십 분의 1로 준다.

const NIM_EMBED = 'https://integrate.api.nvidia.com/v1/embeddings'
// 이전 모델(llama-nemotron-embed-1b-v2)은 2026-08-25 서비스 종료됐다.
// 살아 있는 임베딩 모델을 전부 호출해 확인한 뒤 이걸로 옮겼다 —
// 34개 언어, 32K 컨텍스트, RTEB 종합 1위.
const MODEL = 'nvidia/nemotron-3-embed-1b'
// 2048은 pgvector의 hnsw 색인 한계(2000)를 넘는다.
// 값은 vector(2048)로 두고 색인만 halfvec으로 캐스팅해 건다 (migrations/20260825_embed_2048.sql).
const DIMENSIONS = 2048
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

// 문서를 넣을 때는 'passage', 검색어는 'query'로 구분해야 한다.
// 이전 embedqa 계열은 input_type 파라미터로 받았지만 nemotron-3는 텍스트 앞에
// 'passage: ' / 'query: ' 접두사를 붙이는 방식이다. 빠뜨리면 검색 품질이 떨어진다.
async function embed(key: string, texts: string[], inputType: 'passage' | 'query') {
  const res = await fetch(NIM_EMBED, {
    method: 'POST',
    headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: MODEL,
      input: texts.map((t) => `${inputType}: ${t}`),
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
    const { documents, reembed = null } = await req.json()

    // 재임베딩 — 임베딩 모델을 바꿨을 때 기존 자료의 벡터만 새로 채운다.
    //
    // 자료를 원본에서 다시 긁지 않는다. content가 그대로 있으니 그걸 읽어 벡터만 만든다.
    // 외부에서 받아온 자료(KEV·MITRE)가 그사이 바뀌어 내용이 달라지는 일도 없다.
    //
    // 한 번에 다 처리하면 함수 실행 시간을 넘긴다. 정해진 만큼만 하고 남은 수를
    // 돌려주면, 부르는 쪽이 0이 될 때까지 반복하면 된다.
    if (reembed) {
      const take = Math.min(Number(reembed.limit) || 64, 256)
      const { data: rows, error: selErr } = await admin
        .from('knowledge').select('id, content').is('embedding', null).limit(take)
      if (selErr) throw selErr

      let updated = 0
      const errors = []
      for (let i = 0; i < (rows?.length ?? 0); i += BATCH_SIZE) {
        const slice = rows.slice(i, i + BATCH_SIZE)
        try {
          const vectors = await embed(key, slice.map((r) => r.content), 'passage')
          for (let j = 0; j < slice.length; j++) {
            const { error } = await admin.from('knowledge')
              .update({ embedding: vectors[j], model: MODEL }).eq('id', slice[j].id)
            if (error) errors.push(`${slice[j].id}: ${error.message}`)
            else updated++
          }
        } catch (e) {
          errors.push(String(e).slice(0, 150))
        }
        if (i + BATCH_SIZE < rows.length) await sleep(RATE_GAP_MS)
      }

      const { count: remaining } = await admin
        .from('knowledge').select('id', { count: 'exact', head: true }).is('embedding', null)

      return json({ ok: errors.length === 0, model: MODEL, updated, remaining, errors })
    }

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
