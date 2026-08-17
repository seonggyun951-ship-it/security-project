import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

// 규칙 엔진의 판정을 자연어로 풀어 설명한다.
//
// 판정은 하지 않는다. 위험한지 아닌지는 이미 규칙 엔진이 정했고, 여기서는 그 결론을
// 근거와 함께 읽기 쉽게 옮길 뿐이다. LLM에게 판단을 맡기면 같은 신청에 매번 다른
// 답이 나오고, 무엇을 근거로 그렇게 말했는지도 알 수 없게 된다.
//
// 규칙 로직을 이 함수에 두지 않는 이유도 같다. 화면(rules.js)과 두 벌이 되면
// 한쪽만 고쳐져 어긋난다. 판정 결과는 호출하는 쪽에서 넘겨받는다.

const NIM_CHAT = 'https://integrate.api.nvidia.com/v1/chat/completions'
const NIM_EMBED = 'https://integrate.api.nvidia.com/v1/embeddings'
// 모델은 속도와 정확도를 재서 골랐다.
//   llama-3.3-70b      63초  — 품질은 좋으나 화면에서 기다릴 수 없다
//   nemotron-nano-8b   타임아웃
//   llama-3.1-8b        4.6초 — 빠르지만 문장이 반복되고 앞뒤가 맞지 않았다
//   mistral-nemotron    4.3초 — 무난
//   gemma-4-31b         6.5초 — 근거 인용이 정확하고 판정을 뒤집지 않는다  ← 선택
// model 파라미터로 호출할 때마다 바꿀 수 있다.
const CHAT_MODEL = 'google/gemma-4-31b-it'
const EMBED_MODEL = 'nvidia/llama-nemotron-embed-1b-v2'
const DIMENSIONS = 1024

// 출처를 섞어서 한 번에 뽑으면 규칙 엔진 문서가 상위를 다 차지한다.
// 한국어라 한국어 질문과 가깝기 때문이다. 출처별로 따로 뽑아야 관점이 골고루 들어온다.
const RETRIEVE = [
  { source: 'rule_engine', count: 2, label: '비슷한 신청의 판정 사례' },
  { source: 'policy', count: 2, label: '우리 시스템의 정책' },
  { source: 'concept', count: 2, label: '관련 개념 (AWS 공식 문서)' },
  { source: 'aws_baseline', count: 2, label: 'AWS 보안 기준' },
  { source: 'gcp_baseline', count: 1, label: 'GCP 보안 기준' },
  { source: 'mitre', count: 1, label: '공격 기법 (MITRE ATT&CK)' },
  { source: 'mitigation', count: 1, label: '막는 방법 (MITRE 완화책)' },
  { source: 'owasp', count: 1, label: '보안 원칙 (OWASP)' },
]

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

    const db = createClient(url, Deno.env.get('SUPABASE_ANON_KEY')!, {
      global: { headers: { Authorization: authHeader } },
    })
    const { data: { user } } = await db.auth.getUser(token)
    const client = user ? db : createClient(url, token)

    const key = Deno.env.get('NIM_API_KEY')
    if (!key) return json({ ok: false, error: 'NIM_API_KEY가 설정되지 않았습니다' }, 500)

    // summary  : 무엇을 신청했는지 (한 줄)
    // findings : 규칙 엔진이 이미 내린 판정 [{ severity, title, why }]
    // verdict  : 'reject' | 'warn' | 'pass' (있으면 문장에 반영한다)
    const { summary, findings = [], verdict = null, question = null, model = CHAT_MODEL } = await req.json()
    if (!summary && !question) {
      return json({ ok: false, error: 'summary 또는 question이 필요합니다' }, 400)
    }

    // 검색어는 신청 내용과 판정 사유를 합쳐 만든다.
    // 판정 사유에 '위험 포트 22(SSH)' 같은 핵심어가 들어 있어 검색이 잘 걸린다.
    const queryText = [
      question || summary,
      ...findings.slice(0, 4).map((f) => f.title),
    ].filter(Boolean).join(' ')

    const embedRes = await fetch(NIM_EMBED, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: EMBED_MODEL, input: [queryText], input_type: 'query',
        dimensions: DIMENSIONS, encoding_format: 'float', truncate: 'END',
      }),
    })
    if (!embedRes.ok) {
      const d = await embedRes.text().catch(() => '')
      throw new Error(`임베딩 실패 (${embedRes.status}): ${d.slice(0, 200)}`)
    }
    const embedding = JSON.stringify((await embedRes.json()).data[0].embedding)

    const groups = await Promise.all(RETRIEVE.map(async (r) => {
      const { data, error } = await client.rpc('match_knowledge', {
        query_embedding: embedding,
        match_count: r.count,
        filter_sources: [r.source],
        min_similarity: 0.15, // 억지로 끌어온 무관한 조각은 근거로 쓰지 않는다
      })
      if (error) throw error
      return { ...r, docs: data ?? [] }
    }))

    // 조각을 통째로 넣으면 프롬프트가 커지고 생성이 그만큼 느려진다.
    // 설명 3~5문장에 필요한 건 앞부분이라 잘라 쓴다.
    const EXCERPT = 500
    const context = groups
      .filter((g) => g.docs.length > 0)
      .map((g) => `## ${g.label}\n` + g.docs
        .map((d) => `[${d.ref}] ${String(d.content).slice(0, EXCERPT)}`)
        .join('\n\n'))
      .join('\n\n')

    const verdictKo = { reject: '반려', warn: '주의 — 관리자 확인 필요', pass: '통과' }[verdict] || null
    const findingText = findings.length > 0
      ? findings.map((f) => `- (${f.severity}) ${f.title}: ${f.why || ''}`).join('\n')
      : '(규칙 엔진이 지적한 항목 없음)'

    const system = [
      '당신은 AWS 보안 신청을 검토하는 담당자를 돕는 조수입니다.',
      '',
      '지켜야 할 것:',
      '1. 위험도 판정은 이미 규칙 엔진이 내렸습니다. 판정을 바꾸거나 새로 매기지 마세요.',
      '2. 아래 참고 자료에 없는 내용은 지어내지 마세요. 자료가 부족하면 부족하다고 쓰세요.',
      '3. 한국어로, 3~5문장으로 짧게 씁니다. 목록이나 제목은 쓰지 마세요.',
      '4. 왜 그런 판정이 나왔는지와, 신청자가 무엇을 고치면 되는지를 담으세요.',
      '5. 참고한 자료가 있으면 문장 끝에 [T1021.004] 같은 식별자를 붙이세요.',
    ].join('\n')

    const userPrompt = [
      `신청 내용: ${summary || question}`,
      verdictKo ? `처리 결과: ${verdictKo}` : null,
      '',
      '규칙 엔진 판정:',
      findingText,
      '',
      '참고 자료:',
      context || '(관련 자료를 찾지 못했습니다)',
    ].filter((x) => x !== null).join('\n')

    const chatRes = await fetch(NIM_CHAT, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0.2, // 같은 신청에는 비슷한 답이 나와야 한다
        max_tokens: 400,
      }),
    })
    if (!chatRes.ok) {
      const d = await chatRes.text().catch(() => '')
      throw new Error(`설명 생성 실패 (${chatRes.status}): ${d.slice(0, 200)}`)
    }
    const chat = await chatRes.json()
    const explanation = chat.choices?.[0]?.message?.content?.trim() || ''

    return json({
      ok: true,
      explanation,
      model,
      // 무엇을 보고 쓴 설명인지 함께 돌려준다. 화면에서 근거를 펼쳐볼 수 있어야
      // 이상한 답이 나왔을 때 어디서 온 것인지 추적할 수 있다.
      sources: groups.flatMap((g) => g.docs.map((d) => ({
        source: d.source, ref: d.ref, similarity: Number(d.similarity?.toFixed(3)),
      }))),
      usage: chat.usage ?? null,
    })
  } catch (e) {
    console.error('rag-explain error:', e)
    return json({ ok: false, error: String(e) }, 500)
  }
})
