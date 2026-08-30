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
// 모델은 속도와 정확도를 재서 고른다. 값이 고정된 게 아니라 시간이 지나면 달라진다 —
// 2026-08-15에 6.5초였던 gemma-4-31b가 열흘 뒤 68초가 됐다. 느려지면 다시 재는 게 맞다.
//
// 2026-08-26 재측정. 같은 신청 건을 9개 모델에 돌린 결과:
//   gpt-oss-20b         4.3초  문장 깔끔, 근거 인용 정확          ← 선택
//   mistral-nemotron    3.6초  문단을 나눠 써서 지시를 안 지킴
//   gemma-4-31b        68.3초  전에 6.5초였는데 10배 느려졌고 문장도 깨짐("확인이 확인이")
//   llama-3.3-70b      51.8초  한국어에 중국어가 섞임("이申请을")
//   nemotron-3 계열     3~32초  사고 과정을 영어로 그대로 출력 — <think> 분리 처리가 필요
//   gpt-oss-120b        4.1초  빈 응답
// model 파라미터로 호출할 때마다 바꿀 수 있다.
const CHAT_MODEL = 'openai/gpt-oss-20b'
const EMBED_MODEL = 'nvidia/nemotron-3-embed-1b'
const DIMENSIONS = 2048

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
      // nemotron-3는 'query: ' / 'passage: ' 접두사로 검색어와 문서를 구분한다.
      body: JSON.stringify({
        model: EMBED_MODEL, input: [`query: ${queryText}`],
        encoding_format: 'float', truncate: 'END',
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
        // 억지로 끌어온 무관한 조각은 근거로 쓰지 않는다.
        //
        // 이 값은 임베딩 모델에 딸려 있다. 모델을 바꾸면 점수 분포가 통째로 달라지므로
        // 다시 재야 한다. 이전 모델에서는 0.15였는데 nemotron-3에서는 전반적으로 낮게 나온다.
        //
        // 2026-08-26 측정 (질문 3개 × 출처 6개):
        //   관련 있는 것  0.20 ~ 0.44
        //   애매한 것     0.14 ~ 0.17
        //   무관한 것     0.06 ~ 0.13  (예: 루트 MFA 질문에 policy 0.067, rule_engine 0.075)
        // 무관한 무리의 위, 애매한 무리의 아래인 0.12로 잡았다.
        min_similarity: 0.12,
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
      '2. "규칙 엔진 판정"에 적힌 내용은 확인된 사실입니다. 그와 다른 상태를 가정하지 마세요.',
      '   참고 자료가 다른 얘기를 하더라도 판정 쪽이 지금 이 건의 실제 상태입니다.',
      '   ("MFA가 없습니다"라고 적혀 있으면 있다고 바꿔 쓰면 안 됩니다.)',
      '3. 참고 자료에 없는 내용은 지어내지 마세요. 자료가 부족하면 부족하다고 쓰세요.',
      '4. 한국어로, 3~5문장으로 짧게 씁니다. 목록·제목·굵은 글씨 없이 문장만 쓰세요.',
      '5. 왜 그런 판정이 나왔는지와, 무엇을 고치면 되는지를 담으세요.',
      '6. 읽는 사람이 신청자일 수도 관리자일 수도 있습니다. 용어를 늘어놓지 말고,',
      '   무엇이 어떤 상태이고 어떻게 하면 되는지를 담백하게 설명하세요.',
      '7. 참고한 자료가 있으면 문장 끝에 [T1021.004] 같은 식별자를 붙이세요.',
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
        // gpt-oss는 추론형이라 답을 쓰기 전에 reasoning_content로 400~500자를 먼저 쓴다.
        // 그 몫까지 계산해서 넉넉히 준다. 400으로 두면 추론에 다 먹혀 본문이 빈 채로 온다
        // (설명이 안 보이는데 오류도 안 나서 원인을 찾기 어렵다).
        max_tokens: 1200,
      }),
    })
    if (!chatRes.ok) {
      const d = await chatRes.text().catch(() => '')
      throw new Error(`설명 생성 실패 (${chatRes.status}): ${d.slice(0, 200)}`)
    }
    const chat = await chatRes.json()
    const explanation = chat.choices?.[0]?.message?.content?.trim() || ''
    // 빈 본문을 그대로 내보내면 화면에 아무것도 안 뜨고 원인도 안 보인다.
    // 토큰이 모자라 잘렸는지(length) 다른 이유인지 알 수 있게 남긴다.
    if (!explanation) {
      throw new Error(`설명이 비어 있습니다 (finish_reason: ${chat.choices?.[0]?.finish_reason}, `
        + `완성 토큰: ${chat.usage?.completion_tokens})`)
    }

    return json({
      ok: true,
      explanation,
      model,
      // 무엇을 보고 쓴 설명인지 함께 돌려준다. 화면에서 근거를 펼쳐볼 수 있어야
      // 이상한 답이 나왔을 때 어디서 온 것인지 추적할 수 있다.
      // 식별자만 돌려주면 무엇을 보고 쓴 설명인지 알 수 없다(T1021.004가 무슨 내용인지
      // 아는 사람은 없다). 첫 줄을 제목으로, 그 뒤를 발췌로 함께 보낸다.
      sources: groups.flatMap((g) => g.docs.map((d) => {
        const lines = String(d.content || '').split('\n').map((s) => s.trim()).filter(Boolean)
        return {
          source: d.source,
          ref: d.ref,
          similarity: Number(d.similarity?.toFixed(3)),
          title: lines[0]?.slice(0, 120) || '',
          excerpt: lines.slice(1).join(' ').slice(0, 220),
        }
      })),
      usage: chat.usage ?? null,
    })
  } catch (e) {
    console.error('rag-explain error:', e)
    return json({ ok: false, error: String(e) }, 500)
  }
})
