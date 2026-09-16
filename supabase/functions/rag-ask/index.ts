import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

// 자유 질의 — 지식 베이스 전체에 대해 물으면 근거를 인용해 답한다.
//
// rag-explain과 나눈 이유:
//   rag-explain은 '신청 하나를 설명'하는 데 최적화돼 있다. 판정 사유를 받아
//   그걸 풀어 쓰고, 검색 출처도 신청 검토에 필요한 것만(정책·기준·공격기법) 본다.
//   자유 질문("우리 개인정보 DB는 어떻게 접근해?")을 거기 넣으면 두 가지가 어긋난다:
//     1. virtual_infra(우리 설계) 같은 출처가 검색 대상에 없어 우리 얘기가 안 나온다.
//     2. "제출된 자료에서 위반이 발견되지 않았습니다" 같은 신청-검토 말투로 답한다.
//   그래서 검색 범위와 프롬프트만 질의용으로 바꾼 함수를 따로 둔다. 생성 뼈대는 같다.

const NIM_CHAT = 'https://integrate.api.nvidia.com/v1/chat/completions'
const NIM_EMBED = 'https://integrate.api.nvidia.com/v1/embeddings'
const CHAT_MODEL = 'openai/gpt-oss-20b'
const EMBED_MODEL = 'nvidia/nemotron-3-embed-1b'

// 자유 질의는 어느 출처가 답일지 미리 알 수 없다. 섞어서 상위 N개를 뽑되,
// 우리 설계(virtual_infra)와 정책(policy)은 '우리 회사'를 묻는 질문에서 묻히기 쉬워
// (KEV·MITRE 같은 큰 사전이 상위를 차지한다) 최소 몇 건은 따로 확보한다.
//   floor: 이 출처에서 최소 이만큼은 본다(관련도가 낮아도)
const PRIORITY = [
  { source: 'virtual_infra', floor: 3, min: 0.20 },
  { source: 'policy',        floor: 2, min: 0.20 },
]
const MIX_COUNT = 8   // 나머지는 전 출처 섞어서 상위 이만큼
const MIX_MIN = 0.30

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}
const json = (b: unknown, status = 200) =>
  new Response(JSON.stringify(b), { headers: { ...cors, 'Content-Type': 'application/json' }, status })

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })

  try {
    const url = Deno.env.get('SUPABASE_URL')!
    const authHeader = req.headers.get('Authorization') || ''
    const token = authHeader.replace('Bearer ', '')
    if (!token) return json({ ok: false, error: '로그인이 필요합니다' }, 401)

    // 검색은 로그인만 하면 된다. 담긴 자료가 공개 보안 문서와 우리 설계라 계정별로 가릴 게 없다.
    const db = createClient(url, Deno.env.get('SUPABASE_ANON_KEY')!, {
      global: { headers: { Authorization: authHeader } },
    })
    const { data: { user } } = await db.auth.getUser(token)
    const client = user ? db : createClient(url, token)

    const key = Deno.env.get('NIM_API_KEY')
    if (!key) return json({ ok: false, error: 'NIM_API_KEY가 설정되지 않았습니다' }, 500)

    const { question, model = CHAT_MODEL } = await req.json()
    if (!question || !String(question).trim()) {
      return json({ ok: false, error: 'question이 필요합니다' }, 400)
    }

    // 1) 질문을 임베딩
    const embedRes = await fetch(NIM_EMBED, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: EMBED_MODEL, input: [`query: ${question}`],
        encoding_format: 'float', truncate: 'END',
      }),
    })
    if (!embedRes.ok) {
      const d = await embedRes.text().catch(() => '')
      throw new Error(`임베딩 실패 (${embedRes.status}): ${d.slice(0, 200)}`)
    }
    const embedding = JSON.stringify((await embedRes.json()).data[0].embedding)

    // 2) 검색 — 우선 출처는 따로 확보하고, 나머지는 전 출처 섞어서 상위.
    const seen = new Set<string>()   // 같은 문서가 두 번 안 들어가게 (source|ref)
    const collected: Array<Record<string, unknown>> = []

    const take = (rows: Array<Record<string, unknown>> | null) => {
      for (const d of rows ?? []) {
        const k = `${d.source}|${d.ref}`
        if (seen.has(k)) continue
        seen.add(k)
        collected.push(d)
      }
    }

    // 우선 출처
    for (const p of PRIORITY) {
      const { data, error } = await client.rpc('match_knowledge', {
        query_embedding: embedding,
        match_count: p.floor,
        filter_sources: [p.source],
        min_similarity: p.min,
      })
      if (error) throw error
      take(data)
    }
    // 전 출처 섞어서
    const { data: mixed, error: mixErr } = await client.rpc('match_knowledge', {
      query_embedding: embedding,
      match_count: MIX_COUNT,
      filter_sources: null,
      min_similarity: MIX_MIN,
    })
    if (mixErr) throw mixErr
    take(mixed)

    if (collected.length === 0) {
      return json({
        ok: true,
        answer: '관련된 자료를 찾지 못했습니다. 질문을 조금 더 구체적으로 적어 주세요.',
        sources: [],
      })
    }

    // 3) 프롬프트 — 자유 질의용. 근거에 없으면 지어내지 말 것.
    const EXCERPT = 600
    const context = collected
      .map((d) => `[${d.source} · ${d.ref}] ${String(d.content).slice(0, EXCERPT)}`)
      .join('\n\n')

    const system = [
      '당신은 이 회사의 클라우드 보안·인프라에 대해 답하는 조수입니다.',
      '읽는 사람은 이 분야를 잘 모를 수 있습니다. 인증기준 번호를 늘어놓지 말고,',
      '우리가 실제로 무엇을 어떻게 하는지가 먼저 이해되게 쓰세요.',
      '',
      '지켜야 할 것:',
      '1. 아래 "참고 자료"에 있는 내용만으로 답하세요. 자료에 없으면 지어내지 말고',
      '   "자료에 없습니다"라고 쓰세요.',
      '2. 우리 회사 질문이면 우리 설계(virtual_infra)·정책(policy)에 있는 "우리가 하는 것"을',
      '   먼저, 구체적으로 씁니다(예: vpc-pii 10.99에 격리, PrivateLink+DB SAFER로만 접근,',
      '   접속기록 2년 보관). 그게 왜 그런지는 뒤에 자연스럽게 한 문장으로 엮으세요.',
      '3. 인증기준(ISMS-P 등)은 근거로만 쓰되, "2.6.4에 따라 ~해야 한다"처럼 조항을 주어로',
      '   삼지 마세요. 조항 번호를 여러 개 나열하지 마세요. 우리 조치를 설명하고, 필요하면',
      '   "이는 개인정보처리시스템의 접근통제·기록 요구를 충족한다" 정도로만 언급합니다.',
      '4. 한국어로, 핵심부터 3~5문장. 목록·제목·굵은 글씨 없이 문장으로만.',
      '5. 문장 끝이나 본문 어디에도 [출처]·[ismsp 2.6.4] 같은 대괄호 인용을 붙이지 마세요.',
      '   근거 출처는 화면이 답변 아래에 따로 보여줍니다. 본문은 인용 없이 깔끔하게 쓰세요.',
    ].join('\n')

    const userPrompt = [
      `질문: ${question}`,
      '',
      '참고 자료:',
      context,
    ].join('\n')

    const chatRes = await fetch(NIM_CHAT, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: system },
          { role: 'user', content: userPrompt },
        ],
        temperature: 0.2,
        max_tokens: 1400,   // gpt-oss는 본문 전에 추론을 먼저 써서 넉넉히 준다
      }),
    })
    if (!chatRes.ok) {
      const d = await chatRes.text().catch(() => '')
      throw new Error(`답변 생성 실패 (${chatRes.status}): ${d.slice(0, 200)}`)
    }
    const chat = await chatRes.json()
    let answer = chat.choices?.[0]?.message?.content?.trim() || ''
    // 프롬프트로 막았지만 모델이 습관적으로 붙이는 대괄호 인용을 한 번 더 걷어낸다.
    // [ismsp · 2.6.4 …], [virtual_infra · vinfra-…] 처럼 출처를 가리키는 것만 지운다.
    answer = answer
      // 출처를 가리키는 대괄호 인용
      .replace(/\s*\[(?:ismsp|virtual_infra|policy|rule_engine|aws_baseline|gcp_baseline|mitre|owasp|mitigation|kev|concept)\b[^\]]*\]/gi, '')
      // **굵은 제목** 같은 마크다운 — 화면이 평문으로 그리므로 별표만 남는다
      .replace(/^\s*#{1,6}\s*/gm, '')
      .replace(/\*\*([^*]+)\*\*/g, '$1')
      // 답을 다 해놓고 습관적으로 끝에 붙이는 '출처'/'자료에 없습니다' 블록.
      // 근거는 아래 배지가 담당하므로 본문 끝의 이런 꼬리는 지운다.
      .replace(/\n+\s*(출처|근거|참고\s*자료|자료에 없습니다)[:\s].*$/is, '')
      .replace(/\n+\s*(출처|근거|참고\s*자료|자료에 없습니다)\s*$/i, '')
      .replace(/[ \t]{2,}/g, ' ')
      .replace(/[ \t]+\n/g, '\n')
      .replace(/\n{3,}/g, '\n\n')
      .trim()
    if (!answer) {
      throw new Error(`답변이 비어 있습니다 (finish_reason: ${chat.choices?.[0]?.finish_reason}, `
        + `완성 토큰: ${chat.usage?.completion_tokens})`)
    }

    // 4) 출처 목록 — 화면이 근거로 보여준다
    const sources = collected.map((d) => {
      const first = String(d.content || '').split('\n').map((s) => s.trim()).filter(Boolean)[0] || ''
      return {
        source: d.source,
        ref: d.ref,
        similarity: d.similarity ?? null,
        title: first.slice(0, 80),
      }
    })

    return json({ ok: true, question, answer, model, sources })
  } catch (e) {
    console.error('rag-ask error:', e)
    return json({ ok: false, error: String(e instanceof Error ? e.message : e) }, 500)
  }
})
