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

// 출처를 섞어서 한 번에 뽑으면 규칙 엔진과 AWS 기준이 상위를 다 차지한다.
// 질문과 같은 층위(구체적인 설정)라 점수가 높기 때문이다. 출처별로 따로 뽑아야
// 관점이 골고루 들어온다.
//
// min은 출처마다 다르다. 하나의 값으로는 가를 수 없다는 걸 측정으로 확인했다:
//   MFA 질문  → rule_engine 1위 's3-no-encryption'  0.219  (무관)
//   NACL 질문 → ismsp 1위 '2.6.1 네트워크 접근'      0.228  (정답)
// 점수가 거의 같은데 하나는 쓰레기이고 하나는 정답이다. 다만 같은 출처 안에서는
// 관련과 무관이 잘 갈려서, 출처별로 자르면 대부분 걸러진다.
//
// 2026-09-02 측정 (질의 6개 × 출처별 상위 4건). 각 출처의 '무관한 1위'와
// '관련 있는 1위' 사이에 값을 뒀다:
//   rule_engine   무관 0.166~0.219 · 관련 0.533~0.695
//   aws_baseline  무관 0.285       · 관련 0.404~0.733
//   concept       무관 0.139~0.230 · 관련 0.368~0.558
//   policy        무관 0.145~0.213 · 관련 0.382~0.499
//   gcp_baseline  무관 0.242~0.254 · 관련 0.468~0.604
//   mitigation    무관 0.222(M1055 '완화 불가') · 관련 0.378(M1032 다중 인증)
//   ismsp         무관 0.146~0.183 · 관련 0.228~0.486
//
// mitre와 owasp는 이 방법으로 못 가른다 — 관련(0.340~0.364)과 무관(0.286~0.339)이
// 같은 구간에 있고, owasp는 A10 SSRF 0.319(무관)와 A01 0.320(관련)이 붙어 있다.
// 임계값을 올리면 맞는 것까지 잘리므로 낮게 두고 다른 방법을 찾아야 한다.
//
// 모델을 바꾸면 점수 분포가 통째로 달라지므로 이 값들을 다시 재야 한다.
const RETRIEVE = [
  { source: 'rule_engine',  count: 2, min: 0.35, label: '비슷한 신청의 판정 사례' },
  { source: 'policy',       count: 2, min: 0.25, label: '우리 시스템의 정책' },
  { source: 'concept',      count: 2, min: 0.25, label: '관련 개념 (AWS 공식 문서)' },
  { source: 'aws_baseline', count: 2, min: 0.35, label: 'AWS 보안 기준' },
  { source: 'gcp_baseline', count: 1, min: 0.30, label: 'GCP 보안 기준' },
  { source: 'ismsp',        count: 2, min: 0.22, label: '국내 인증기준 (ISMS-P)' },
  { source: 'mitre',        count: 1, min: 0.30, label: '공격 기법 (MITRE ATT&CK)' },
  { source: 'mitigation',   count: 1, min: 0.30, label: '막는 방법 (MITRE 완화책)' },
  { source: 'owasp',        count: 1, min: 0.25, label: '보안 원칙 (OWASP)' },
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
    const {
      summary, findings = [], verdict = null, question = null, model = CHAT_MODEL,
      // 화면이 짚어 준 근거. { ismsp: ['2.6.6'], mitre: ['T1021.004'], owasp: [...] }
      // 있으면 그 출처는 검색하지 않고 이쪽을 그대로 쓴다.
      pinned_refs = null,
      // 예전 이름. 인증기준만 넘기던 시절의 호출을 위해 남겨 둔다.
      ismsp_refs = null,
    } = await req.json()
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

    // 화면이 근거를 지정해 보낸 경우, 그 출처는 검색하지 않고 그대로 가져온다.
    //
    // 체크와 근거의 대응은 src/lib/scan.js의 ISMSP_MAP·ATTACK_MAP·OWASP_MAP에
    // 손으로 맞춰 두었다. 유사도로 더듬으면 관련 있는 것과 없는 것이 같은
    // 점수대(0.29~0.36)에 섞여 나온다. 특히 MITRE는 '공격자가 하는 행위'를 적은 것이라
    // 어휘가 겹쳐도 방향이 반대인 기법이 잘 걸린다(방화벽이 열림 → '방화벽을 끄는' 기법).
    // 아는 답이 있으면 찾지 않는다.
    //
    // 표를 여기에 복사해 두지 않는 이유: 두 벌이 되면 한쪽만 고쳐져 화면과 설명이 갈라진다.
    const pins: Record<string, string[]> = {}
    if (pinned_refs && typeof pinned_refs === 'object') {
      for (const [src, refs] of Object.entries(pinned_refs)) {
        if (Array.isArray(refs)) pins[src] = refs.filter((v) => typeof v === 'string')
      }
    } else if (Array.isArray(ismsp_refs)) {
      pins.ismsp = ismsp_refs.filter((v: unknown) => typeof v === 'string')
    }

    // ISMS-P는 항목 번호로, 나머지는 ref로 찾는다. 저장할 때 ref를 '2.6.1 네트워크 접근'
    // 형태로 만들어 두어서 번호만으로는 안 맞기 때문이다.
    const pinnedBySource: Record<string, Array<Record<string, unknown>>> = {}
    await Promise.all(Object.entries(pins).map(async ([src, refs]) => {
      // 빈 배열은 '아직 안 정함'이 아니라 '살펴봤고 대응이 없다'는 뜻이다.
      // 그때 검색으로 되돌리면 표에서 일부러 뺀 근거가 도로 딸려 들어온다
      // (SSH 개방에 OWASP를 비워 뒀는데 'A05 Description'이 실려 오던 문제).
      pinnedBySource[src] = []
      if (!refs?.length) return
      // source까지 가져와야 한다. 응답의 출처 목록이 이 값을 그대로 쓴다.
      // 검색 결과와 달리 similarity가 없는데, 유사도로 고른 게 아니라 표가 지정한 것이라
      // 점수라는 개념 자체가 없다. 화면에서는 빈 값으로 나간다.
      const q = client.from('knowledge').select('source, ref, content, meta').eq('source', src)
      const { data, error } = await (src === 'ismsp'
        ? q.in('meta->>no', refs)
        : q.in('ref', refs))
      if (error) throw error
      pinnedBySource[src] = data ?? []
    }))

    const groups = await Promise.all(RETRIEVE.map(async (r) => {
      // 표가 그 출처를 다뤘으면 검색하지 않는다. 빈 배열도 표의 결론이므로 그대로 따른다.
      if (r.source in pinnedBySource) return { ...r, docs: pinnedBySource[r.source] }
      const { data, error } = await client.rpc('match_knowledge', {
        query_embedding: embedding,
        match_count: r.count,
        filter_sources: [r.source],
        // 억지로 끌어온 무관한 조각은 근거로 쓰지 않는다.
        // 기준값은 출처마다 다르다 — 근거와 측정값은 RETRIEVE 위 주석에 있다.
        min_similarity: r.min,
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
        // 출처 표시는 발췌에서 잘려 나간다(문서 끝에 있는데 발췌는 앞 220자다).
        // ISMS-P 안내서가 "가공·인용할 때는 출처를 밝혀" 달라고 요구하므로
        // 따로 뽑아 화면이 항상 보여줄 수 있게 한다.
        const noteAt = lines.findIndex((l) => l.startsWith('출처:'))
        const body = noteAt >= 0 ? lines.slice(1, noteAt) : lines.slice(1)
        return {
          source: d.source,
          ref: d.ref,
          similarity: Number(d.similarity?.toFixed(3)),
          title: lines[0]?.slice(0, 120) || '',
          excerpt: body.join(' ').slice(0, 220),
          note: noteAt >= 0 ? lines[noteAt] : null,
        }
      })),
      usage: chat.usage ?? null,
    })
  } catch (e) {
    console.error('rag-explain error:', e)
    return json({ ok: false, error: String(e) }, 500)
  }
})
