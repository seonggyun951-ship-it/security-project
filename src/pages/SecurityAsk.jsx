import { useState, useRef, useEffect } from 'react'
import { callFunction } from '../lib/db'

// 보안 질의 — 지식 베이스 전체(우리 설계 + 국내 인증기준 + 공개 보안 문서)에
// 자유롭게 묻고 근거와 함께 답을 받는다. 답은 rag-ask 함수가 만든다.
//
// 판정이 아니라 '설명'이다. 신청 판정은 규칙 엔진이 하고, 여기서는 물으면 답할 뿐이다.

// 처음 온 사람이 뭘 물어야 할지 알 수 있게. 실제로 답이 잘 나오는 것들로.
const SAMPLES = [
  '개인정보 DB는 어떻게 접근하나요?',
  'prod가 밖으로 나가는 IP가 뭐예요?',
  'dev 환경은 인터넷에서 접속되나요?',
  '개인정보 접속기록은 몇 년 보관하나요?',
  'AWS랑 GCP는 어떻게 연결돼요?',
]

// 출처 배지 색 — 우리 것(설계·정책)과 참고(공개 기준)를 눈으로 가른다.
const SOURCE_META = {
  virtual_infra: { label: '우리 설계', cls: 'ours' },
  policy:        { label: '우리 정책', cls: 'ours' },
  rule_engine:   { label: '판정 사례', cls: 'ours' },
  ismsp:         { label: 'ISMS-P', cls: 'ref' },
  aws_baseline:  { label: 'AWS 기준', cls: 'ref' },
  gcp_baseline:  { label: 'GCP 기준', cls: 'ref' },
  mitre:         { label: 'MITRE', cls: 'ref' },
  owasp:         { label: 'OWASP', cls: 'ref' },
  mitigation:    { label: '완화책', cls: 'ref' },
  kev:           { label: 'KEV', cls: 'ref' },
  concept:       { label: '개념', cls: 'ref' },
}
const srcMeta = (s) => SOURCE_META[s] || { label: s, cls: 'ref' }

export default function SecurityAsk() {
  const [turns, setTurns] = useState([])   // { q, answer, sources, error, loading }
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const endRef = useRef(null)

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [turns])

  const ask = async (q) => {
    const question = (q ?? input).trim()
    if (!question || busy) return
    setInput('')
    setBusy(true)
    const idx = turns.length
    setTurns((prev) => [...prev, { q: question, loading: true }])

    const data = await callFunction('rag-ask', { question })
    setTurns((prev) => prev.map((t, i) => i !== idx ? t : (
      data.ok
        ? { q: question, answer: data.answer, sources: data.sources || [] }
        : { q: question, error: data.error || '답변을 가져오지 못했습니다' }
    )))
    setBusy(false)
  }

  return (
    <div className="ask-page">
      <div className="ask-head">
        <h2 className="ac-title">보안 질의</h2>
        <p className="ac-sub">
          우리 클라우드 설계와 정책, 국내 인증기준(ISMS-P)·공개 보안 문서에 근거해 답합니다.
          자유롭게 물어보세요.
        </p>
      </div>

      <div className="ask-thread">
        {turns.length === 0 && (
          <div className="ask-empty">
            <div className="ask-empty-t">이런 걸 물어볼 수 있어요</div>
            <div className="ask-samples">
              {SAMPLES.map((s) => (
                <button key={s} className="ask-sample" onClick={() => ask(s)}>{s}</button>
              ))}
            </div>
          </div>
        )}

        {turns.map((t, i) => (
          <div key={i} className="ask-turn">
            <div className="ask-q"><span className="ask-q-ic">나</span><span>{t.q}</span></div>

            {t.loading && <div className="ask-a ask-loading">근거를 찾아 답을 만드는 중…</div>}

            {t.error && <div className="ask-a ask-err">{t.error}</div>}

            {t.answer && (
              <div className="ask-a">
                <div className="ask-a-body">{t.answer}</div>
                {t.sources?.length > 0 && (
                  <div className="ask-sources">
                    <span className="ask-sources-h">근거</span>
                    {t.sources.map((s, j) => {
                      const m = srcMeta(s.source)
                      return (
                        <span key={j} className={`ask-src ${m.cls}`} title={s.title || ''}>
                          <b>{m.label}</b> {s.ref}
                        </span>
                      )
                    })}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
        <div ref={endRef} />
      </div>

      <form className="ask-bar" onSubmit={(e) => { e.preventDefault(); ask() }}>
        <input
          className="ask-input"
          placeholder="보안·인프라에 대해 물어보세요"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          disabled={busy}
        />
        <button className="ac-btn" type="submit" disabled={busy || !input.trim()}>
          {busy ? '…' : '질문'}
        </button>
      </form>
    </div>
  )
}
