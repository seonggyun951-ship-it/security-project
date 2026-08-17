import { useState } from 'react'
import { callFunction } from '../lib/db'
import { checkRequest } from '../lib/rules'
import { summarizePayload } from '../lib/discord'
import { ACTION_LABEL } from '../lib/aws'

// 규칙 엔진의 판정을 자연어로 풀어 보여준다.
//
// 자동으로 부르지 않는다. 신청 하나당 몇 초가 걸리고 무료 티어에 호출 한도가 있어서,
// 목록을 넘겨볼 때마다 부르면 금방 동난다. 관리자가 필요할 때 누르게 한다.
//
// 판정은 여기서 하지 않는다 — 위험한지는 rules.js가 이미 정했고, 그 결과를 그대로 넘긴다.
export default function ExplainPanel({ request }) {
  const [state, setState] = useState('idle') // idle | loading | done | error
  const [text, setText] = useState('')
  const [sources, setSources] = useState([])
  const [error, setError] = useState('')
  const [showSources, setShowSources] = useState(false)

  const run = async () => {
    setState('loading')
    setError('')

    const check = checkRequest(request.action, request.payload)
    const detail = summarizePayload(request.action, request.payload)
    const actionLabel = ACTION_LABEL[request.action] || request.action

    const data = await callFunction('rag-explain', {
      summary: `${actionLabel}${detail ? ` — ${detail}` : ''}`,
      findings: (check?.findings || []).map((f) => ({
        severity: f.severity, title: f.title, why: f.why,
      })),
      verdict: check?.verdict ?? null,
    })

    if (!data.ok) {
      setError(data.error || '설명을 만들지 못했습니다')
      setState('error')
      return
    }
    setText(data.explanation)
    setSources(data.sources || [])
    setState('done')
  }

  return (
    <div className="xp">
      {state === 'idle' && (
        <button className="ac-btn ac-btn-secondary xp-run" onClick={run}>
          이 신청 설명 보기
        </button>
      )}

      {state === 'loading' && (
        <div className="xp-loading">보안 자료를 찾아 설명을 만드는 중... (몇 초 걸립니다)</div>
      )}

      {state === 'error' && (
        <div className="ac-req-error">
          {error}
          <button className="ac-btn ac-btn-secondary xp-retry" onClick={run}>다시 시도</button>
        </div>
      )}

      {state === 'done' && (
        <div className="xp-result">
          <div className="xp-text">{text}</div>

          {sources.length > 0 && (
            <>
              <button className="xp-toggle" onClick={() => setShowSources(!showSources)}>
                {showSources ? '근거 접기' : `근거 ${sources.length}건 보기`}
              </button>
              {showSources && (
                <div className="xp-sources">
                  {sources.map((s, i) => (
                    <div key={i} className="xp-source">
                      <span className={`xp-badge xp-badge-${s.source}`}>{SOURCE_LABEL[s.source] || s.source}</span>
                      <span className="xp-ref">{s.ref}</span>
                      <span className="xp-sim">{s.similarity}</span>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}

          {/* 사람이 쓴 글이 아니라는 걸 분명히 해둔다. 그대로 믿고 승인하면 안 된다. */}
          <div className="xp-note">
            자동 생성된 설명입니다. 판정은 규칙 엔진이 내렸고, 이 글은 그 근거를 옮긴 것입니다.
          </div>
        </div>
      )}
    </div>
  )
}

const SOURCE_LABEL = {
  rule_engine: '판정 기준',
  aws_baseline: 'AWS 기준',
  mitre: 'MITRE',
  owasp: 'OWASP',
}
