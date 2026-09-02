import { useState } from 'react'
import { callFunction } from '../lib/db'
import { checkRequest } from '../lib/rules'
import { summarizePayload } from '../lib/discord'
import { ACTION_LABEL } from '../lib/aws'
import { knowledgeRefsFor } from '../lib/scan'

// 무엇이 왜 문제인지 자연어로 풀어 보여준다.
//
// 자동으로 부르지 않는다. 한 번에 몇 초가 걸리고 무료 티어에 호출 한도가 있어서,
// 목록을 넘겨볼 때마다 부르면 금방 동난다. 필요할 때 누르게 한다.
//
// 판정은 여기서 하지 않는다 — 신청은 rules.js가, 점검은 Prowler가 이미 정했고
// 그 결과를 그대로 넘긴다.
//
// 쓰는 곳이 둘이다.
//   request  신청 검토 — 규칙 엔진 판정을 여기서 계산해 넘긴다
//   finding  점검 결과 — 이미 나온 판정을 그대로 받는다
export default function ExplainPanel({ request, finding }) {
  const [state, setState] = useState('idle') // idle | loading | done | error
  const [text, setText] = useState('')
  const [sources, setSources] = useState([])
  const [error, setError] = useState('')
  const [showSources, setShowSources] = useState(false)
  const [openSource, setOpenSource] = useState(null)

  const run = async () => {
    setState('loading')
    setError('')

    let body
    if (finding) {
      // 점검 결과. 체크 ID가 지식 베이스의 ref와 같은 값이라 검색이 정확히 걸린다.
      body = {
        summary: `AWS 보안 점검에서 걸린 항목 — ${finding.check_id}`,
        findings: [{
          severity: finding.severity,
          title: finding.title || finding.check_id,
          why: finding.detail || '',
        }],
        verdict: null,
        // 인증기준·공격기법·OWASP 항목은 유사도로 찾지 않고 손으로 맞춘 표에서 넘긴다.
        // 검색으로 더듬으면 관련 있는 것과 없는 것이 같은 점수대에 섞여 나오는데,
        // 이런 근거는 틀리면 설명 자체가 무너진다. 표가 있으니 정확한 것을 바로 준다.
        pinned_refs: knowledgeRefsFor(finding.check_id),
      }
    } else {
      const check = checkRequest(request.action, request.payload)
      const detail = summarizePayload(request.action, request.payload)
      const actionLabel = ACTION_LABEL[request.action] || request.action
      body = {
        summary: `${actionLabel}${detail ? ` — ${detail}` : ''}`,
        findings: (check?.findings || []).map((f) => ({
          severity: f.severity, title: f.title, why: f.why,
        })),
        verdict: check?.verdict ?? null,
      }
    }

    const data = await callFunction('rag-explain', body)

    if (!data.ok) {
      setError(data.error || '설명을 만들지 못했습니다')
      setState('error')
      return
    }
    setText(data.explanation)
    // 출처별로 뽑아 오므로 순서가 출처 순이다. 점수 순으로 바꿔야 무엇이 결정적이었는지 보인다.
    setSources([...(data.sources || [])].sort((a, b) => (b.similarity ?? 0) - (a.similarity ?? 0)))
    setOpenSource(null)
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
                  {/* 12건쯤 나오므로 한 줄에 하나씩만 보이게 하고, 누른 것만 펼친다.
                      전부 펼쳐두면 설명보다 근거가 길어져 아무도 안 읽는다. */}
                  {sources.map((s, i) => (
                    <div key={i} className={`xp-source ${openSource === i ? 'is-open' : ''}`}>
                      <button className="xp-source-head" onClick={() => setOpenSource(openSource === i ? null : i)}>
                        <span className={`xp-badge xp-badge-${s.source}`}>{SOURCE_LABEL[s.source] || s.source}</span>
                        <span className="xp-title">{s.title || s.ref}</span>
                        <span className="xp-sim">{s.similarity}</span>
                        <span className="xp-caret">{openSource === i ? '−' : '+'}</span>
                      </button>
                      {openSource === i && (
                        <div className="xp-source-body">
                          {s.excerpt && <p className="xp-excerpt">{s.excerpt}</p>}
                          <span className="xp-ref">{s.ref}</span>
                        </div>
                      )}
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

// 출처 이름은 전부 적어둔다. 빠뜨리면 화면에 'gcp_baseline' 같은 원본 값이 그대로 나온다.
const SOURCE_LABEL = {
  rule_engine: '판정 사례',
  policy: '우리 정책',
  concept: 'AWS 개념',
  aws_baseline: 'AWS 기준',
  gcp_baseline: 'GCP 기준',
  ismsp: 'ISMS-P',
  mitre: '공격 기법',
  mitigation: '완화책',
  owasp: 'OWASP',
  kev: '악용 취약점',
}
