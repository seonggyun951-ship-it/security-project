import { useState } from 'react'
import { analyzeConfig, summarize, SEVERITY_ORDER, SEVERITY_LABEL, TYPE_META } from '../lib/rules'

// 판정 로직은 src/lib/rules.js에 있다. 이 화면은 입력받아 보여주기만 한다.
// (같은 엔진을 신청 점검과 RAG 라벨링에서도 쓰기 때문에 화면과 분리해 두었다)
const SEV_COLOR = {
  high:   { color: '#ef4444', bg: 'rgba(239,68,68,0.08)' },
  medium: { color: '#f59e0b', bg: 'rgba(245,158,11,0.08)' },
  low:    { color: '#38bdf8', bg: 'rgba(56,189,248,0.08)' },
  ok:     { color: '#10b981', bg: 'rgba(16,185,129,0.08)' },
}

export default function CloudCheck() {
  const [input, setInput] = useState('')
  const [findings, setFindings] = useState(null)
  const [detectedType, setDetectedType] = useState(null)
  const [error, setError] = useState('')

  const analyze = () => {
    setError('')
    setFindings(null)
    let data
    try {
      data = JSON.parse(input)
    } catch {
      setError('JSON 파싱 오류: 올바른 JSON 형식인지 확인하세요.')
      return
    }
    const { type, findings: result } = analyzeConfig(data)
    if (!type) {
      setError('S3 버킷, AWS Security Group, 또는 GCP 방화벽 JSON 형식을 인식하지 못했습니다. 아래 예시 명령어를 참고하세요.')
      return
    }
    setDetectedType(type)
    setFindings(result)
  }

  const counts = findings && summarize(findings).counts

  return (
    <div className="cc-page">
      <h2 className="cc-title">클라우드 설정 점검</h2>
      <p className="cc-sub">AWS S3 버킷, AWS Security Group, 또는 GCP 방화벽 규칙 JSON을 붙여넣으세요.</p>

      <div className="cc-examples">
        <div className="cc-example-label">CLI 명령어</div>
        <code>aws s3api get-public-access-block --bucket {'<bucket-name>'}</code>
        <code>aws ec2 describe-security-groups --group-ids {'<sg-id>'}</code>
        <code>gcloud compute firewall-rules list --format=json</code>
      </div>

      <textarea
        className="cc-textarea"
        value={input}
        onChange={e => setInput(e.target.value)}
        placeholder={'{\n  "PublicAccessBlockConfiguration": {\n    "BlockPublicAcls": false,\n    "IgnorePublicAcls": true,\n    "BlockPublicPolicy": false,\n    "RestrictPublicBuckets": true\n  }\n}'}
        spellCheck={false}
      />

      <button className="cc-btn" onClick={analyze} disabled={!input.trim()}>
        분석하기
      </button>

      {error && <div className="cc-error">{error}</div>}

      {findings && (
        <div className="cc-results">
          <div className="cc-result-header">
            <span className="cc-type-badge">
              {TYPE_META[detectedType].label} 감지됨
            </span>
            <div className="cc-counts">
              {SEVERITY_ORDER.map(sev => counts[sev] > 0 && (
                <span key={sev} className="cc-count" style={{ background: SEV_COLOR[sev].color }}>
                  {counts[sev]} {SEVERITY_LABEL[sev]}
                </span>
              ))}
            </div>
          </div>

          <div className="cc-findings">
            {SEVERITY_ORDER.flatMap(sev =>
              findings
                .filter(f => f.severity === sev)
                .map((f, i) => (
                  <div
                    key={`${sev}-${i}`}
                    className="cc-finding"
                    style={{ borderLeft: `4px solid ${SEV_COLOR[sev].color}`, background: SEV_COLOR[sev].bg }}
                  >
                    <div className="cc-finding-top">
                      <span className="cc-sev-badge" style={{ background: SEV_COLOR[sev].color }}>
                        {SEVERITY_LABEL[sev]}
                      </span>
                      <span className="cc-finding-title">{f.title}</span>
                    </div>
                    <div className="cc-finding-detail">{f.detail}</div>
                    {f.why && <div className="cc-finding-why">{f.why}</div>}
                  </div>
                ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}
