import { useState } from 'react'

/* ─── Constants ──────────────────────────────────── */
const TRUSTED_BRANDS = [
  'paypal','amazon','google','apple','netflix','facebook','microsoft',
  'instagram','twitter','naver','kakao','toss','kbank','shinhan','woori',
  'kb','hana','citi','samsung','lg','hyundai',
]
const SHORTENERS = [
  'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','buff.ly','is.gd',
  'cli.gs','tr.im','tiny.cc','rb.gy','cutt.ly','short.io',
]
const SUSPICIOUS_TLDS = [
  '.xyz','.tk','.ml','.ga','.cf','.gq','.top','.click',
  '.download','.zip','.link','.work','.cam','.surf','.loan',
]
const TYPO_PATTERNS = [
  { re: /paypa[l1]|paypai/i,          brand: 'PayPal' },
  { re: /g[o0][o0]g[l1]e/i,           brand: 'Google' },
  { re: /arnazon|amaz[o0]n(?!\.)/i,   brand: 'Amazon' },
  { re: /micros[o0]ft|microsofl/i,     brand: 'Microsoft' },
  { re: /faceb[o0][o0]k|facebok/i,    brand: 'Facebook' },
  { re: /nav[e3]r(?!\.)/i,            brand: 'Naver' },
  { re: /kaka[o0](?!\.)/i,            brand: 'Kakao' },
  { re: /app[l1]e(?!\.)/i,            brand: 'Apple' },
]

const SAMPLES = [
  'https://paypal-security-alert.xyz/verify?user=1',
  'http://192.168.1.100/login',
  'https://google.com',
  'https://naver.com.secure-login.top/update',
  'https://bit.ly/3xAbCd',
]

/* ─── URL Heuristic Analysis ─────────────────────── */
function analyzeURL(rawUrl) {
  let fullUrl = rawUrl.trim()
  if (!/^https?:\/\//i.test(fullUrl)) fullUrl = 'http://' + fullUrl

  let parsed
  try { parsed = new URL(fullUrl) } catch { return null }

  const hostname = parsed.hostname.toLowerCase()
  const path     = (parsed.pathname + parsed.search).toLowerCase()
  const parts    = hostname.split('.')
  const mainDomain = parts.slice(-2).join('.')
  const subdomain  = parts.slice(0, -2).join('.')
  const checks     = []

  // 1. HTTPS
  const isHttps = parsed.protocol === 'https:'
  checks.push({
    id: 'https', label: 'HTTPS 사용 여부', pass: isHttps, severity: 'medium',
    desc: isHttps ? 'HTTPS 암호화 연결을 사용합니다.' : 'HTTP 평문 연결입니다. 피싱 사이트는 HTTPS가 없는 경우가 많습니다.',
  })

  // 2. IP address
  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)
  checks.push({
    id: 'ip', label: 'IP 주소 URL', pass: !isIP, severity: 'high',
    desc: isIP ? '도메인 대신 IP 주소를 직접 사용합니다. 합법적인 서비스는 거의 사용하지 않습니다.' : '정상적인 도메인 이름을 사용합니다.',
  })

  // 3. Suspicious TLD
  const badTLD = SUSPICIOUS_TLDS.find(t => hostname.endsWith(t))
  checks.push({
    id: 'tld', label: '의심 도메인 확장자', pass: !badTLD, severity: 'high',
    desc: badTLD ? `".${hostname.split('.').pop()}" 확장자는 피싱에 자주 사용됩니다. 극히 주의하세요.` : '정상적인 도메인 확장자입니다.',
  })

  // 4. URL shortener
  const isShort = SHORTENERS.some(s => hostname === s || hostname.endsWith('.' + s))
  checks.push({
    id: 'shortener', label: 'URL 단축 서비스', pass: !isShort, severity: 'medium',
    desc: isShort ? 'URL 단축 서비스는 실제 목적지를 숨길 수 있습니다. 클릭 전 원본 URL을 확인하세요.' : 'URL 단축 서비스가 아닙니다.',
  })

  // 5. Excessive subdomains
  const subCount = parts.length - 2
  checks.push({
    id: 'subdomains', label: '서브도메인 과다', pass: subCount <= 2, severity: 'medium',
    desc: subCount > 2
      ? `서브도메인이 ${subCount}개입니다. "paypal.com.attacker.net" 형태의 위장 수법일 수 있습니다.`
      : '서브도메인 수가 정상 범위입니다.',
  })

  // 6. Brand impersonation (brand in subdomain/path but not main domain)
  const impostors = TRUSTED_BRANDS.filter(brand => {
    const inSub  = subdomain.includes(brand)
    const inPath = path.includes(brand)
    const isReal = mainDomain.startsWith(brand + '.')
    return (inSub || inPath) && !isReal
  })
  checks.push({
    id: 'brand', label: '브랜드 사칭', pass: impostors.length === 0, severity: 'high',
    desc: impostors.length > 0
      ? `"${impostors.join(', ')}" 서비스를 사칭하는 URL 구조입니다. 공식 도메인과 다릅니다.`
      : '알려진 브랜드 사칭 패턴이 없습니다.',
  })

  // 7. @ symbol in URL
  const hasAt = rawUrl.includes('@')
  checks.push({
    id: 'at', label: 'URL 내 @ 기호', pass: !hasAt, severity: 'high',
    desc: hasAt ? 'URL에 @ 기호가 있으면 브라우저는 @ 이후를 실제 도메인으로 해석합니다. 전형적인 피싱 속임수입니다.' : '@ 기호가 없습니다.',
  })

  // 8. Typosquatting
  const typos = TYPO_PATTERNS.filter(p => p.re.test(hostname))
  checks.push({
    id: 'typo', label: '타이포스쿼팅 (유사 철자)', pass: typos.length === 0, severity: 'high',
    desc: typos.length > 0
      ? `"${typos.map(t => t.brand).join(', ')}" 유사 철자 도메인이 감지되었습니다. 타이포스쿼팅 피싱 사이트일 가능성이 높습니다.`
      : '알려진 타이포스쿼팅 패턴이 없습니다.',
  })

  // 9. URL length
  const len = rawUrl.length
  checks.push({
    id: 'length', label: 'URL 길이', pass: len <= 100, severity: 'low',
    desc: len > 100
      ? `URL 길이가 ${len}자로 깁니다. 악성 파라미터를 숨기거나 분석을 어렵게 만들 수 있습니다.`
      : `URL 길이가 정상입니다 (${len}자).`,
  })

  // Scoring
  const failH = checks.filter(c => !c.pass && c.severity === 'high').length
  const failM = checks.filter(c => !c.pass && c.severity === 'medium').length
  const failL = checks.filter(c => !c.pass && c.severity === 'low').length
  const risk  = Math.min(failH * 30 + failM * 15 + failL * 5, 100)
  const verdict = risk >= 60 ? 'danger' : risk >= 25 ? 'suspicious' : 'safe'

  return { hostname, checks, risk, verdict }
}

const VERDICT_CONFIG = {
  safe:       { label: '안전', color: '#10b981', bg: 'rgba(16,185,129,0.1)',  icon: '✅' },
  suspicious: { label: '의심', color: '#f59e0b', bg: 'rgba(245,158,11,0.1)', icon: '⚠️' },
  danger:     { label: '위험', color: '#ef4444', bg: 'rgba(239,68,68,0.1)',  icon: '🚨' },
}

const SEV_PASS  = { color: '#10b981' }
const SEV_FAIL  = { high: '#ef4444', medium: '#f59e0b', low: '#38bdf8' }

export default function PhishingDetect() {
  const [url, setUrl]       = useState('')
  const [result, setResult] = useState(null)
  const [error, setError]   = useState('')

  const analyze = () => {
    setError(''); setResult(null)
    if (!url.trim()) return
    const r = analyzeURL(url)
    if (!r) { setError('올바른 URL 형식이 아닙니다. https://example.com 형태로 입력하세요.'); return }
    setResult(r)
  }

  const vc = result ? VERDICT_CONFIG[result.verdict] : null

  return (
    <div className="pd-page">
      <h2 className="pd-title">🎣 피싱 URL 탐지</h2>
      <p className="pd-sub">URL을 입력하면 피싱 여부를 휴리스틱으로 분석합니다. (IP 주소, 브랜드 사칭, 타이포스쿼팅 등 9개 항목 검사)</p>

      <div className="pd-input-row">
        <input
          className="pd-input"
          value={url}
          onChange={e => setUrl(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && analyze()}
          placeholder="https://example.com"
          autoComplete="off"
          spellCheck={false}
        />
        <button className="pd-btn" onClick={analyze} disabled={!url.trim()}>검사</button>
      </div>

      <div className="pd-samples">
        <span className="pd-samples-label">예시 :</span>
        {SAMPLES.map(s => (
          <button key={s} className="pd-sample" onClick={() => { setUrl(s); setResult(null); setError('') }}>
            {s.length > 40 ? s.slice(0, 38) + '…' : s}
          </button>
        ))}
      </div>

      {error && <div className="pd-error">⚠️ {error}</div>}

      {result && (
        <div className="pd-results">
          {/* Verdict card */}
          <div className="pd-verdict-card" style={{ background: vc.bg, borderColor: vc.color }}>
            <span className="pd-verdict-icon">{vc.icon}</span>
            <div>
              <div className="pd-verdict-label" style={{ color: vc.color }}>{vc.label}</div>
              <div className="pd-verdict-host">{result.hostname}</div>
            </div>
            <div className="pd-risk-score" style={{ color: vc.color }}>
              {result.risk}
              <div className="pd-risk-unit">/ 100</div>
            </div>
          </div>

          {/* Risk bar */}
          <div className="pd-risk-bar-wrap">
            <div className="pd-risk-bar">
              <div className="pd-risk-fill" style={{ width: `${result.risk}%`, background: vc.color }} />
            </div>
            <div className="pd-risk-bar-labels">
              <span>안전</span><span>의심</span><span>위험</span>
            </div>
          </div>

          {/* Checks */}
          <div className="pd-checks">
            {result.checks.map(c => {
              const clr = c.pass ? SEV_PASS.color : (SEV_FAIL[c.severity] || '#94a3b8')
              return (
                <div key={c.id} className="pd-check">
                  <span className="pd-check-icon" style={{ color: clr }}>{c.pass ? '✓' : '✗'}</span>
                  <div>
                    <div className="pd-check-label" style={{ color: c.pass ? '#94a3b8' : '#f1f5f9' }}>{c.label}</div>
                    <div className="pd-check-desc">{c.desc}</div>
                  </div>
                  {!c.pass && (
                    <span className="pd-check-sev" style={{ color: clr, borderColor: clr }}>
                      {c.severity === 'high' ? '위험' : c.severity === 'medium' ? '주의' : '낮음'}
                    </span>
                  )}
                </div>
              )
            })}
          </div>

          {result.verdict !== 'safe' && (
            <div className="pd-warning">
              💡 의심스러운 URL은 클릭하지 말고, 공식 웹사이트는 직접 주소창에 입력하거나 북마크를 이용하세요.
            </div>
          )}
        </div>
      )}
    </div>
  )
}
