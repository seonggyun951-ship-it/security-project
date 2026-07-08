import { useState } from 'react'

const SEV_CONFIG = {
  critical: { label: 'Critical', color: '#9333ea', bg: 'rgba(147,51,234,0.08)', order: 0 },
  high:     { label: 'High',     color: '#ef4444', bg: 'rgba(239,68,68,0.08)',   order: 1 },
  medium:   { label: 'Medium',   color: '#f59e0b', bg: 'rgba(245,158,11,0.08)',  order: 2 },
  low:      { label: 'Low',      color: '#38bdf8', bg: 'rgba(56,189,248,0.08)',  order: 3 },
  info:     { label: 'Info',     color: '#94a3b8', bg: 'rgba(148,163,184,0.06)', order: 4 },
  unknown:  { label: 'Unknown',  color: '#64748b', bg: 'rgba(100,116,139,0.06)', order: 5 },
}

const SAMPLE = `{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j2 RCE","severity":"critical","description":"Apache Log4j2 <=2.14.1 JNDI features allow remote code execution via crafted log messages.","tags":["cve","log4j","rce"]},"host":"https://target.example.com","matched-at":"https://target.example.com/api/login","timestamp":"2024-06-01T10:11:34Z"}
{"template-id":"CVE-2022-26134","info":{"name":"Confluence OGNL Injection","severity":"critical","description":"Confluence Server/Data Center OGNL injection via template URI — unauthenticated RCE.","tags":["cve","confluence","rce"]},"host":"https://confluence.example.com","matched-at":"https://confluence.example.com/pages/","timestamp":"2024-06-01T10:12:00Z"}
{"template-id":"exposed-git-folder","info":{"name":"Git Folder Exposed","severity":"high","description":"Publicly accessible .git directory allows source code and credential leakage.","tags":["exposure","git"]},"host":"https://target.example.com","matched-at":"https://target.example.com/.git/config","timestamp":"2024-06-01T10:13:00Z"}
{"template-id":"http-missing-security-headers","info":{"name":"Missing Security Headers","severity":"medium","description":"Detects missing HTTP security headers (X-Frame-Options, CSP, HSTS, etc.).","tags":["headers","hardening"]},"host":"https://target.example.com","matched-at":"https://target.example.com/","timestamp":"2024-06-01T10:15:00Z"}
{"template-id":"ssl-expired","info":{"name":"SSL Certificate Expired","severity":"medium","description":"The SSL/TLS certificate has passed its expiry date.","tags":["ssl","expired"]},"host":"https://old.example.com","matched-at":"https://old.example.com/","timestamp":"2024-06-01T10:16:00Z"}
{"template-id":"robots-txt","info":{"name":"Robots.txt Endpoint Found","severity":"info","description":"robots.txt may reveal sensitive paths such as /admin, /backup.","tags":["info","recon"]},"host":"https://target.example.com","matched-at":"https://target.example.com/robots.txt","timestamp":"2024-06-01T10:17:00Z"}`

function parseNuclei(text) {
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean)
  const jsonlResults = []
  for (const line of lines) {
    try {
      const obj = JSON.parse(line)
      if (obj['template-id'] || obj.templateID) jsonlResults.push(obj)
    } catch {}
  }
  if (jsonlResults.length > 0) return jsonlResults
  try {
    const arr = JSON.parse(text)
    if (Array.isArray(arr)) return arr
    if (arr['template-id']) return [arr]
  } catch {}
  return null
}

function normalize(e) {
  const info = e.info || {}
  return {
    id:          e['template-id'] || e.templateID || 'unknown',
    name:        info.name        || e.name        || e.id || 'Unknown',
    severity:   (info.severity   || e.severity    || 'unknown').toLowerCase(),
    description: info.description || e.description || '',
    host:        e.host           || e.url          || '',
    matchedAt:   e['matched-at']  || e.matchedAt   || '',
    tags:        info.tags        || e.tags         || [],
    timestamp:   e.timestamp      || '',
  }
}

export default function VulnScan() {
  const [input, setInput]     = useState('')
  const [findings, setFindings] = useState(null)
  const [error, setError]     = useState('')
  const [expanded, setExpanded] = useState(() => new Set())
  const [filter, setFilter]   = useState('all')

  const toggle = (key) => setExpanded(prev => {
    const next = new Set(prev)
    next.has(key) ? next.delete(key) : next.add(key)
    return next
  })

  const analyze = () => {
    setError(''); setFindings(null); setExpanded(new Set()); setFilter('all')
    const raw = parseNuclei(input)
    if (!raw || !raw.length) { setError('Nuclei 스캔 결과를 파싱할 수 없습니다. JSONL 또는 JSON 배열 형식인지 확인하세요.'); return }
    setFindings(raw.map(normalize))
  }

  const sevOrder = Object.fromEntries(Object.entries(SEV_CONFIG).map(([k, v]) => [k, v.order]))
  const sorted   = findings ? [...findings].sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9)) : []
  const visible  = filter === 'all' ? sorted : sorted.filter(f => f.severity === filter)
  const counts   = findings ? Object.fromEntries(Object.keys(SEV_CONFIG).map(s => [s, findings.filter(f => f.severity === s).length])) : {}

  return (
    <div className="vs-page">
      <h2 className="vs-title">🔍 취약점 스캔</h2>
      <p className="vs-sub">Nuclei 스캔 결과(JSONL 또는 JSON 배열)를 붙여넣으면 심각도별로 정리합니다.</p>

      <div className="vs-examples">
        <div className="vs-example-label">CLI 명령어</div>
        <code>nuclei -u https://target.com -o results.json -json</code>
        <code>nuclei -l urls.txt -severity critical,high -json</code>
      </div>

      <div className="vs-textarea-wrap">
        <textarea className="vs-textarea" value={input} onChange={e => setInput(e.target.value)} placeholder="Nuclei JSONL 결과를 여기에 붙여넣으세요..." spellCheck={false} />
        <button className="vs-sample-btn" onClick={() => { setInput(SAMPLE); setFindings(null); setError('') }}>샘플 로드</button>
      </div>

      <button className="vs-btn" onClick={analyze} disabled={!input.trim()}>분석하기</button>
      {error && <div className="vs-error">⚠️ {error}</div>}

      {findings && (
        <div className="vs-results">
          <div className="vs-filter-row">
            <button className="vs-filter-btn" style={filter==='all' ? {borderColor:'#38bdf8',color:'#38bdf8',background:'rgba(56,189,248,0.08)'} : {}} onClick={() => setFilter('all')}>
              전체 {findings.length}
            </button>
            {Object.entries(SEV_CONFIG).map(([sev, cfg]) => counts[sev] > 0 && (
              <button key={sev} className="vs-filter-btn"
                style={filter===sev ? {borderColor:cfg.color,color:cfg.color,background:cfg.bg} : {borderColor:cfg.color+'55',color:cfg.color}}
                onClick={() => setFilter(filter===sev ? 'all' : sev)}>
                {cfg.label} {counts[sev]}
              </button>
            ))}
          </div>

          <div className="vs-findings">
            {visible.length === 0 && <div className="vs-empty">선택한 심각도의 취약점이 없습니다.</div>}
            {visible.map((f, i) => {
              const cfg = SEV_CONFIG[f.severity] || SEV_CONFIG.unknown
              const key = `${f.id}-${i}`
              return (
                <div key={key} className="vs-finding" style={{borderLeft:`4px solid ${cfg.color}`, background:cfg.bg}}>
                  <div className="vs-finding-top" onClick={() => toggle(key)}>
                    <span className="vs-sev-badge" style={{background:cfg.color}}>{cfg.label}</span>
                    <span className="vs-finding-name">{f.name}</span>
                    <code className="vs-template-id">{f.id}</code>
                    <span className="vs-expand-icon">{expanded.has(key) ? '▲' : '▼'}</span>
                  </div>
                  <div className="vs-finding-host">{f.matchedAt || f.host}</div>
                  {expanded.has(key) && (
                    <div className="vs-finding-body">
                      {f.description && <div className="vs-finding-desc">{f.description}</div>}
                      <div className="vs-meta-grid">
                        {f.host      && <><span className="vs-meta-k">Host</span><span className="vs-meta-v">{f.host}</span></>}
                        {f.matchedAt && f.matchedAt !== f.host && <><span className="vs-meta-k">Matched</span><span className="vs-meta-v">{f.matchedAt}</span></>}
                        {f.timestamp && <><span className="vs-meta-k">Time</span><span className="vs-meta-v">{f.timestamp}</span></>}
                      </div>
                      {f.tags.length > 0 && (
                        <div className="vs-tags">{f.tags.map(t => <span key={t} className="vs-tag">{t}</span>)}</div>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
