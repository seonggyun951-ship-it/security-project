import { useState } from 'react'
import { supabase } from '../lib/supabase'

// 스캐너가 매긴 심각도는 "이 결함이 얼마나 나쁜가"만 말한다.
// CISA KEV는 "이게 실제 공격에 쓰이고 있는가"를 말한다 — 둘은 다른 질문이다.
// 지식 베이스에 KEV 1,665건이 들어 있으므로, 결과에서 뽑은 CVE ID로 조회해
// 실제 악용이 확인된 것을 위로 올린다. 유사도 검색이 아니라 ID 조회다.

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

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi

// CVE ID가 붙어 있을 만한 곳만 본다. 설명문까지 뒤지면 "CVE-XXXX와 비슷한" 같은
// 문장에서 남의 번호를 주워와 엉뚱한 KEV가 붙는다.
function extractCves(e, info) {
  const cls = info.classification || {}
  const raw = [
    e['template-id'], e.templateID, info.name,
    cls['cve-id'], cls.cveId,
    ...(Array.isArray(info.tags) ? info.tags : []),
  ]
  const found = new Set()
  for (const v of raw.flat()) {
    if (typeof v !== 'string') continue
    for (const m of v.match(CVE_RE) || []) found.add(m.toUpperCase())
  }
  return [...found]
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
    cves:        extractCves(e, info),
  }
}

// 지식 베이스 본문 끝에 "조치: ..." 한 줄이 붙어 있다 (KEV 적재 스크립트가 넣는다)
function fixNote(content) {
  const m = /\n조치:\s*([\s\S]+)$/.exec(content || '')
  return m ? m[1].trim() : ''
}

// 실제 악용 중인 것을 위로. 랜섬웨어에 쓰인 것이 그 안에서 또 먼저다.
// 심각도만으로 정렬하면 "critical이지만 아무도 안 쓰는 것"이 "high인데 지금
// 랜섬웨어가 쓰는 것"보다 위에 온다.
const kevRank = (f) => (f.kev ? (f.kev.meta?.ransomware ? 0 : 1) : 2)

export default function VulnScan() {
  const [input, setInput]     = useState('')
  const [findings, setFindings] = useState(null)
  const [error, setError]     = useState('')
  const [expanded, setExpanded] = useState(() => new Set())
  const [filter, setFilter]   = useState('all')
  const [kevBusy, setKevBusy] = useState(false)
  const [kevError, setKevError] = useState('')

  const toggle = (key) => setExpanded(prev => {
    const next = new Set(prev)
    next.has(key) ? next.delete(key) : next.add(key)
    return next
  })

  const analyze = async () => {
    setError(''); setKevError(''); setFindings(null); setExpanded(new Set()); setFilter('all')
    const raw = parseNuclei(input)
    if (!raw || !raw.length) {
      setError('스캔 결과를 읽지 못했습니다. 한 줄에 하나씩(JSONL)이거나 배열 형식인지 확인해주세요. 각 항목에 template-id가 있어야 합니다.')
      return
    }
    const parsed = raw.map(normalize)
    setFindings(parsed)

    // KEV 대조는 파싱과 분리한다. 조회가 실패해도 결과 정리는 이미 화면에 있어야 한다.
    const cves = [...new Set(parsed.flatMap((f) => f.cves))]
    if (cves.length === 0) return

    setKevBusy(true)
    const { data, error: e } = await supabase.rpc('lookup_knowledge', {
      refs: cves, filter_source: 'kev',
    })
    setKevBusy(false)
    if (e) { setKevError(`KEV 대조 실패: ${e.message}`); return }

    const byRef = Object.fromEntries((data || []).map((k) => [k.ref, k]))
    setFindings(parsed.map((f) => {
      const hit = f.cves.map((c) => byRef[c]).find(Boolean)
      return hit ? { ...f, kev: hit } : f
    }))
  }

  const sevOrder = Object.fromEntries(Object.entries(SEV_CONFIG).map(([k, v]) => [k, v.order]))
  const sorted   = findings ? [...findings].sort((a, b) => {
    const d = kevRank(a) - kevRank(b)
    return d !== 0 ? d : (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9)
  }) : []
  const visible  = filter === 'all' ? sorted
    : filter === 'kev' ? sorted.filter(f => f.kev)
      : sorted.filter(f => f.severity === filter)
  const counts   = findings ? Object.fromEntries(Object.keys(SEV_CONFIG).map(s => [s, findings.filter(f => f.severity === s).length])) : {}
  const kevCount = findings ? findings.filter(f => f.kev).length : 0
  const ransomCount = findings ? findings.filter(f => f.kev?.meta?.ransomware).length : 0

  return (
    <div className="vs-page">
      <h2 className="vs-title">취약점 스캔 결과 정리</h2>
      <p className="vs-sub">
        웹 서비스를 스캔한 결과를 붙여넣으면 심각도별로 정리하고,
        CISA가 실제 악용을 확인한 취약점(KEV)인지 대조해 먼저 조치할 것을 위로 올립니다.
      </p>

      <div className="vs-examples">
        <div className="vs-example-label">
          Nuclei로 스캔한 결과를 넣습니다. Nuclei는 오픈소스 웹 취약점 스캐너로,
          아래 명령을 실행하면 나오는 JSON 파일 내용을 그대로 붙여넣으면 됩니다.
        </div>
        <code>nuclei -u https://target.com -o results.json -json</code>
        <code>nuclei -l urls.txt -severity critical,high -json</code>
        <div className="vs-example-note">
          스캔 결과가 없다면 아래 <strong>샘플 로드</strong>를 눌러 예시로 확인해볼 수 있습니다.
        </div>
      </div>

      <div className="vs-textarea-wrap">
        <textarea className="vs-textarea" value={input} onChange={e => setInput(e.target.value)} placeholder="스캔 결과 JSON을 여기에 붙여넣으세요. 한 줄에 하나씩(JSONL)이거나 배열 형식 모두 됩니다." spellCheck={false} />
        <button className="vs-sample-btn" onClick={() => { setInput(SAMPLE); setFindings(null); setError('') }}>샘플 로드</button>
      </div>

      <button className="vs-btn" onClick={analyze} disabled={!input.trim()}>분석하기</button>
      {error && <div className="vs-error">{error}</div>}

      {findings && (
        <div className="vs-results">
          {kevBusy && <div className="vs-kevbar is-busy">CISA KEV 대조 중...</div>}
          {kevError && <div className="vs-kevbar is-err">{kevError}</div>}
          {!kevBusy && kevCount > 0 && (
            <div className="vs-kevbar">
              <b>{kevCount}건이 실제 악용이 확인된 취약점(CISA KEV)입니다.</b>
              {ransomCount > 0 && <> 그중 <b>{ransomCount}건은 랜섬웨어에 쓰였습니다.</b></>}
              {' '}심각도보다 이쪽을 먼저 조치하는 게 맞아 목록 위로 올려 두었습니다.
            </div>
          )}

          <div className="vs-filter-row">
            <button className="vs-filter-btn" style={filter==='all' ? {borderColor:'#38bdf8',color:'#38bdf8',background:'rgba(56,189,248,0.08)'} : {}} onClick={() => setFilter('all')}>
              전체 {findings.length}
            </button>
            {kevCount > 0 && (
              <button className="vs-filter-btn vs-kev-filter" data-on={filter === 'kev' ? '1' : '0'}
                onClick={() => setFilter(filter === 'kev' ? 'all' : 'kev')}>
                실제 악용 {kevCount}
              </button>
            )}
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
                    {f.kev && (
                      <span className={`vs-kev-badge ${f.kev.meta?.ransomware ? 'is-ransom' : ''}`}
                        title={`CISA KEV 등재 ${f.kev.meta?.date_added || ''}`}>
                        {f.kev.meta?.ransomware ? '랜섬웨어' : '실제 악용'}
                      </span>
                    )}
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
                      {f.kev && (
                        <div className="vs-kevbox">
                          <div className="vs-kevbox-h">
                            CISA 악용된 취약점 목록(KEV) · {f.kev.ref}
                            {f.kev.meta?.date_added && <span> · {f.kev.meta.date_added} 등재</span>}
                          </div>
                          <div className="vs-meta-grid">
                            {(f.kev.meta?.vendor || f.kev.meta?.product) && (
                              <><span className="vs-meta-k">제품</span>
                                <span className="vs-meta-v">{[f.kev.meta.vendor, f.kev.meta.product].filter(Boolean).join(' ')}</span></>
                            )}
                            <span className="vs-meta-k">랜섬웨어</span>
                            <span className="vs-meta-v">{f.kev.meta?.ransomware ? '사용된 것으로 알려짐' : '확인되지 않음'}</span>
                            {f.kev.meta?.cwes?.length > 0 && (
                              <><span className="vs-meta-k">CWE</span>
                                <span className="vs-meta-v">{f.kev.meta.cwes.join(', ')}</span></>
                            )}
                          </div>
                          {fixNote(f.kev.content) && (
                            <div className="vs-kevfix"><b>조치</b> {fixNote(f.kev.content)}</div>
                          )}
                        </div>
                      )}
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
