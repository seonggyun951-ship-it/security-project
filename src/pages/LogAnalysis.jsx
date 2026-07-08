import { useState } from 'react'

/* ─── Attack Pattern Libraries ───────────────────── */
const SQL_PATTERNS = [
  { re: /union\s+(?:all\s+)?select/i,                     label: 'UNION SELECT' },
  { re: /select\s+.+\s+from\s+\w+/i,                     label: 'SELECT FROM' },
  { re: /drop\s+table/i,                                  label: 'DROP TABLE' },
  { re: /insert\s+into/i,                                 label: 'INSERT INTO' },
  { re: /delete\s+from/i,                                 label: 'DELETE FROM' },
  { re: /'?\s*or\s+['"]?1['"]?\s*=\s*['"]?1/i,           label: "OR '1'='1'" },
  { re: /exec(?:ute)?\s*\(/i,                             label: 'EXEC()' },
  { re: /xp_cmdshell/i,                                   label: 'xp_cmdshell' },
  { re: /information_schema/i,                            label: 'information_schema' },
  { re: /benchmark\s*\(/i,                                label: 'BENCHMARK()' },
  { re: /sleep\s*\(\d+\)/i,                               label: 'SLEEP()' },
  { re: /waitfor\s+delay/i,                               label: 'WAITFOR DELAY' },
  { re: /load_file\s*\(/i,                                label: 'LOAD_FILE()' },
  { re: /into\s+(?:out|dump)file/i,                       label: 'INTO OUTFILE' },
  { re: /char\s*\(\d+/i,                                  label: 'CHAR()' },
  { re: /(?:order|group)\s+by\s+\d+/i,                   label: 'ORDER BY N' },
]

const XSS_PATTERNS = [
  { re: /<script[\s>]/i,                                                             label: '<script>' },
  { re: /javascript\s*:/i,                                                           label: 'javascript:' },
  { re: /on(?:load|error|click|mouseover|submit|focus|blur|change|keyup|keydown|input|drag)\s*=/i, label: 'event handler' },
  { re: /alert\s*\(/i,                                                               label: 'alert()' },
  { re: /document\.cookie/i,                                                         label: 'document.cookie' },
  { re: /eval\s*\(/i,                                                                label: 'eval()' },
  { re: /<iframe[\s>]/i,                                                             label: '<iframe>' },
  { re: /fromcharcode/i,                                                             label: 'fromCharCode' },
  { re: /%3Cscript/i,                                                                label: '%3Cscript (encoded)' },
  { re: /&#x?\d+;/,                                                                  label: 'HTML entity encoding' },
  { re: /<svg[^>]*on\w+\s*=/i,                                                       label: '<svg> event' },
]

const PATH_TRAVERSAL_PATTERNS = [
  { re: /(?:\.\.\/){2,}/,           label: '../../../' },
  { re: /(?:\.\.%2f){2,}/i,        label: '..%2F (encoded)' },
  { re: /(?:%2e%2e%2f){2,}/i,      label: '%2e%2e%2f (encoded)' },
  { re: /(?:\.\.%5c){2,}/i,        label: '..%5C (encoded)' },
  { re: /etc\/passwd/i,             label: '/etc/passwd' },
  { re: /etc\/shadow/i,             label: '/etc/shadow' },
  { re: /windows\/system32/i,       label: 'windows/system32' },
  { re: /boot\.ini/i,               label: 'boot.ini' },
  { re: /proc\/self/i,              label: '/proc/self' },
]

const CMD_INJECTION_PATTERNS = [
  { re: /[;&|`]\s*(?:cat|ls|id|whoami|uname|pwd|echo|env)\b/i, label: 'command chain' },
  { re: /wget\s+https?:\/\//i,                                  label: 'wget download' },
  { re: /curl\s+-[a-z]*o\s/i,                                   label: 'curl download' },
  { re: /bash\s+-[ci]/i,                                        label: 'bash -c exec' },
  { re: /\|\s*(?:nc|netcat)\b/i,                                label: 'netcat pipe' },
  { re: /\$\([^)]{3,}\)/,                                       label: '$(command)' },
  { re: /`[^`]{3,}`/,                                           label: '`command`' },
  { re: /;\s*(?:rm|dd|mkfs)\b/i,                                label: 'destructive cmd' },
]

const SCANNER_UAS = [
  'sqlmap', 'nikto', 'nmap', 'dirbuster', 'gobuster', 'masscan',
  'nessus', 'openvas', 'burpsuite', 'zap/', 'acunetix', 'w3af',
  'metasploit', 'hydra', 'medusa', 'skipfish', 'wfuzz', 'nuclei',
  'whatweb', 'dirb', 'havij', 'pangolin', 'joomscan', 'wpscan',
  'appscan', 'webscarab', 'paros', 'owasp', 'arachni', 'vega',
]

/* ─── Log Parsers ────────────────────────────────── */
// Apache/Nginx Combined Log Format
const APACHE_RE = /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*?)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/

function parseApacheLine(line) {
  const m = line.match(APACHE_RE)
  if (!m) return null
  const [, ip, , timestamp, request, status, bytes, referer = '', ua = ''] = m
  const parts = request.split(' ')
  return {
    type: 'http',
    ip,
    timestamp,
    method: parts[0] || '',
    url: parts[1] || '',
    status: parseInt(status),
    bytes: bytes === '-' ? 0 : (parseInt(bytes) || 0),
    referer,
    ua,
  }
}

// SSH auth logs (with or without syslog prefix)
const SSH_FAILED_RE  = /Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)/
const SSH_ACCEPTED_RE = /Accepted (?:password|publickey) for (\S+) from (\S+)/
const SSH_INVALID_RE  = /Invalid user (\S+) from (\S+)/

function parseSSHLine(line) {
  let m
  if ((m = line.match(SSH_FAILED_RE)))  return { type: 'ssh_fail',    user: m[1], ip: m[2] }
  if ((m = line.match(SSH_ACCEPTED_RE))) return { type: 'ssh_ok',      user: m[1], ip: m[2] }
  if ((m = line.match(SSH_INVALID_RE)))  return { type: 'ssh_invalid', user: m[1], ip: m[2] }
  return null
}

/* ─── Helpers ─────────────────────────────────────── */
function decodeURISafely(str) {
  try { return decodeURIComponent(str || '') } catch { return str || '' }
}

function extractHour(timestamp) {
  const m = (timestamp || '').match(/:(\d{2}):\d{2}:\d{2}/)
  return m ? parseInt(m[1]) : null
}

function fmtBytes(bytes) {
  if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + ' GB'
  if (bytes >= 1048576)    return (bytes / 1048576).toFixed(1) + ' MB'
  if (bytes >= 1024)       return (bytes / 1024).toFixed(1) + ' KB'
  return bytes + ' B'
}

/* ─── Detection Rules ────────────────────────────── */
function detectBruteForce(entries) {
  const ipFails = {}
  for (const e of entries) {
    const isFail = (e.type === 'http' && (e.status === 401 || e.status === 403))
      || e.type === 'ssh_fail'
      || e.type === 'ssh_invalid'
    if (isFail && e.ip) ipFails[e.ip] = (ipFails[e.ip] || 0) + 1
  }
  return Object.entries(ipFails)
    .filter(([, c]) => c >= 5)
    .map(([ip, count]) => ({
      severity: count >= 20 ? 'high' : 'medium',
      rule: '무차별 대입 공격 의심',
      ip, count,
      detail: `${ip} — 인증 실패 ${count}회 감지`,
      why: '동일 IP에서 반복적인 인증 실패는 자격 증명을 자동으로 추측하는 브루트포스 공격의 전형적 패턴입니다. IP 차단 또는 계정 잠금 정책을 확인하세요.',
      samples: [],
    }))
}

function detectByPattern(entries, patterns, ruleName, why) {
  const byIP = {}
  for (const e of entries) {
    if (e.type !== 'http') continue
    const target = decodeURISafely(e.url + ' ' + e.referer)
    for (const { re, label } of patterns) {
      if (re.test(target)) {
        if (!byIP[e.ip]) byIP[e.ip] = { count: 0, labels: new Set(), samples: [] }
        byIP[e.ip].count++
        byIP[e.ip].labels.add(label)
        if (byIP[e.ip].samples.length < 3) byIP[e.ip].samples.push(e.url)
        break
      }
    }
  }
  return Object.entries(byIP).map(([ip, d]) => ({
    severity: 'high',
    rule: ruleName,
    ip, count: d.count,
    detail: `${ip} — ${[...d.labels].join(', ')} 패턴 ${d.count}회 감지`,
    why,
    samples: d.samples,
  }))
}

function detectScanners(entries) {
  const byIP = {}
  for (const e of entries) {
    if (e.type !== 'http') continue
    const ua = (e.ua || '').toLowerCase()
    for (const tool of SCANNER_UAS) {
      if (ua.includes(tool)) {
        if (!byIP[e.ip]) byIP[e.ip] = { tool, count: 0, samples: [] }
        byIP[e.ip].count++
        if (byIP[e.ip].samples.length < 3) byIP[e.ip].samples.push(e.url)
        break
      }
    }
  }
  return Object.entries(byIP).map(([ip, d]) => ({
    severity: 'high',
    rule: '보안 스캐너 감지',
    ip, count: d.count,
    detail: `${ip} — "${d.tool}" User-Agent ${d.count}회 감지`,
    why: `${d.tool}는 취약점 자동 스캔 도구입니다. 공격자가 사전에 취약점을 탐색하는 정찰 활동일 수 있습니다. 해당 IP를 즉시 차단하고 스캔된 경로를 점검하세요.`,
    samples: d.samples,
  }))
}

function detectHighErrorRate(entries) {
  const ipErrors = {}
  for (const e of entries) {
    if (e.type !== 'http') continue
    if (e.status >= 400) {
      if (!ipErrors[e.ip]) ipErrors[e.ip] = { c4: 0, c5: 0, samples: [] }
      if (e.status < 500) ipErrors[e.ip].c4++
      else ipErrors[e.ip].c5++
      if (ipErrors[e.ip].samples.length < 3) ipErrors[e.ip].samples.push(e.url)
    }
  }
  return Object.entries(ipErrors)
    .filter(([, d]) => d.c4 + d.c5 >= 10)
    .map(([ip, d]) => {
      const total = d.c4 + d.c5
      return {
        severity: total >= 50 ? 'high' : 'medium',
        rule: '비정상 에러율',
        ip, count: total,
        detail: `${ip} — 4xx ${d.c4}회, 5xx ${d.c5}회`,
        why: '다수의 4xx 오류는 존재하지 않는 경로 탐색(디렉토리 브루트포스) 또는 퍼징 시도, 5xx는 서버 과부하 공격일 수 있습니다.',
        samples: d.samples,
      }
    })
}

function detectUnusualHours(entries) {
  const byIP = {}
  for (const e of entries) {
    if (e.type !== 'http') continue
    const hour = extractHour(e.timestamp)
    if (hour !== null && hour >= 2 && hour <= 5) {
      if (!byIP[e.ip]) byIP[e.ip] = { count: 0, samples: [] }
      byIP[e.ip].count++
      if (byIP[e.ip].samples.length < 3) byIP[e.ip].samples.push(`[${e.timestamp}] ${e.url}`)
    }
  }
  return Object.entries(byIP)
    .filter(([, d]) => d.count >= 3)
    .map(([ip, d]) => ({
      severity: 'low',
      rule: '심야 시간대 접근',
      ip, count: d.count,
      detail: `${ip} — 새벽 2~5시 접근 ${d.count}회`,
      why: '업무 시간 외 심야 시간대의 대량 접근은 자동화된 공격 도구 사용이나 사용자 몰래 이루어지는 침입 시도일 수 있습니다.',
      samples: d.samples,
    }))
}

function detectLargeResponse(entries) {
  const byIP = {}
  const threshold = 10 * 1024 * 1024 // 10 MB
  for (const e of entries) {
    if (e.type !== 'http' || e.status !== 200 || e.bytes < threshold) continue
    if (!byIP[e.ip]) byIP[e.ip] = { count: 0, total: 0, samples: [] }
    byIP[e.ip].count++
    byIP[e.ip].total += e.bytes
    if (byIP[e.ip].samples.length < 3) byIP[e.ip].samples.push(`${e.url} (${fmtBytes(e.bytes)})`)
  }
  return Object.entries(byIP).map(([ip, d]) => ({
    severity: 'medium',
    rule: '대용량 데이터 전송',
    ip, count: d.count,
    detail: `${ip} — ${d.count}회, 총 ${fmtBytes(d.total)} 전송`,
    why: '단일 IP로의 반복적인 대용량 응답은 데이터 유출(Data Exfiltration) 가능성이 있습니다. 해당 URL과 응답 내용을 확인하세요.',
    samples: d.samples,
  }))
}

/* ─── Main Analysis ──────────────────────────────── */
function runAnalysis(text) {
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean)
  if (!lines.length) return null

  const entries = []
  let parseErrors = 0
  for (const line of lines) {
    const parsed = parseApacheLine(line) || parseSSHLine(line)
    if (parsed) entries.push(parsed)
    else parseErrors++
  }

  if (!entries.length) return null

  const sevOrder = { high: 0, medium: 1, low: 2 }
  const findings = [
    ...detectBruteForce(entries),
    ...detectByPattern(entries, SQL_PATTERNS, 'SQL 인젝션 시도',
      'SQL 인젝션은 데이터베이스를 직접 조작해 데이터 탈취, 삭제, 인증 우회가 가능한 치명적 공격입니다. WAF 적용 및 Prepared Statement 사용을 권장합니다.'),
    ...detectByPattern(entries, XSS_PATTERNS, 'XSS(크로스 사이트 스크립팅) 시도',
      'XSS 공격은 악성 스크립트를 삽입해 세션 탈취, 악성 사이트 리다이렉트, 사용자 행위 조작이 가능합니다. 출력 인코딩 및 CSP 헤더 적용을 권장합니다.'),
    ...detectByPattern(entries, PATH_TRAVERSAL_PATTERNS, '경로 탐색(Path Traversal) 시도',
      '경로 탐색 공격으로 서버의 설정 파일, 패스워드 파일(/etc/passwd), 소스코드 등 민감한 파일에 접근할 수 있습니다. 파일 경로 검증 로직을 점검하세요.'),
    ...detectByPattern(entries, CMD_INJECTION_PATTERNS, '명령어 인젝션 시도',
      '명령어 인젝션 성공 시 서버에서 임의 시스템 명령 실행이 가능해 파일 탈취, 백도어 설치, 랜섬웨어 배포 등 최고 위험 상황이 됩니다. 즉시 점검이 필요합니다.'),
    ...detectScanners(entries),
    ...detectHighErrorRate(entries),
    ...detectUnusualHours(entries),
    ...detectLargeResponse(entries),
  ].sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9))

  const httpEntries = entries.filter(e => e.type === 'http')
  const sshEntries  = entries.filter(e => e.type.startsWith('ssh'))
  const format = sshEntries.length > httpEntries.length ? 'ssh' : 'http'

  return {
    format,
    totalLines: lines.length,
    parsed: entries.length,
    parseErrors,
    uniqueIPs: new Set(entries.map(e => e.ip).filter(Boolean)).size,
    s2xx: httpEntries.filter(e => e.status >= 200 && e.status < 300).length,
    s4xx: httpEntries.filter(e => e.status >= 400 && e.status < 500).length,
    s5xx: httpEntries.filter(e => e.status >= 500).length,
    sshFails: sshEntries.filter(e => e.type === 'ssh_fail' || e.type === 'ssh_invalid').length,
    sshOk: sshEntries.filter(e => e.type === 'ssh_ok').length,
    findings,
  }
}

/* ─── Component ──────────────────────────────────── */
const SEV = {
  high:   { label: '위험', color: '#ef4444', bg: 'rgba(239,68,68,0.08)',  border: '#ef4444' },
  medium: { label: '주의', color: '#f59e0b', bg: 'rgba(245,158,11,0.08)', border: '#f59e0b' },
  low:    { label: '낮음', color: '#38bdf8', bg: 'rgba(56,189,248,0.08)', border: '#38bdf8' },
}

const SAMPLE_LOG = `192.168.1.50 - - [15/Jun/2024:03:21:44 +0000] "GET /admin?id=1'%20OR%20'1'='1 HTTP/1.1" 200 4321 "-" "sqlmap/1.7"
10.0.0.1 - - [15/Jun/2024:03:21:45 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
10.0.0.1 - - [15/Jun/2024:03:21:46 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
10.0.0.1 - - [15/Jun/2024:03:21:47 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
10.0.0.1 - - [15/Jun/2024:03:21:48 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
10.0.0.1 - - [15/Jun/2024:03:21:49 +0000] "POST /login HTTP/1.1" 401 0 "-" "Mozilla/5.0"
172.16.0.9 - - [15/Jun/2024:03:22:01 +0000] "GET /page?q=<script>alert(1)</script> HTTP/1.1" 400 162 "-" "Mozilla/5.0"
203.0.113.5 - - [15/Jun/2024:03:22:10 +0000] "GET /../../../../etc/passwd HTTP/1.1" 404 162 "-" "curl/7.68"
127.0.0.1 - - [15/Jun/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"`

export default function LogAnalysis() {
  const [input, setInput] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [expanded, setExpanded] = useState(() => new Set())

  const toggle = (i) => setExpanded(prev => {
    const next = new Set(prev)
    next.has(i) ? next.delete(i) : next.add(i)
    return next
  })

  const run = () => {
    setError('')
    setResult(null)
    setExpanded(new Set())
    const r = runAnalysis(input)
    if (!r) {
      setError('로그를 파싱할 수 없습니다. Apache/Nginx 접근 로그 또는 SSH 인증 로그 형식인지 확인하세요.')
      return
    }
    setResult(r)
  }

  const loadSample = () => {
    setInput(SAMPLE_LOG)
    setResult(null)
    setError('')
  }

  const counts = result && {
    high:   result.findings.filter(f => f.severity === 'high').length,
    medium: result.findings.filter(f => f.severity === 'medium').length,
    low:    result.findings.filter(f => f.severity === 'low').length,
  }

  return (
    <div className="la-page">
      <h2 className="la-title">📋 로그 분석</h2>
      <p className="la-sub">Apache/Nginx 접근 로그 또는 SSH 인증 로그를 붙여넣으세요. 이상 패턴을 자동으로 탐지합니다.</p>

      <div className="la-examples">
        <div className="la-example-label">지원 형식</div>
        <code>Apache/Nginx: 192.168.1.1 - - [01/Jan/2024:00:00:00 +0000] &quot;GET /path HTTP/1.1&quot; 200 1234 &quot;-&quot; &quot;UA&quot;</code>
        <code>SSH: Failed password for root from 10.0.0.1 port 52114 ssh2</code>
      </div>

      <div className="la-textarea-wrap">
        <textarea
          className="la-textarea"
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="로그 내용을 여기에 붙여넣으세요..."
          spellCheck={false}
        />
        <button className="la-sample-btn" onClick={loadSample}>샘플 로드</button>
      </div>

      <button className="la-btn" onClick={run} disabled={!input.trim()}>
        분석하기
      </button>

      {error && <div className="la-error">⚠️ {error}</div>}

      {result && (
        <div className="la-results">
          {/* Stats */}
          <div className="la-stats">
            <div className="la-stat">
              <div className="la-stat-val">{result.parsed.toLocaleString()}</div>
              <div className="la-stat-label">파싱된 로그</div>
            </div>
            <div className="la-stat">
              <div className="la-stat-val">{result.uniqueIPs}</div>
              <div className="la-stat-label">고유 IP</div>
            </div>
            {result.format === 'http' ? (
              <>
                <div className="la-stat">
                  <div className="la-stat-val" style={{ color: '#10b981' }}>{result.s2xx}</div>
                  <div className="la-stat-label">2xx 성공</div>
                </div>
                <div className="la-stat">
                  <div className="la-stat-val" style={{ color: '#f59e0b' }}>{result.s4xx}</div>
                  <div className="la-stat-label">4xx 오류</div>
                </div>
                <div className="la-stat">
                  <div className="la-stat-val" style={{ color: '#ef4444' }}>{result.s5xx}</div>
                  <div className="la-stat-label">5xx 오류</div>
                </div>
              </>
            ) : (
              <>
                <div className="la-stat">
                  <div className="la-stat-val" style={{ color: '#10b981' }}>{result.sshOk}</div>
                  <div className="la-stat-label">로그인 성공</div>
                </div>
                <div className="la-stat">
                  <div className="la-stat-val" style={{ color: '#ef4444' }}>{result.sshFails}</div>
                  <div className="la-stat-label">로그인 실패</div>
                </div>
              </>
            )}
          </div>

          {/* Header */}
          <div className="la-result-header">
            <span className="la-format-badge">
              {result.format === 'http' ? '🌐 웹 접근 로그' : '🔐 SSH 인증 로그'} 감지됨
            </span>
            <div className="la-counts">
              {counts.high   > 0 && <span className="la-count" style={{ background: '#ef4444' }}>{counts.high} 위험</span>}
              {counts.medium > 0 && <span className="la-count" style={{ background: '#f59e0b' }}>{counts.medium} 주의</span>}
              {counts.low    > 0 && <span className="la-count" style={{ background: '#38bdf8' }}>{counts.low} 낮음</span>}
            </div>
          </div>

          {/* Findings */}
          {result.findings.length === 0 ? (
            <div className="la-finding" style={{ borderLeft: '4px solid #10b981', background: 'rgba(16,185,129,0.08)' }}>
              <div className="la-finding-top">
                <span className="la-sev-badge" style={{ background: '#10b981' }}>안전</span>
                <span className="la-finding-title">이상 패턴 없음</span>
              </div>
              <div className="la-finding-detail">분석된 로그에서 의심스러운 패턴이 발견되지 않았습니다.</div>
            </div>
          ) : (
            <div className="la-findings">
              {result.findings.map((f, i) => (
                <div
                  key={i}
                  className="la-finding"
                  style={{ borderLeft: `4px solid ${SEV[f.severity].color}`, background: SEV[f.severity].bg }}
                >
                  <div
                    className="la-finding-top"
                    onClick={() => toggle(i)}
                    style={{ cursor: 'pointer' }}
                  >
                    <span className="la-sev-badge" style={{ background: SEV[f.severity].color }}>
                      {SEV[f.severity].label}
                    </span>
                    <span className="la-finding-title">{f.rule}</span>
                    <span className="la-finding-count">{f.count}건</span>
                    <span className="la-expand-icon">{expanded.has(i) ? '▲' : '▼'}</span>
                  </div>
                  <div className="la-finding-detail">{f.detail}</div>
                  {expanded.has(i) && (
                    <div className="la-finding-expanded">
                      <div className="la-finding-why">💡 {f.why}</div>
                      {f.samples.length > 0 && (
                        <div className="la-samples">
                          <div className="la-samples-label">샘플 요청</div>
                          {f.samples.map((s, si) => (
                            <code key={si} className="la-sample-line">{s}</code>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
