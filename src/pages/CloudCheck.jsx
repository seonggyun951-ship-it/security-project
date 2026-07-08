import { useState } from 'react'

const DANGEROUS_PORTS = {
  22:    { name: 'SSH',             why: 'SSH 포트 전체 오픈은 무차별 대입(brute force) 공격의 주요 타깃입니다. 특정 IP로 제한하거나 VPN을 사용하세요.' },
  23:    { name: 'Telnet',          why: 'Telnet은 암호화가 없어 자격 증명이 평문으로 전송됩니다. SSH로 대체하세요.' },
  21:    { name: 'FTP',             why: 'FTP는 자격 증명과 데이터를 평문 전송합니다. SFTP/FTPS를 사용하세요.' },
  3389:  { name: 'RDP',             why: 'RDP 전체 오픈은 랜섬웨어 공격의 주요 진입점입니다. 특정 IP 또는 VPN으로 제한하세요.' },
  3306:  { name: 'MySQL',           why: 'MySQL DB를 인터넷에 직접 노출하면 SQL 인젝션 및 무차별 대입 공격에 취약합니다.' },
  5432:  { name: 'PostgreSQL',      why: 'PostgreSQL DB를 인터넷에 직접 노출하면 무차별 대입 공격에 취약합니다.' },
  6379:  { name: 'Redis',           why: 'Redis는 기본 설정에 인증이 없어 인터넷 노출 시 데이터 탈취 및 원격 코드 실행 위험이 있습니다.' },
  27017: { name: 'MongoDB',         why: 'MongoDB 인터넷 노출은 인증 없이 DB 전체가 탈취될 수 있습니다.' },
  1433:  { name: 'MSSQL',           why: 'MSSQL DB를 인터넷에 직접 노출하면 무차별 대입 공격에 취약합니다.' },
  5900:  { name: 'VNC',             why: 'VNC는 암호화가 약해 인터넷 노출 시 원격 제어 탈취 위험이 있습니다.' },
  8080:  { name: 'HTTP Alt',        why: '대체 HTTP 포트 전체 오픈은 개발/관리 서버가 의도치 않게 노출될 수 있습니다.' },
  8443:  { name: 'HTTPS Alt',       why: '대체 HTTPS 포트 전체 오픈은 관리 패널이 외부에 노출될 수 있습니다.' },
  9200:  { name: 'Elasticsearch',   why: 'Elasticsearch 인터넷 노출은 인증 없이 전체 인덱스 데이터가 탈취될 수 있습니다.' },
  2375:  { name: 'Docker',          why: 'Docker daemon 포트 노출은 서버 전체 장악이 가능합니다. 즉시 차단하세요.' },
  2376:  { name: 'Docker TLS',      why: 'Docker TLS 포트도 제한 없이 노출 시 컨테이너/호스트 완전 장악 위험이 있습니다.' },
  11211: { name: 'Memcached',       why: 'Memcached 인터넷 노출은 DDoS 반사 증폭 공격 및 데이터 탈취에 취약합니다.' },
  7001:  { name: 'WebLogic',        why: 'WebLogic 포트 노출은 다수의 RCE 취약점의 직접 타깃이 됩니다.' },
  2181:  { name: 'ZooKeeper',       why: 'ZooKeeper 인터넷 노출은 분산 시스템 설정이 외부에 노출될 수 있습니다.' },
}

const SEV = {
  high:   { label: '위험', color: '#ef4444', bg: 'rgba(239,68,68,0.08)',  border: '#ef4444' },
  medium: { label: '주의', color: '#f59e0b', bg: 'rgba(245,158,11,0.08)', border: '#f59e0b' },
  low:    { label: '낮음', color: '#38bdf8', bg: 'rgba(56,189,248,0.08)', border: '#38bdf8' },
  ok:     { label: '안전', color: '#10b981', bg: 'rgba(16,185,129,0.08)', border: '#10b981' },
}

function expandPorts(portStr) {
  const s = String(portStr)
  if (s.includes('-')) {
    const [start, end] = s.split('-').map(Number)
    const ports = []
    for (let i = start; i <= Math.min(end, start + 200); i++) ports.push(i)
    return ports
  }
  return [Number(s)]
}

/* ─── AWS S3 ──────────────────────────────────────── */
function analyzeS3(data) {
  const findings = []

  const pac = data.PublicAccessBlockConfiguration
  if (!pac) {
    findings.push({ severity: 'high', title: '퍼블릭 접근 차단 설정 없음', detail: 'PublicAccessBlockConfiguration이 설정되지 않았습니다.', why: '버킷이 인터넷에 공개될 수 있어 민감 데이터가 누구나 접근 가능한 상태가 됩니다.' })
  } else {
    ;['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'].forEach(f => {
      if (pac[f] === false) findings.push({ severity: 'high', title: `${f} 비활성화`, detail: `${f}가 false로 설정되어 있습니다.`, why: '퍼블릭 ACL 또는 정책을 통해 버킷 데이터가 외부에 노출될 수 있습니다.' })
    })
  }

  if (data.ACL === 'public-read' || data.ACL === 'public-read-write') {
    findings.push({ severity: 'high', title: `버킷 ACL: ${data.ACL}`, detail: '버킷 ACL이 퍼블릭 읽기/쓰기로 설정되어 있습니다.', why: '인터넷상 누구나 버킷의 파일을 읽거나 업로드할 수 있습니다.' })
  }

  const rawPolicy = data.BucketPolicy || data.Policy
  if (rawPolicy) {
    try {
      const policy = typeof rawPolicy === 'string' ? JSON.parse(rawPolicy) : rawPolicy
      ;(policy?.Statement || []).forEach(stmt => {
        const p = stmt.Principal
        const isPublic = p === '*' || p?.AWS === '*' || (Array.isArray(p?.AWS) && p.AWS.includes('*'))
        if (isPublic && stmt.Effect === 'Allow') {
          findings.push({ severity: 'high', title: '버킷 정책에 퍼블릭 Principal 허용', detail: `Statement "${stmt.Sid || 'unnamed'}" — Principal: *`, why: '버킷 정책에서 모든 사용자(Principal: *)에게 허용하면 인증 없이 버킷에 접근 가능합니다.' })
        }
      })
    } catch {}
  }

  if (!data.ServerSideEncryptionConfiguration) {
    findings.push({ severity: 'high', title: '서버 사이드 암호화 미설정', detail: 'ServerSideEncryptionConfiguration이 없습니다.', why: '저장된 데이터가 암호화되지 않아 물리적 접근 또는 내부자 위협 시 데이터가 평문 노출됩니다.' })
  }

  const vc = data.VersioningConfiguration
  if (!vc || vc.Status !== 'Enabled') {
    findings.push({ severity: 'medium', title: '버전 관리 미사용', detail: '버전 관리가 활성화되어 있지 않습니다.', why: '파일 실수 삭제나 랜섬웨어 공격 시 이전 버전으로 복구가 불가능합니다.' })
  } else if (vc.MFADelete !== 'Enabled') {
    findings.push({ severity: 'low', title: 'MFA Delete 미활성화', detail: 'VersioningConfiguration.MFADelete가 Enabled가 아닙니다.', why: 'MFA Delete가 없으면 탈취된 자격 증명만으로 버전 기록까지 삭제해 복구 불가 상태로 만들 수 있습니다.' })
  }

  const logging = data.LoggingConfiguration
  if (!logging || (!logging.LoggingEnabled && !logging.TargetBucket)) {
    findings.push({ severity: 'low', title: '접근 로깅 미설정', detail: '버킷 접근 로그가 기록되지 않습니다.', why: '비인가 접근이 발생해도 감사 추적이 불가능해 침해 사고 대응이 어렵습니다.' })
  }

  const cors = data.CORSConfiguration || data.CORSRules
  if (cors) {
    const rules = Array.isArray(cors) ? cors : (cors.CORSRules || [cors])
    rules.forEach(rule => {
      const origins = rule.AllowedOrigins || rule.allowedOrigins || []
      if (origins.includes('*')) {
        findings.push({ severity: 'medium', title: 'CORS 와일드카드 오리진 허용', detail: 'AllowedOrigins: ["*"] — 모든 도메인 허용', why: 'CORS 와일드카드 설정은 모든 웹사이트에서 이 버킷에 크로스 오리진 요청을 보낼 수 있게 하여 데이터 탈취 위험을 높입니다.' })
      }
    })
  }

  if (findings.length === 0) findings.push({ severity: 'ok', title: '위험 설정 없음', detail: '검사 항목 모두 안전합니다.', why: '' })
  return findings
}

/* ─── GCP Firewall ────────────────────────────────── */
function analyzeGCP(raw) {
  const rules = Array.isArray(raw) ? raw : [raw]
  const findings = []
  const seen = new Set()

  rules.forEach(rule => {
    if (rule.disabled) return
    const isIngress = !rule.direction || rule.direction === 'INGRESS'
    const sources = rule.sourceRanges || []
    const hasAllOpen = sources.includes('0.0.0.0/0') || sources.includes('::/0')
    if (!isIngress || !hasAllOpen) return

    ;(rule.allowed || []).forEach(a => {
      if (a.IPProtocol === 'all') {
        const key = `${rule.name}-all`
        if (!seen.has(key)) {
          seen.add(key)
          findings.push({ severity: 'high', title: `"${rule.name}": 모든 포트 인터넷 전체 오픈`, detail: 'sourceRanges: 0.0.0.0/0, protocol: all', why: '인터넷 전체에서 서버의 모든 포트에 접근 가능합니다. 무차별 대입, 포트 스캔, 익스플로잇 시도에 그대로 노출됩니다.' })
        }
        return
      }

      const ports = a.ports || []
      if (ports.length === 0) {
        const key = `${rule.name}-${a.IPProtocol}-noPorts`
        if (!seen.has(key)) {
          seen.add(key)
          findings.push({ severity: 'high', title: `"${rule.name}": ${a.IPProtocol} 전체 인터넷 오픈`, detail: `sourceRanges: 0.0.0.0/0, protocol: ${a.IPProtocol} (포트 미지정 = 전체)`, why: '특정 포트 제한 없이 프로토콜 전체가 열려 있어 공격 표면이 매우 넓습니다.' })
        }
        return
      }

      ports.forEach(portStr => {
        expandPorts(portStr).forEach(port => {
          const key = `${rule.name}-${port}`
          if (seen.has(key)) return
          seen.add(key)
          const info = DANGEROUS_PORTS[port]
          if (info) {
            findings.push({ severity: 'high', title: `"${rule.name}": 위험 포트 ${port}(${info.name}) 인터넷 전체 오픈`, detail: `sourceRanges: 0.0.0.0/0 → tcp:${port}`, why: info.why })
          } else if (port !== 80 && port !== 443) {
            findings.push({ severity: 'medium', title: `"${rule.name}": 포트 ${port} 인터넷 전체 오픈`, detail: `sourceRanges: 0.0.0.0/0 → ${a.IPProtocol}:${port}`, why: '특정 IP로 제한하지 않으면 불필요한 공격 표면이 생깁니다. 허용 IP를 최소화하세요.' })
          }
        })
      })
    })
  })

  if (findings.length === 0) findings.push({ severity: 'ok', title: '위험 설정 없음', detail: '0.0.0.0/0 전체 오픈 인바운드 규칙이 없습니다.', why: '' })
  return findings
}

/* ─── AWS Security Group ──────────────────────────── */
function analyzeSecurityGroup(raw) {
  const groups = Array.isArray(raw) ? raw : (raw.SecurityGroups || [raw])
  const findings = []
  const seen = new Set()

  groups.forEach(sg => {
    const name = sg.GroupName ? `${sg.GroupName} (${sg.GroupId || ''})` : (sg.GroupId || 'Unknown')
    ;(sg.IpPermissions || []).forEach(perm => {
      const fromPort = perm.FromPort
      const toPort = perm.ToPort ?? fromPort
      const protocol = perm.IpProtocol

      const allRanges = [...(perm.IpRanges || []), ...(perm.Ipv6Ranges || [])]
      const isPublic = allRanges.some(r => r.CidrIp === '0.0.0.0/0' || r.CidrIpv6 === '::/0')
      if (!isPublic) return

      if (protocol === '-1' || fromPort === undefined || fromPort === null) {
        const key = `${name}-all`
        if (!seen.has(key)) {
          seen.add(key)
          findings.push({ severity: 'high', title: `"${name}": 모든 트래픽 인터넷 전체 오픈`, detail: 'IpProtocol: -1 (all), 0.0.0.0/0', why: '인터넷 전체에서 서버의 모든 포트에 접근 가능합니다. 즉시 특정 IP로 제한해야 합니다.' })
        }
        return
      }

      for (let port = fromPort; port <= Math.min(toPort, fromPort + 200); port++) {
        const key = `${name}-${port}`
        if (seen.has(key)) continue
        seen.add(key)
        const info = DANGEROUS_PORTS[port]
        if (info) {
          findings.push({ severity: 'high', title: `"${name}": 위험 포트 ${port}(${info.name}) 인터넷 전체 오픈`, detail: `0.0.0.0/0 → ${protocol}:${port}`, why: info.why })
        } else if (port !== 80 && port !== 443) {
          findings.push({ severity: 'medium', title: `"${name}": 포트 ${port} 인터넷 전체 오픈`, detail: `0.0.0.0/0 → ${protocol}:${port}`, why: '특정 IP로 제한하지 않으면 불필요한 공격 표면이 생깁니다.' })
        }
      }
    })
  })

  if (findings.length === 0) findings.push({ severity: 'ok', title: '위험 설정 없음', detail: '0.0.0.0/0 전체 오픈 인바운드 규칙이 없습니다.', why: '' })
  return findings
}

/* ─── Type Detection ─────────────────────────────── */
function detectType(data) {
  const arr = Array.isArray(data) ? data : [data]
  const first = arr[0] || {}
  if (first.sourceRanges !== undefined || first.allowed !== undefined || first.direction !== undefined) return 'gcp'
  if (first.IpPermissions !== undefined || first.GroupId !== undefined) return 'sg'
  if (first.SecurityGroups && Array.isArray(first.SecurityGroups)) return 'sg'
  if (
    first.PublicAccessBlockConfiguration !== undefined ||
    first.ACL !== undefined ||
    first.BucketName !== undefined ||
    first.ServerSideEncryptionConfiguration !== undefined ||
    first.BucketPolicy !== undefined ||
    first.CORSConfiguration !== undefined
  ) return 's3'
  return null
}

const TYPE_META = {
  s3:  { icon: '🪣', label: 'AWS S3 버킷' },
  gcp: { icon: '🔥', label: 'GCP 방화벽' },
  sg:  { icon: '🛡️', label: 'AWS Security Group' },
}

/* ─── Component ──────────────────────────────────── */
export default function CloudCheck() {
  const [input, setInput] = useState('')
  const [findings, setFindings] = useState(null)
  const [detectedType, setDetectedType] = useState(null)
  const [error, setError] = useState('')

  const analyze = () => {
    setError('')
    setFindings(null)
    try {
      const data = JSON.parse(input)
      const type = detectType(data)
      if (!type) {
        setError('S3 버킷, AWS Security Group, 또는 GCP 방화벽 JSON 형식을 인식하지 못했습니다. 아래 예시 명령어를 참고하세요.')
        return
      }
      setDetectedType(type)
      if (type === 's3') setFindings(analyzeS3(data))
      else if (type === 'gcp') setFindings(analyzeGCP(data))
      else setFindings(analyzeSecurityGroup(data))
    } catch {
      setError('JSON 파싱 오류: 올바른 JSON 형식인지 확인하세요.')
    }
  }

  const counts = findings && {
    high:   findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low:    findings.filter(f => f.severity === 'low').length,
    ok:     findings.filter(f => f.severity === 'ok').length,
  }

  return (
    <div className="cc-page">
      <h2 className="cc-title">☁️ 클라우드 설정 점검</h2>
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

      {error && <div className="cc-error">⚠️ {error}</div>}

      {findings && (
        <div className="cc-results">
          <div className="cc-result-header">
            <span className="cc-type-badge">
              {TYPE_META[detectedType].icon} {TYPE_META[detectedType].label} 감지됨
            </span>
            <div className="cc-counts">
              {counts.high   > 0 && <span className="cc-count" style={{ background: '#ef4444' }}>{counts.high} 위험</span>}
              {counts.medium > 0 && <span className="cc-count" style={{ background: '#f59e0b' }}>{counts.medium} 주의</span>}
              {counts.low    > 0 && <span className="cc-count" style={{ background: '#38bdf8' }}>{counts.low} 낮음</span>}
              {counts.ok     > 0 && <span className="cc-count" style={{ background: '#10b981' }}>{counts.ok} 안전</span>}
            </div>
          </div>

          <div className="cc-findings">
            {['high', 'medium', 'low', 'ok'].flatMap(sev =>
              findings
                .filter(f => f.severity === sev)
                .map((f, i) => (
                  <div
                    key={`${sev}-${i}`}
                    className="cc-finding"
                    style={{ borderLeft: `4px solid ${SEV[sev].color}`, background: SEV[sev].bg }}
                  >
                    <div className="cc-finding-top">
                      <span className="cc-sev-badge" style={{ background: SEV[sev].color }}>
                        {SEV[sev].label}
                      </span>
                      <span className="cc-finding-title">{f.title}</span>
                    </div>
                    <div className="cc-finding-detail">{f.detail}</div>
                    {f.why && <div className="cc-finding-why">💡 {f.why}</div>}
                  </div>
                ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}
