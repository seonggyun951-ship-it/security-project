// 클라우드 설정 위험도 판정 엔진.
//
// 화면과 분리해 둔 이유:
//   1) JSX 파일 안에 있으면 브라우저 밖(Node 스크립트)에서 import할 수 없다.
//      RAG 학습 데이터를 만들려면 시나리오 수천 건을 일괄로 판정해야 한다.
//   2) 같은 규칙을 화면과 데이터 생성이 함께 써야 한다. 복사해두면 한쪽만 고쳐져
//      화면이 보여주는 판정과 학습된 판정이 갈라진다.
//
// 순수 함수만 둔다 — React, DOM, 네트워크 호출 금지.

export const DANGEROUS_PORTS = {
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

// 심각도는 높은 것부터. 화면 정렬과 집계가 이 순서를 따른다.
export const SEVERITY_ORDER = ['high', 'medium', 'low', 'ok']

export const SEVERITY_LABEL = {
  high: '위험',
  medium: '주의',
  low: '낮음',
  ok: '안전',
}

// "5000-5010" 또는 "3389" → [시작, 끝]
export function parsePortRange(portStr) {
  const s = String(portStr)
  if (s.includes('-')) {
    const [start, end] = s.split('-').map(Number)
    return [start, end]
  }
  const n = Number(s)
  return [n, n]
}

// 웹 서비스용이라 전체 개방이어도 지적하지 않는 포트
export const WEB_PORTS = [80, 443]

// 열린 포트 구간 하나를 판정한다.
//
// 규칙 하나가 결과 하나로 떨어지도록 묶는다. 예전에는 5000-5010을 열면
// 거의 같은 내용의 '주의'가 11건 나왔다 — 화면도 지저분하고, 이 판정이
// 그대로 RAG 학습 데이터가 되면 같은 줄이 수백 개 쌓인다.
//
// 다만 범위 안에 위험 포트(21 FTP, 22 SSH 등)가 섞여 있으면 그것만은
// 따로 짚어준다. "20-25 열림"으로 뭉뚱그리면 SSH가 열린 걸 놓친다.
function portRangeFindings(label, protocol, fromPort, toPort, source) {
  const findings = []

  // 범위 전체를 훑지 않고 위험 포트 목록(18개)만 대조한다.
  // 1024-65535 같은 넓은 범위에서도 비용이 일정하다.
  const dangerous = Object.keys(DANGEROUS_PORTS)
    .map(Number)
    .filter((p) => p >= fromPort && p <= toPort)
    .sort((a, b) => a - b)

  for (const port of dangerous) {
    const info = DANGEROUS_PORTS[port]
    findings.push({
      severity: 'high',
      title: `"${label}": 위험 포트 ${port}(${info.name}) 인터넷 전체 오픈`,
      detail: `${source} → ${protocol}:${port}`,
      why: info.why,
    })
  }

  const total = toPort - fromPort + 1
  const isSingle = total === 1

  // 웹 포트만 딱 열었으면 막지 않는다. 외부 공개 서비스라면 그게 목적이기 때문이다.
  // 다만 사내용을 실수로 연 것일 수도 있어 관리자가 보도록 '주의'로 남긴다.
  // (80-443처럼 범위로 열면 사이 300여 개가 같이 열리므로 아래 일반 경로로 간다)
  if (isSingle && WEB_PORTS.includes(fromPort)) {
    findings.push({
      severity: 'medium',
      title: `"${label}": 웹 포트 ${fromPort} 인터넷 전체 오픈`,
      detail: `${source} → ${protocol}:${fromPort}`,
      why: '외부에 공개하는 서비스라면 정상입니다. 사내용이라면 ALB·CloudFront 뒤에 두거나 접근 대역을 제한하세요.',
    })
    return findings
  }

  const rest = total - dangerous.length
  if (rest <= 0) return findings

  const portLabel = isSingle ? String(fromPort) : `${fromPort}-${toPort}`
  const excluded = []
  if (dangerous.length) excluded.push(`위험 포트 ${dangerous.length}개는 위에 따로 표시`)

  findings.push({
    severity: 'medium',
    title: isSingle
      ? `"${label}": 포트 ${portLabel} 인터넷 전체 오픈`
      : `"${label}": 포트 ${portLabel} 인터넷 전체 오픈 (${rest}개)`,
    detail: `${source} → ${protocol}:${portLabel}`,
    why: '특정 IP로 제한하지 않으면 불필요한 공격 표면이 생깁니다. 허용 IP를 최소화하세요.'
      + (excluded.length ? ` (${excluded.join(' / ')})` : ''),
  })
  return findings
}

/* ─── AWS S3 ──────────────────────────────────────── */
export function analyzeS3(data) {
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
    } catch (e) {
      // 파싱 실패를 조용히 넘기면 "정책에 문제 없음"으로 보인다. 점검하지 못했다는 사실을 드러내야 한다.
      findings.push({
        severity: 'medium',
        title: '버킷 정책을 해석하지 못했습니다',
        detail: `JSON 파싱 실패: ${e.message}`,
        why: '정책을 읽지 못해 퍼블릭 접근 허용 여부를 점검하지 못했습니다. 정책 원문을 직접 확인해주세요.',
      })
    }
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
export function analyzeGCP(raw) {
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
        const [from, to] = parsePortRange(portStr)
        const key = `${rule.name}-${from}-${to}`
        if (seen.has(key)) return
        seen.add(key)
        findings.push(...portRangeFindings(rule.name, a.IPProtocol, from, to, 'sourceRanges: 0.0.0.0/0'))
      })
    })
  })

  if (findings.length === 0) findings.push({ severity: 'ok', title: '위험 설정 없음', detail: '0.0.0.0/0 전체 오픈 인바운드 규칙이 없습니다.', why: '' })
  return findings
}

/* ─── AWS Security Group ──────────────────────────── */
export function analyzeSecurityGroup(raw) {
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

      const key = `${name}-${fromPort}-${toPort}`
      if (seen.has(key)) return
      seen.add(key)
      findings.push(...portRangeFindings(name, protocol, fromPort, toPort, '0.0.0.0/0'))
    })
  })

  if (findings.length === 0) findings.push({ severity: 'ok', title: '위험 설정 없음', detail: '0.0.0.0/0 전체 오픈 인바운드 규칙이 없습니다.', why: '' })
  return findings
}

/* ─── 종류 판별 ───────────────────────────────────── */
export function detectType(data) {
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

export const TYPE_META = {
  s3:  { label: 'AWS S3 버킷' },
  gcp: { label: 'GCP 방화벽' },
  sg:  { label: 'AWS Security Group' },
}

const ANALYZERS = { s3: analyzeS3, gcp: analyzeGCP, sg: analyzeSecurityGroup }

// 종류를 알아서 판별하고 판정까지 한 번에. 화면과 일괄 라벨링이 같은 입구를 쓴다.
// 인식하지 못하는 형식이면 type: null, findings: [] 로 돌려준다 (예외를 던지지 않는다).
export function analyzeConfig(data) {
  const type = detectType(data)
  if (!type) return { type: null, findings: [] }
  return { type, findings: ANALYZERS[type](data) }
}

/* ─── 신청 점검 ───────────────────────────────────── */
//
// 신청이 관리자에게 가기 전에 자동으로 한 번 거른다.
// 예전에는 이 검사가 aws-request-apply(승인 후 적용 시점)에만 있어서,
// 관리자가 통과 못 할 신청인 줄 모르고 승인 버튼을 누르고 나서야 실패했다.

export const REQUEST_POLICY = {
  MIN_CIDR_PREFIX: 24,   // /24 이상만 허용 (/0~/23은 너무 넓다)
  MAX_RULES: 50,
  SENSITIVE_PORTS: [22, 3389, 3306, 5432, 1433, 6379, 27017],
}

// 환경별 접근 권한. Terraform으로 만들어 둔 그룹·역할과 짝이 맞아야 한다
// (terraform/envs/iam). 그룹에 들어가면 그 역할을 맡아 임시 키를 받는다.
//
// aws.jsx가 아니라 여기 두는 이유: JSX 파일에 있으면 Node에서 import할 수 없어
// 학습 자료를 만들 때 값을 손으로 옮겨 적게 된다. 그러면 정책을 바꿨을 때
// 문서만 옛날 값으로 남는다.
export const ENVIRONMENTS = [
  { key: 'dev',  label: '개발 (vpc-dev)',   can: '생성·수정·삭제', needsSuper: false },
  { key: 'qa',   label: 'QA (vpc-qa)',      can: '생성·수정 (삭제 불가)', needsSuper: false },
  { key: 'prod', label: '운영 (vpc-prod)',  can: '조회만', needsSuper: true },
  { key: 'db',   label: '개인정보 (vpc-db)', can: '조회만', needsSuper: true },
]

export const envMeta = (key) => ENVIRONMENTS.find((e) => e.key === key)

// IAM만으로는 "db는 소수에게만"을 표현할 수 없어 승인 절차로 지킨다.
// 실제 강제는 Edge Function이 하고, 이건 화면 안내용이다.
export const envNeedsSuper = (key) => !!envMeta(key)?.needsSuper

// 신청 폼의 규칙 { direction, protocol, from_port, to_port, cidr } 을
// 점검 엔진이 읽는 AWS 응답 형태로 바꾼다.
function toAwsShape(rules) {
  return {
    GroupId: '신청한 규칙',
    IpPermissions: rules
      .filter((r) => r.direction === 'ingress')
      .map((r) => ({
        IpProtocol: r.protocol,
        FromPort: r.from_port,
        ToPort: r.to_port ?? r.from_port,
        IpRanges: [{ CidrIp: r.cidr }],
      })),
  }
}

// SG 신청 하나를 점검한다. 반환은 화면 점검과 같은 finding 배열.
export function checkSgRules(rules = []) {
  // 전체 개방·위험 포트는 이미 있는 엔진이 판정한다 (같은 규칙을 두 벌 쓰지 않기 위해)
  const findings = analyzeSecurityGroup(toAwsShape(rules)).filter((f) => f.severity !== 'ok')

  for (const r of rules) {
    const cidr = String(r.cidr || '')
    const isPublic = cidr === '0.0.0.0/0' || cidr === '::/0'
    if (isPublic) continue // 위에서 이미 '위험'으로 잡혔다

    const prefix = parseInt(cidr.split('/')[1])
    if (!isNaN(prefix) && prefix < REQUEST_POLICY.MIN_CIDR_PREFIX) {
      findings.push({
        severity: 'high',
        title: `CIDR ${cidr}: 허용 범위가 너무 넓습니다`,
        detail: `현재 /${prefix} — /${REQUEST_POLICY.MIN_CIDR_PREFIX} 이상만 허용됩니다`,
        why: `/${prefix}는 IP ${Math.pow(2, 32 - prefix).toLocaleString()}개를 포함합니다. 실제로 접속할 대역만 남기세요.`,
      })
      continue
    }

    if (r.direction !== 'ingress') continue
    const from = r.from_port
    const to = r.to_port ?? from
    const hit = REQUEST_POLICY.SENSITIVE_PORTS.filter((p) => p >= from && p <= to)
    for (const port of hit) {
      const info = DANGEROUS_PORTS[port]
      findings.push({
        severity: 'medium',
        title: `포트 ${port}(${info?.name || ''}) 인바운드는 관리자 확인이 필요합니다`,
        detail: `${cidr} → ${r.protocol}:${port}`,
        why: info?.why || '민감 포트는 허용 대역이 좁아도 관리자가 직접 확인합니다.',
      })
    }
  }

  if (rules.length > REQUEST_POLICY.MAX_RULES) {
    findings.push({
      severity: 'high',
      title: `규칙이 ${rules.length}개입니다`,
      detail: `한 번에 ${REQUEST_POLICY.MAX_RULES}개까지 신청할 수 있습니다`,
      why: '규칙이 많으면 검토가 어렵고 실수가 섞이기 쉽습니다. 나눠서 신청하세요.',
    })
  }

  return findings
}

// 점검 결과 → 처리 방향
//   reject : 위험이 있어 접수하지 않는다 (신청자가 고쳐서 다시)
//   warn   : 접수하되 사유를 붙여 관리자에게 넘긴다
//   pass   : 그냥 대기열로
export function requestVerdict(findings) {
  const { counts } = summarize(findings)
  if (counts.high > 0) return 'reject'
  if (counts.medium > 0) return 'warn'
  return 'pass'
}

// 신청 종류에 맞는 점검기를 고른다. 점검 대상이 아니면 null.
export function checkRequest(action, payload = {}) {
  if (action === 'create_sg' || action === 'add_rules') {
    const findings = checkSgRules(payload.rules || [])
    return { findings, verdict: requestVerdict(findings) }
  }
  return null
}

// 판정 결과 요약 — 심각도별 건수와 최고 심각도
export function summarize(findings) {
  const counts = { high: 0, medium: 0, low: 0, ok: 0 }
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1
  const worst = SEVERITY_ORDER.find((s) => s !== 'ok' && counts[s] > 0) || 'ok'
  return { counts, worst }
}
