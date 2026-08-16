// 규칙 엔진으로 RAG 학습 자료를 만든다.
//
// 설정을 조합해서 만들고 → src/lib/rules.js에 통과시켜 판정을 받고 →
// (설정, 판정, 이유) 한 덩어리의 한국어 문장으로 바꾼다.
//
// 판정은 화면이 쓰는 그 엔진이 그대로 내린다. 여기서 규칙을 다시 쓰지 않는 이유는,
// 두 벌이 되면 한쪽만 고쳐져 화면 판정과 학습된 판정이 갈라지기 때문이다.
// (그래서 rules.js를 CloudCheck.jsx에서 떼어냈다)
//
// 사용법:
//   node scripts/rag/build-rule-dataset.mjs            # 만들어서 파일로만 저장
//   node scripts/rag/build-rule-dataset.mjs --push     # 만들고 지식 베이스에 적재
//     (--push 시 SB_SERVICE_KEY 환경변수 필요)

import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import {
  analyzeSecurityGroup, analyzeS3, analyzeGCP,
  checkSgRules, requestVerdict, summarize,
  SEVERITY_LABEL, DANGEROUS_PORTS,
} from '../../src/lib/rules.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const OUT = resolve(HERE, 'rule-dataset.json')
const FN_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/rag-index'

/* ─── 조합 재료 ──────────────────────────────────── */

// 위험 포트 전부 + 흔히 쓰는 일반 포트 몇 개
const PORTS = [
  ...Object.keys(DANGEROUS_PORTS).map(Number),
  80, 443, 3000, 8000, 9000, 5000,
].sort((a, b) => a - b)

const SOURCES = [
  { cidr: '0.0.0.0/0', desc: '인터넷 전체' },
  { cidr: '10.0.0.0/8', desc: '사내망 전체(/8)' },
  { cidr: '172.31.0.0/16', desc: '사내 대역(/16)' },
  { cidr: '10.0.1.0/24', desc: '특정 서브넷(/24)' },
  { cidr: '192.168.1.0/25', desc: '좁은 대역(/25)' },
  { cidr: '10.0.1.50/32', desc: '단일 호스트(/32)' },
]

const PORT_RANGES = [
  { from: 20, to: 25, desc: 'FTP·SSH·Telnet이 포함된 구간' },
  { from: 5000, to: 5010, desc: '연속된 애플리케이션 포트' },
  { from: 1024, to: 65535, desc: '비특권 포트 전체' },
  { from: 80, to: 443, desc: '웹 포트 사이 전 구간' },
]

const docs = []
const add = (source, ref, content, meta) => docs.push({ source, ref, content, meta })

// findings 배열 → 사람이 읽는 판정/이유 문장
function verdictText(findings) {
  const { worst } = summarize(findings)
  const real = findings.filter((f) => f.severity !== 'ok')
  if (real.length === 0) return { label: '안전', reasons: ['지적할 설정이 없습니다.'] }
  return {
    label: SEVERITY_LABEL[worst],
    reasons: real.map((f) => `${f.title} — ${f.why}`),
  }
}

/* ─── 1. SG 단일 포트 ────────────────────────────── */

// 아무 지적도 없는 조합(좁은 대역 + 평범한 포트)은 내용이 전부 같아진다.
// 다 넣으면 검색 결과를 이런 것들이 채워버리므로 대표만 남긴다.
let plainSafeKept = 0
const PLAIN_SAFE_LIMIT = 12

for (const port of PORTS) {
  for (const src of SOURCES) {
    const sg = {
      GroupId: 'example-sg',
      IpPermissions: [{
        IpProtocol: 'tcp', FromPort: port, ToPort: port,
        IpRanges: [{ CidrIp: src.cidr }],
      }],
    }
    const audit = analyzeSecurityGroup(sg).filter((f) => f.severity !== 'ok')
    const info = DANGEROUS_PORTS[port]
    const portName = info ? `${port}번(${info.name})` : `${port}번`

    // 신청 화면이 이 설정을 접수할지, 접수한다면 왜 그런지.
    // 신청자가 "왜 반려됐나요"라고 물었을 때 근거가 되는 부분이다.
    const rules = [{ direction: 'ingress', protocol: 'tcp', from_port: port, to_port: port, cidr: src.cidr }]
    const checked = checkSgRules(rules)
    const verdict = requestVerdict(checked)
    const verdictKo = { reject: '반려', warn: '접수 — 관리자 확인 필요', pass: '접수' }[verdict]

    const plainSafe = audit.length === 0 && verdict === 'pass'
    if (plainSafe && ++plainSafeKept > PLAIN_SAFE_LIMIT) continue

    // 두 점검은 보는 범위가 다르다. 한쪽을 그냥 '안전'이라고만 적으면
    // "안전인데 반려"처럼 읽혀 모순으로 학습된다. 각자 무엇을 봤는지 밝힌다.
    const exposure = audit.length > 0
      ? audit.map((f) => `${f.title} — ${f.why}`).join(' / ')
      : src.cidr === '0.0.0.0/0'
        ? '지적 사항 없음'
        : '해당 없음 (0.0.0.0/0이 아니라 인터넷에 직접 열리지는 않음)'

    const reason = checked.length > 0
      ? checked.map((f) => `${f.title} — ${f.why}`).join(' / ')
      : '허용 대역이 좁고 민감 포트도 아니라 그대로 접수됩니다.'

    add('rule_engine', `sg-${port}-${src.cidr.replace(/[./]/g, '_')}`,
      [
        `설정: AWS 보안 그룹에 인바운드 규칙 추가 — TCP ${portName} 포트를 ${src.cidr}(${src.desc})에서 허용.`,
        `인터넷 노출 점검: ${exposure}`,
        `신청 처리: ${verdictKo}`,
        `사유: ${reason}`,
      ].join('\n'),
      {
        kind: 'sg_single_port', port, cidr: src.cidr,
        severity: audit.length ? SEVERITY_LABEL[summarize(audit).worst] : '안전',
        request_verdict: verdict,
      },
    )
  }
}

/* ─── 2. SG 포트 범위 ────────────────────────────── */

for (const range of PORT_RANGES) {
  for (const src of [SOURCES[0], SOURCES[3]]) { // 전체 개방 / 특정 서브넷
    const sg = {
      GroupId: 'example-sg',
      IpPermissions: [{
        IpProtocol: 'tcp', FromPort: range.from, ToPort: range.to,
        IpRanges: [{ CidrIp: src.cidr }],
      }],
    }
    const { label, reasons } = verdictText(analyzeSecurityGroup(sg))
    add('rule_engine', `sg-range-${range.from}-${range.to}-${src.cidr.replace(/[./]/g, '_')}`,
      [
        `설정: AWS 보안 그룹에 인바운드 규칙 추가 — TCP ${range.from}-${range.to} 포트 구간(${range.desc})을 ${src.cidr}(${src.desc})에서 허용.`,
        `판정: ${label}`,
        `이유: ${reasons.join(' / ')}`,
      ].join('\n'),
      { kind: 'sg_port_range', from: range.from, to: range.to, cidr: src.cidr, severity: label },
    )
  }
}

/* ─── 3. SG 전체 프로토콜 개방 ───────────────────── */

for (const src of SOURCES) {
  const sg = {
    GroupId: 'example-sg',
    IpPermissions: [{ IpProtocol: '-1', IpRanges: [{ CidrIp: src.cidr }] }],
  }
  const { label, reasons } = verdictText(analyzeSecurityGroup(sg))
  add('rule_engine', `sg-all-${src.cidr.replace(/[./]/g, '_')}`,
    [
      `설정: AWS 보안 그룹에 인바운드 규칙 추가 — 모든 프로토콜·모든 포트를 ${src.cidr}(${src.desc})에서 허용.`,
      `판정: ${label}`,
      `이유: ${reasons.join(' / ')}`,
    ].join('\n'),
    { kind: 'sg_all_traffic', cidr: src.cidr, severity: label },
  )
}

/* ─── 4. S3 버킷 설정 ───────────────────────────── */

const S3_CASES = [
  { ref: 's3-all-open', desc: '퍼블릭 접근 차단 없음 + 퍼블릭 읽기 ACL',
    data: { BucketName: 'b', ACL: 'public-read' } },
  { ref: 's3-block-partial', desc: '차단 설정 일부만 켜짐',
    data: { BucketName: 'b', PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: false, BlockPublicPolicy: false, RestrictPublicBuckets: true }, ServerSideEncryptionConfiguration: {}, VersioningConfiguration: { Status: 'Enabled', MFADelete: 'Enabled' }, LoggingConfiguration: { TargetBucket: 'log' } } },
  { ref: 's3-policy-public', desc: '버킷 정책에 Principal * 허용',
    data: { BucketName: 'b', PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true }, BucketPolicy: { Statement: [{ Sid: 'Public', Effect: 'Allow', Principal: '*', Action: 's3:GetObject' }] }, ServerSideEncryptionConfiguration: {}, VersioningConfiguration: { Status: 'Enabled', MFADelete: 'Enabled' }, LoggingConfiguration: { TargetBucket: 'log' } } },
  { ref: 's3-no-encryption', desc: '암호화 미설정',
    data: { BucketName: 'b', PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true }, VersioningConfiguration: { Status: 'Enabled', MFADelete: 'Enabled' }, LoggingConfiguration: { TargetBucket: 'log' } } },
  { ref: 's3-no-versioning', desc: '버전 관리 미사용',
    data: { BucketName: 'b', PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true }, ServerSideEncryptionConfiguration: {}, LoggingConfiguration: { TargetBucket: 'log' } } },
  { ref: 's3-cors-wildcard', desc: 'CORS 와일드카드 오리진',
    data: { BucketName: 'b', PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true }, ServerSideEncryptionConfiguration: {}, VersioningConfiguration: { Status: 'Enabled', MFADelete: 'Enabled' }, LoggingConfiguration: { TargetBucket: 'log' }, CORSConfiguration: { CORSRules: [{ AllowedOrigins: ['*'] }] } } },
  { ref: 's3-clean', desc: '권장 설정을 모두 갖춘 버킷',
    data: { BucketName: 'b', PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true }, ServerSideEncryptionConfiguration: {}, VersioningConfiguration: { Status: 'Enabled', MFADelete: 'Enabled' }, LoggingConfiguration: { TargetBucket: 'log' } } },
]

for (const c of S3_CASES) {
  const { label, reasons } = verdictText(analyzeS3(c.data))
  add('rule_engine', c.ref,
    [
      `설정: AWS S3 버킷 — ${c.desc}.`,
      `판정: ${label}`,
      `이유: ${reasons.join(' / ')}`,
    ].join('\n'),
    { kind: 's3', severity: label },
  )
}

/* ─── 5. GCP 방화벽 ─────────────────────────────── */

for (const port of [22, 3389, 3306, 80, 443, 9000]) {
  for (const src of [SOURCES[0], SOURCES[3]]) {
    const rule = [{
      name: 'example-rule', direction: 'INGRESS',
      sourceRanges: [src.cidr],
      allowed: [{ IPProtocol: 'tcp', ports: [String(port)] }],
    }]
    const { label, reasons } = verdictText(analyzeGCP(rule))
    const info = DANGEROUS_PORTS[port]
    add('rule_engine', `gcp-${port}-${src.cidr.replace(/[./]/g, '_')}`,
      [
        `설정: GCP 방화벽 인바운드 규칙 — TCP ${port}번${info ? `(${info.name})` : ''} 포트를 ${src.cidr}(${src.desc})에서 허용.`,
        `판정: ${label}`,
        `이유: ${reasons.join(' / ')}`,
      ].join('\n'),
      { kind: 'gcp_firewall', port, cidr: src.cidr, severity: label },
    )
  }
}

// 전체 프로토콜
{
  const rule = [{ name: 'allow-all', direction: 'INGRESS', sourceRanges: ['0.0.0.0/0'], allowed: [{ IPProtocol: 'all' }] }]
  const { label, reasons } = verdictText(analyzeGCP(rule))
  add('rule_engine', 'gcp-all-open',
    [
      '설정: GCP 방화벽 인바운드 규칙 — 모든 프로토콜을 0.0.0.0/0(인터넷 전체)에서 허용.',
      `판정: ${label}`,
      `이유: ${reasons.join(' / ')}`,
    ].join('\n'),
    { kind: 'gcp_firewall', severity: label },
  )
}

/* ─── 출력 ──────────────────────────────────────── */

const bySeverity = {}
for (const d of docs) {
  const s = d.meta.severity || '-'
  bySeverity[s] = (bySeverity[s] || 0) + 1
}

writeFileSync(OUT, JSON.stringify(docs, null, 2))
console.log(`생성: ${docs.length}건 → ${OUT}`)
console.log('판정 분포:', Object.entries(bySeverity).map(([k, v]) => `${k} ${v}`).join(', '))

if (!process.argv.includes('--push')) {
  console.log('\n적재하려면 --push (SB_SERVICE_KEY 필요)')
  process.exit(0)
}

const key = process.env.SB_SERVICE_KEY
if (!key) {
  console.error('SB_SERVICE_KEY가 없습니다')
  process.exit(1)
}

// Edge Function이 배치를 나눠 임베딩하지만, 한 요청이 너무 커지지 않게 여기서도 쪼갠다.
const CHUNK = 100
let sent = 0
for (let i = 0; i < docs.length; i += CHUNK) {
  const slice = docs.slice(i, i + CHUNK)
  const res = await fetch(FN_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ documents: slice }),
  })
  const body = await res.json()
  if (!body.ok) {
    console.error(`적재 실패 (${i}~${i + slice.length}):`, body.error || JSON.stringify(body.failures))
    continue
  }
  sent += body.inserted
  console.log(`  ${i + slice.length}/${docs.length} 적재됨`)
}
console.log(`\n적재 완료: ${sent}건`)
