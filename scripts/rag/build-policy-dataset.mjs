// 이 시스템의 정책을 설명하는 문서를 만든다.
//
// 값을 손으로 적지 않는다. rules.js 상수와 Terraform 파일에서 읽어 문장을 만든다.
// 정책을 바꾸면 이 스크립트를 다시 돌리는 것만으로 문서가 따라온다.
// 손으로 적으면 정책은 바뀌었는데 문서만 옛날 값으로 남고, LLM은 그 옛날 값을
// 확신에 차서 말하게 된다.
//
// 사용법:
//   node scripts/rag/build-policy-dataset.mjs           # 만들어서 파일로만
//   node scripts/rag/build-policy-dataset.mjs --push    # 적재까지

import { writeFileSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { REQUEST_POLICY, WEB_PORTS, DANGEROUS_PORTS, ENVIRONMENTS } from '../../src/lib/rules.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '../..')
const OUT = resolve(HERE, 'policy-dataset.json')
const FN_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/rag-index'

// Terraform 값은 HCL이라 import할 수 없다. 파일에서 뽑아 쓴다.
// 값이 안 잡히면 추측해서 넣지 말고 멈춘다 — 틀린 값이 학습되는 것보다 낫다.
function fromTerraform(file, pattern, label) {
  const text = readFileSync(resolve(ROOT, file), 'utf8')
  const m = text.match(pattern)
  if (!m) throw new Error(`${label}을(를) ${file}에서 찾지 못했습니다. 스크립트를 고쳐주세요.`)
  return m[1]
}

const sessionSeconds = Number(fromTerraform(
  'terraform/envs/iam/roles.tf',
  /max_session_duration\s*=\s*(\d+)/,
  '역할 세션 시간',
))

const cronSchedule = fromTerraform(
  'supabase/migrations/20260816040000_expiry_cron.sql',
  /'expire-access-daily',\s*'([^']+)'/,
  '만료 배치 주기',
)

// 만료 선택지도 화면 코드에서 읽는다
const expiryOptions = [...readFileSync(resolve(ROOT, 'src/pages/forms/EnvAccessForm.jsx'), 'utf8')
  .matchAll(/\{\s*value:\s*'(\d*)',\s*label:\s*'([^']+)'\s*\}/g)]
  .map((m) => m[2])

const docs = []
const add = (ref, content, meta = {}) =>
  docs.push({ source: 'policy', ref, content, meta })

const ipCount = (prefix) => Math.pow(2, 32 - prefix).toLocaleString('ko-KR')
const portName = (p) => (DANGEROUS_PORTS[p] ? `${p}번(${DANGEROUS_PORTS[p].name})` : `${p}번`)

/* ─── 신청 점검 정책 ─────────────────────────────── */

add('policy-cidr',
  [
    '이 시스템의 보안 그룹 신청 정책 — 허용 대역 폭',
    '',
    `인바운드 규칙의 출발지는 /${REQUEST_POLICY.MIN_CIDR_PREFIX} 이상으로 좁혀야 접수됩니다.`,
    `/${REQUEST_POLICY.MIN_CIDR_PREFIX}보다 넓은 대역(/0 ~ /${REQUEST_POLICY.MIN_CIDR_PREFIX - 1})은 자동으로 반려됩니다.`,
    `예를 들어 /16은 IP ${ipCount(16)}개, /8은 ${ipCount(8)}개를 포함하므로 반려됩니다.`,
    `/${REQUEST_POLICY.MIN_CIDR_PREFIX}는 ${ipCount(REQUEST_POLICY.MIN_CIDR_PREFIX)}개, /32는 1개입니다.`,
    '반려된 신청은 관리자에게 전달되지 않습니다. 신청자가 대역을 좁혀 다시 신청해야 합니다.',
  ].join('\n'),
  { kind: 'request_policy', min_prefix: REQUEST_POLICY.MIN_CIDR_PREFIX })

add('policy-sensitive-ports',
  [
    '이 시스템의 보안 그룹 신청 정책 — 민감 포트',
    '',
    `다음 포트는 인바운드로 열 때 관리자가 직접 확인합니다: ${REQUEST_POLICY.SENSITIVE_PORTS.map(portName).join(', ')}.`,
    '허용 대역이 충분히 좁아도 자동 통과되지 않고, 주의 표시와 함께 접수되어 관리자 판단을 받습니다.',
    '관리자가 승인 버튼을 누른 것이 곧 수동 승인입니다.',
  ].join('\n'),
  { kind: 'request_policy', ports: REQUEST_POLICY.SENSITIVE_PORTS })

add('policy-web-ports',
  [
    '이 시스템의 보안 그룹 신청 정책 — 웹 포트 예외',
    '',
    `${WEB_PORTS.join('번과 ')}번 포트만 단독으로 여는 경우는 0.0.0.0/0(인터넷 전체)이어도 반려하지 않습니다.`,
    '외부에 공개하는 웹 서비스라면 그것이 목적이기 때문입니다.',
    '다만 사내용을 실수로 연 것일 수 있어 주의로 표시되고 관리자가 확인합니다.',
    `포트를 범위로 지정하면(예: ${WEB_PORTS[0]}-${WEB_PORTS[1]}) 사이의 다른 포트도 함께 열리므로 이 예외가 적용되지 않습니다.`,
  ].join('\n'),
  { kind: 'request_policy', web_ports: WEB_PORTS })

add('policy-max-rules',
  [
    '이 시스템의 보안 그룹 신청 정책 — 규칙 수 제한',
    '',
    `한 번에 신청할 수 있는 규칙은 ${REQUEST_POLICY.MAX_RULES}개까지입니다.`,
    '이보다 많으면 반려되며, 나누어 신청해야 합니다.',
    '규칙이 많으면 검토가 어렵고 그 안에 실수가 섞이기 쉽기 때문입니다.',
  ].join('\n'),
  { kind: 'request_policy', max_rules: REQUEST_POLICY.MAX_RULES })

add('policy-verdicts',
  [
    '이 시스템의 신청 처리 단계',
    '',
    '신청은 접수되기 전에 규칙 엔진이 한 번 검사합니다. 결과는 세 가지입니다.',
    '반려 — 접수하지 않고 사유를 보여줍니다. 신청자가 고쳐서 다시 냅니다.',
    '주의 — 사유를 붙여 접수하고, 관리자가 그 사유를 보며 판단합니다.',
    '통과 — 그대로 대기열에 들어갑니다.',
    '같은 기준이 승인 후 실제 적용 단계에서도 최종 방어선으로 한 번 더 검사됩니다.',
  ].join('\n'),
  { kind: 'request_policy' })

/* ─── 환경별 권한 ────────────────────────────────── */

const hours = sessionSeconds / 3600

add('policy-environments',
  [
    '이 시스템의 환경별 접근 권한',
    '',
    ...ENVIRONMENTS.map((e) =>
      `${e.label} — ${e.can}. 권한 부여에 ${e.needsSuper ? '관리자와 최고 관리자 승인이 모두' : '관리자 승인이'} 필요합니다.`),
    '',
    '권한은 IAM 그룹에 넣고 빼는 방식으로 관리합니다.',
    `그룹에 들어가면 해당 환경의 역할을 맡을 수 있고, 맡으면 ${hours}시간짜리 임시 자격증명을 받습니다.`,
    '역할을 맡으면 원래 권한은 버려지고 그 역할의 권한만 적용됩니다. 두 권한이 합쳐지지 않습니다.',
    '권한 회수는 관리자 한 명의 승인으로 처리됩니다. 권한이 줄어드는 방향이기 때문입니다.',
  ].join('\n'),
  { kind: 'env_policy', session_hours: hours })

add('policy-session',
  [
    '이 시스템의 임시 자격증명 유효 시간',
    '',
    `역할을 맡아 받은 임시 키는 ${hours}시간 동안 유효합니다(${sessionSeconds}초).`,
    'AWS가 정한 상한이 12시간이라 며칠짜리 임시 키는 만들 수 없습니다.',
    '이것은 신청서에 적는 사용 기간과 다른 값입니다.',
    '사용 기간은 그 역할을 맡을 자격이 유지되는 기간이고, 이 시간은 한 번 맡아 받은 키의 수명입니다.',
    '사용 기간 안에서는 만료될 때마다 다시 맡을 수 있으며, CLI는 프로필에 role_arn을 적어두면 자동으로 다시 받아옵니다.',
  ].join('\n'),
  { kind: 'env_policy', session_seconds: sessionSeconds })

/* ─── 만료와 회수 ────────────────────────────────── */

add('policy-expiry',
  [
    '이 시스템의 권한 만료와 자동 회수',
    '',
    `환경 권한을 신청할 때 사용 기간을 고를 수 있습니다: ${expiryOptions.join(', ')}.`,
    '기간이 지나면 배치가 자동으로 IAM 그룹에서 빼 권한을 회수합니다.',
    '보안 그룹 규칙 신청에도 같은 만료 기능이 있어, 기간이 지나면 그 규칙이 회수됩니다.',
    `배치는 cron 일정 '${cronSchedule}'로 하루 한 번 돕니다. 만료 목적이라 몇 시간 늦게 회수되어도 무방합니다.`,
    '이미 회수된 대상이나 삭제된 리소스는 실패로 보지 않고 넘어갑니다.',
    '더 쓰려면 만료 후 다시 신청하면 됩니다.',
  ].join('\n'),
  { kind: 'expiry_policy', cron: cronSchedule })

/* ─── 출력 ──────────────────────────────────────── */

writeFileSync(OUT, JSON.stringify(docs, null, 2))
console.log(`생성: ${docs.length}건 → ${OUT}`)
console.log('\n읽어온 값:')
console.log(`  rules.js      MIN_CIDR_PREFIX=${REQUEST_POLICY.MIN_CIDR_PREFIX}, MAX_RULES=${REQUEST_POLICY.MAX_RULES}`)
console.log(`                SENSITIVE_PORTS=[${REQUEST_POLICY.SENSITIVE_PORTS}], WEB_PORTS=[${WEB_PORTS}]`)
console.log(`                ENVIRONMENTS=[${ENVIRONMENTS.map((e) => e.key)}]`)
console.log(`  roles.tf      max_session_duration=${sessionSeconds} (${hours}시간)`)
console.log(`  expiry_cron   '${cronSchedule}'`)
console.log(`  EnvAccessForm 만료 선택지=[${expiryOptions}]`)

if (!process.argv.includes('--push')) {
  console.log('\n적재하려면 --push (SB_SERVICE_KEY 필요)')
  process.exit(0)
}

const key = process.env.SB_SERVICE_KEY
if (!key) { console.error('SB_SERVICE_KEY가 없습니다'); process.exit(1) }

const res = await fetch(FN_URL, {
  method: 'POST',
  headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ documents: docs }),
})
const body = await res.json()
console.log(body.ok ? `\n적재 완료: ${body.inserted}건` : `\n실패: ${body.error || JSON.stringify(body.failures)}`)
