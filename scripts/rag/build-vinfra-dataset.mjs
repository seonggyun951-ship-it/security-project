// 가상 회사 설계를 RAG 지식으로 만든다.
//
// 값을 손으로 적지 않는다. design/virtual-company.yaml 하나에서 읽어 문장을 만든다.
// 설계를 바꾸면 이 스크립트를 다시 돌리는 것만으로 문서가 따라온다.
// 손으로 적으면 설계는 바뀌었는데 문서만 옛날 값으로 남고, LLM은 그 옛날 값을
// 확신에 차서 말하게 된다.
//
// 자르는 단위는 '질문'이다. 사람이 실제로 물어볼 법한 것 하나에 문서 하나.
//   "prod가 밖으로 나가는 IP?"  "개인정보 DB는 어떻게 접근?"  "10.99 대역은 뭐야?"
// 특히 대역→용도 표(vinfra-cidr-map)는 나중에 신청 판정에 쓸 사실이라 또렷하게 둔다.
//
// 사용법:
//   node scripts/rag/build-vinfra-dataset.mjs           # 만들어서 파일로만
//   node scripts/rag/build-vinfra-dataset.mjs --push    # 적재까지 (SB_SERVICE_KEY 필요)

import { writeFileSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { parse } from 'yaml'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '../..')
const SRC = resolve(ROOT, 'design/virtual-company.yaml')
const OUT = resolve(HERE, 'vinfra-dataset.json')
const FN_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/rag-index'

const D = parse(readFileSync(SRC, 'utf8'))
const aws = D.boundaries.aws
const gcp = D.boundaries.gcp
const sec = D.security_layers
const ic = D.interconnect

const docs = []
const add = (ref, content, meta = {}) =>
  docs.push({ source: 'virtual_infra', ref, content: content.trim(), meta })

// VPC 하나를 한 줄 요약으로. 판정에 쓸 사실(대역·격리·연결)을 담는다.
const vpcById = Object.fromEntries(aws.vpcs.map((v) => [v.name, v]))
const eip = (env) => aws.nat_egress_ips[env] || '없음'

/* ─── 전체 개요 ───────────────────────────────────── */
add('vinfra-overview', `
가상 회사 멀티클라우드 구조 개요

통제 경계는 클라우드 계정/프로젝트다.
- AWS: 계정 하나(${aws.id}), 리전 ${aws.region}. 환경마다 VPC로 나눔 — ${aws.vpcs.map((v) => v.name).join(', ')}.
- GCP: 프로젝트로 나눔 — ${gcp.projects.map((p) => p.id).join(', ')} (상태: ${gcp.status}).
두 경계는 Site-to-Site VPN(IPsec)으로 잇는다.

공통 원칙:
${D.principles.map((p) => `- ${p.text}`).join('\n')}

개인정보 취급 시스템은 별도 경계로 완전히 격리한다(ISMS-P 개인정보처리시스템 접근통제·망분리).
`, { kind: 'overview' })

/* ─── 대역 → 용도 표 (판정의 핵심) ─────────────────── */
const cidrRows = []
for (const v of aws.vpcs) {
  const role = v.classification === 'pii' ? '개인정보 DB (PrivateLink+DB접근제어 필수, 대역 직접 접근 금지)'
    : v.classification === 'general' ? '일반 DB (VPC 피어링으로만 접근)'
      : v.internet_facing ? '운영 앱 (외부 공개, ALB 뒤)'
        : `${v.env} 환경 (인바운드 차단)`
  cidrRows.push(`- ${v.cidr}  = AWS ${v.name} · ${role}`)
}
for (const p of gcp.projects) {
  cidrRows.push(`- ${p.network.cidr}  = GCP ${p.id} · ${p.purpose}`)
}
add('vinfra-cidr-map', `
대역별 용도 (어느 IP 대역이 무슨 시스템인지)

이 표가 신청이 올바른지 판단하는 기준이다. 대역을 보고 용도를 안다.
${cidrRows.join('\n')}

주의:
- 10.99.0.0/16(AWS 개인정보 DB)와 GCP 개인정보 프로젝트 대역은 앱이 대역으로 직접 붙으면 안 된다.
  반드시 엔드포인트(AWS PrivateLink / GCP PSC)와 DB 접근제어 게이트웨이를 거친다.
- 전 대역은 서로 겹치지 않는다. 클라우드 간 VPN 라우팅의 전제다.
`, { kind: 'cidr_map' })

/* ─── AWS VPC 각각 ────────────────────────────────── */
for (const v of aws.vpcs) {
  const subs = v.subnets.map((s) => `  - ${s.tier} ${s.az}: ${s.cidr}`).join('\n')
  const comps = (v.components || []).map((c) => `  - ${c.type}${c.eip ? ` (EIP ${c.eip})` : ''}${c.product_example ? ` 예: ${c.product_example}` : ''}`).join('\n')
  const line = v.classification === 'pii'
    ? '개인정보 DB. 인터넷과 완전 격리. 앱은 PrivateLink 엔드포인트 뒤 DB 접근제어 게이트웨이를 거쳐야만 접근한다. 별도 IAM·별도 감사. 접속기록 2년 보관.'
    : v.classification === 'general'
      ? '일반 DB. 인터넷 격리. prod에서 VPC 피어링으로만 접근한다.'
      : v.internet_facing
        ? `외부 공개 환경. 인터넷 유입은 ALB를 통해서만. 나가는 고정 IP는 ${eip(v.env)}.`
        : `비공개 환경. 인바운드 전면 차단. 나가는 고정 IP는 ${eip(v.env)}.`
  add(`vinfra-aws-${v.name}`, `
AWS ${v.name} (${v.cidr})

${line}

서브넷:
${subs}
구성요소:
${comps || '  - 없음'}
`, { kind: 'aws_vpc', vpc: v.name, cidr: v.cidr, classification: v.classification || 'env' })
}

/* ─── 나가는 고정 IP ──────────────────────────────── */
add('vinfra-egress', `
밖으로 나가는 고정 IP (NAT EIP)

앱이 외부로 나갈 때는 환경별 NAT의 고정 IP로만 나간다. 상대가 이 IP를 화이트리스트한다.
${Object.entries(aws.nat_egress_ips).map(([env, ip]) => `- AWS ${env}: ${ip}`).join('\n')}
- AWS db · pii: 나가는 길 없음 (완전 격리)
- GCP prod: ${gcp.projects.find((p) => p.id.endsWith('-prod'))?.network.components.find((c) => c.type === 'cloud_nat')?.eip || '—'} (Cloud NAT)

들어오는 것과 방향이 반대다. 들어오는 것은 로드밸런서(ALB/External LB), 나가는 것은 NAT다.
`, { kind: 'egress' })

/* ─── 개인정보 격리 (양 클라우드 공통) ──────────────── */
const piiVpc = aws.vpcs.find((v) => v.classification === 'pii')
const dbac = (piiVpc.components || []).find((c) => c.type === 'db_access_control')
add('vinfra-pii-isolation', `
개인정보 DB 격리 원칙 (AWS·GCP 공통)

개인정보 DB는 네트워크를 통째로 잇지 않는다. DB 서비스 하나만 엔드포인트로 노출하고,
그 앞에 DB 접근제어 게이트웨이를 둔다. 최소 권한으로만 접근한다.

- AWS: 별도 VPC ${piiVpc.name}(${piiVpc.cidr}) + PrivateLink + DB 접근제어 GW
- GCP: 별도 프로젝트 ${gcp.projects.find((p) => p.id.endsWith('-pii'))?.id} + PSC + DB 접근제어 GW
- DB 접근제어 예시 제품: ${dbac?.product_example || 'DB SAFER'} — 모든 접속·쿼리 기록, 정책 통제, 마스킹
- 접속기록 ${dbac?.log_retention || '2년'} 보관 (개인정보보호법 안전성 확보조치: 고유식별·민감정보 또는 5만명 이상 시 2년)
- 긴급 접속: ${dbac?.emergency_access || 'GW 장애 시 콘솔 직접 접속 · 별도 기록 · 사후 감사'}

두 클라우드의 DB 접근제어를 연동해 접속기록을 한곳에서 관리하고,
개인정보 DB는 VPN 암호화 채널로 잇는다(복제·DR).
`, { kind: 'pii_isolation' })

/* ─── GCP 구조 ────────────────────────────────────── */
add('vinfra-gcp', `
GCP 프로젝트 구조

GCP는 VPC가 글로벌이라 환경마다 VPC를 만들지 않는다. 대신 프로젝트로 경계를 나눈다.
${gcp.projects.map((p) => `- ${p.id}: ${p.purpose} (${p.network.name} ${p.network.cidr})`).join('\n')}

AWS와 개념 대응:
- VPC = 리전(AWS) vs 글로벌(GCP)
- 방화벽: SG+NACL(AWS) vs firewall 태그·priority(GCP)
- 개인정보 DB: PrivateLink(AWS) vs PSC(GCP)
- 외부 LB: ALB 리전(AWS) vs External HTTP LB 글로벌(GCP)
`, { kind: 'gcp' })

/* ─── 클라우드 간 연결 ────────────────────────────── */
add('vinfra-interconnect', `
두 클라우드 연결 (Site-to-Site VPN)

AWS와 GCP를 IPsec VPN(터널 ${ic.tunnels}개)으로 잇는다.
라우팅: ${ic.routed}

CIDR 계획 — 겹치면 라우팅이 불가능하므로 처음부터 분리했다:
- AWS: ${ic.cidr_plan.aws.join(', ')}
- GCP: ${ic.cidr_plan.gcp.join(', ')}

개인정보 보안 채널: 두 클라우드의 DB 접근제어 GW를 연동(접속기록 통합)하고
개인정보 DB를 암호화 채널로 잇는다. 이 트래픽도 VPN을 타 인터넷에 노출되지 않는다.
`, { kind: 'interconnect' })

/* ─── 공통 보안 계층 ──────────────────────────────── */
add('vinfra-iam', `
신원·접근통제 (IAM)

- AWS: ${sec.identity.aws.idp} · ${sec.identity.aws.model}
- GCP: ${sec.identity.gcp.idp} · ${sec.identity.gcp.model}
- 클라우드 간: ${sec.identity.federation.type} — ${sec.identity.federation.note}
- 개인정보 접근: ${sec.identity.aws.pii_access}
`, { kind: 'iam' })

add('vinfra-logging', `
중앙 로깅·SIEM

로그 소스:
- AWS: ${sec.logging.aws_sources.join(', ')}
- GCP: ${sec.logging.gcp_sources.join(', ')}
한곳에 모은다: ${sec.logging.central.sink}. ${sec.logging.central.siem}.
보관: 개인정보 ${sec.logging.central.retention.pii}, 일반 ${sec.logging.central.retention.general}.
`, { kind: 'logging' })

add('vinfra-encryption', `
암호화 (KMS)

- 저장: AWS ${sec.encryption.at_rest.aws} / GCP ${sec.encryption.at_rest.gcp}
- 전송: ${sec.encryption.in_transit}
- 키 관리: ${sec.encryption.key_mgmt.rotation}, ${sec.encryption.key_mgmt.pii_keys}
`, { kind: 'encryption' })

add('vinfra-dns-waf', `
진입 경로 (DNS·WAF)

- DNS: AWS ${sec.dns.aws.service}(${sec.dns.aws.records}) / GCP ${sec.dns.gcp.service}(${sec.dns.gcp.records}). ${sec.dns.note}.
- WAF: AWS ${sec.waf.aws.on} 앞단(${sec.waf.aws.rules.join(', ')}) / GCP ${sec.waf.gcp.on}에 ${sec.waf.gcp.product}.
사용자가 서비스에 닿는 경로: DNS → WAF → 로드밸런서 → 앱. 공개 대상은 prod뿐이다.
`, { kind: 'dns_waf' })

/* ─── 출력 ────────────────────────────────────────── */
writeFileSync(OUT, JSON.stringify(docs, null, 2))
console.log(`생성: ${docs.length}건 → ${OUT}`)
console.log('\n문서 목록:')
for (const d of docs) console.log(`  ${d.ref}`)

if (!process.argv.includes('--push')) {
  console.log('\n적재하려면 --push (SB_SERVICE_KEY 필요)')
  process.exit(0)
}

// supabase CLI의 -o env 출력은 값을 "..."로 감싸므로 따옴표·공백·CR을 벗긴다.
// 안 벗기면 Bearer "eyJ... 가 되어 Invalid JWT로 튕긴다.
const key = (process.env.SB_SERVICE_KEY || '').trim().replace(/^["']|["']$/g, '').trim()
if (!key) { console.error('SB_SERVICE_KEY가 없습니다'); process.exit(1) }
console.log(`\n키 길이: ${key.length} (값은 안 찍음)`)

const res = await fetch(FN_URL, {
  method: 'POST',
  headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ documents: docs }),
})
const raw = await res.text()
console.log(`HTTP ${res.status}`)
let body
try { body = JSON.parse(raw) } catch { body = null }
if (body?.ok) {
  console.log(`\n적재 완료: ${body.inserted ?? docs.length}건`)
} else {
  console.log(`\n실패 — 응답 원문:\n${raw.slice(0, 500)}`)
}
