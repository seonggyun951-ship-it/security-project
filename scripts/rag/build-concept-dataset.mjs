// AWS 기초 개념 문서.
//
// 지식 베이스에 판정 사례와 점검 항목만 있어서, "Security Group이 무엇인지"를
// 물으면 답할 근거가 없었다. 검색해보면 엉뚱한 체크 항목이 걸렸다.
//
// 내용은 AWS 공식 문서를 실제로 열어 확인한 것만 담는다. 기억으로 쓰지 않는다.
// 해석이나 정리 문장도 넣지 않는다 — 문서에 있는 내용을 옮기기만 한다.
// 틀린 설명이 벡터로 박히면 LLM이 그것을 확신에 차서 말하게 되고,
// 보안 도구에서는 "부실한 설명"보다 "그럴듯하게 틀린 설명"이 훨씬 위험하다.
//
// 이 시스템 고유 정책(허용 CIDR 폭, 민감 포트 등)은 여기 없다.
// build-policy-dataset.mjs가 코드 상수에서 생성한다.
//
// 사용법:
//   node scripts/rag/build-concept-dataset.mjs           # 만들어서 파일로만
//   node scripts/rag/build-concept-dataset.mjs --push    # 적재까지

import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const OUT = resolve(HERE, 'concept-dataset.json')
const FN_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/rag-index'

const SRC_SG = 'AWS VPC User Guide — Control traffic to your AWS resources using security groups'
const SRC_SG_RULES = 'AWS VPC User Guide — Security group rules'
const SRC_NACL = 'AWS VPC User Guide — Control subnet traffic with network access control lists'
const SRC_IAM_ID = 'AWS IAM User Guide — IAM Identities'
const SRC_IAM_GROUP = 'AWS IAM User Guide — IAM user groups'

const docs = []
const add = (ref, title, body, source) => docs.push({
  source: 'concept',
  ref,
  content: `${title}\n\n${body.trim()}\n\n출처: ${source}`,
  meta: { doc: source },
})

/* ─── Security Group ─────────────────────────────── */

add('concept-sg-basics', 'Security Group이란', `
Security Group은 연결된 리소스에 드나드는 트래픽을 통제합니다.
EC2 인스턴스에 연결하면 그 인스턴스의 인바운드·아웃바운드 트래픽을 통제하며, 가상 방화벽 역할을 합니다.
Security Group 규칙이 허용한 트래픽만 인스턴스에 도달합니다.

VPC를 만들면 기본 Security Group이 하나 함께 생깁니다. VPC마다 인바운드·아웃바운드 규칙을 가진
Security Group을 추가로 만들 수 있고, 하나의 리소스에 여러 개를 연결할 수도 있습니다.
여러 개를 연결하면 각 그룹의 규칙이 합쳐져 하나의 규칙 집합을 이루고 그것으로 접근 허용 여부를 판단합니다.

규칙을 추가·수정·삭제하면 그 Security Group에 연결된 모든 리소스에 자동으로 반영됩니다.
Security Group 사용에는 추가 요금이 없습니다.
`, SRC_SG)

add('concept-sg-allow-only', 'Security Group은 허용 규칙만 쓸 수 있다', `
Security Group에는 허용(allow) 규칙을 지정할 수 있지만 차단(deny) 규칙은 지정할 수 없습니다.

Security Group을 처음 만들면 인바운드 규칙이 하나도 없습니다.
따라서 인바운드 규칙을 추가하기 전까지는 들어오는 트래픽이 허용되지 않습니다.

Security Group을 처음 만들면 모든 아웃바운드 트래픽을 허용하는 아웃바운드 규칙이 하나 있습니다.
이 규칙을 제거하고 특정 아웃바운드 트래픽만 허용하는 규칙을 추가할 수 있습니다.
아웃바운드 규칙이 하나도 없으면 나가는 트래픽이 허용되지 않습니다.
`, SRC_SG_RULES)

add('concept-sg-stateful', 'Security Group은 상태를 저장한다(stateful)', `
Security Group은 상태를 저장합니다.
인스턴스에서 요청을 보내면 그 요청에 대한 응답 트래픽은 인바운드 규칙과 상관없이 인스턴스에 도달할 수 있습니다.
허용된 인바운드 트래픽에 대한 응답도 아웃바운드 규칙과 상관없이 인스턴스를 떠날 수 있습니다.
`, SRC_SG)

add('concept-sg-inbound-outbound', '인바운드와 아웃바운드, 규칙의 구성 요소', `
규칙은 인바운드 트래픽(ingress)이나 아웃바운드 트래픽(egress) 중 하나에 적용됩니다.
인바운드 규칙에는 출발지(source)를, 아웃바운드 규칙에는 목적지(destination)를 지정합니다.
규칙을 추가하거나 제거하는 것을 인바운드·아웃바운드 접근을 승인(authorize)하거나 회수(revoke)한다고도 합니다.

규칙의 구성 요소는 다음과 같습니다.
프로토콜 — 허용할 프로토콜. 가장 흔한 것은 6(TCP), 17(UDP), 1(ICMP)입니다.
포트 범위 — TCP·UDP나 사용자 지정 프로토콜의 경우 허용할 포트 범위. 단일 포트(예: 22)나 범위(예: 7000-8000)를 지정합니다.
출발지 또는 목적지 — 단일 IPv4 주소(/32), 단일 IPv6 주소(/128), CIDR 표기의 IPv4·IPv6 범위,
프리픽스 목록 ID, 또는 Security Group ID를 지정할 수 있습니다.
설명 — 선택 사항으로 규칙에 설명을 붙일 수 있습니다.
`, SRC_SG_RULES)

add('concept-sg-referencing', '출발지에 다른 Security Group을 지정하기', `
규칙의 출발지나 목적지로 Security Group을 지정하면, 그 Security Group들에 연결된 모든 인스턴스에 규칙이 적용됩니다.
해당 인스턴스들은 지정한 방향으로, 지정한 프로토콜과 포트에서, 인스턴스의 사설 IP 주소를 사용해 통신할 수 있습니다.

AWS 문서의 예시는 다음과 같습니다. 가용 영역 두 곳에 서브넷이 있고 인터넷 게이트웨이와
Application Load Balancer가 있는 VPC에서, 각 가용 영역은 웹 서버용 퍼블릭 서브넷과
DB 서버용 프라이빗 서브넷을 가집니다. 로드밸런서·웹 서버·DB 서버에 각각 별도의 Security Group이 있습니다.
로드밸런서 Security Group에는 인터넷에서 오는 HTTP·HTTPS를 허용하는 규칙을 추가합니다. 출발지는 0.0.0.0/0입니다.
웹 서버 Security Group에는 로드밸런서에서 오는 HTTP·HTTPS만 허용하는 규칙을 추가합니다. 출발지는 로드밸런서의 Security Group입니다.
DB 서버 Security Group에는 웹 서버에서 오는 DB 요청을 허용하는 규칙을 추가합니다. 출발지는 웹 서버의 Security Group입니다.

참조된 Security Group의 규칙이 참조하는 Security Group에 추가되지는 않습니다.
규칙 수를 셀 때 CIDR 블록을 참조하는 규칙은 1개로 세고,
다른 Security Group을 참조하는 규칙도 그 그룹의 크기와 상관없이 1개로 셉니다.
`, SRC_SG_RULES)

add('concept-sg-best-practice', 'Security Group 모범 사례', `
AWS가 제시하는 Security Group 모범 사례입니다.

Security Group을 만들고 수정할 수 있는 IAM 주체를 특정 대상으로만 한정합니다.
실수 위험을 줄이기 위해 필요한 최소 개수의 Security Group만 만들고,
비슷한 기능과 보안 요구사항을 가진 리소스끼리 하나의 Security Group으로 관리합니다.

EC2 인스턴스에 접근하기 위해 22번(SSH)이나 3389번(RDP) 인바운드 규칙을 추가할 때는
특정 IP 주소 범위만 승인합니다. 0.0.0.0/0(IPv4)이나 ::/0(IPv6)을 지정하면
누구든 어느 IP 주소에서나 지정한 프로토콜로 인스턴스에 접근할 수 있게 됩니다.

넓은 포트 범위를 열지 않습니다. 각 포트에 대한 접근이 그것을 필요로 하는
출발지나 목적지로 제한되도록 합니다.

VPC에 보안 계층을 더하기 위해, Security Group 규칙과 비슷한 규칙을 가진 네트워크 ACL을 만드는 것도 고려합니다.
`, SRC_SG)

/* ─── Network ACL ────────────────────────────────── */

add('concept-nacl-basics', 'Network ACL이란', `
네트워크 ACL(NACL)은 서브넷 수준에서 특정 인바운드·아웃바운드 트래픽을 허용하거나 거부합니다.
VPC의 기본 네트워크 ACL을 쓸 수도 있고, Security Group 규칙과 비슷한 규칙을 가진
사용자 지정 네트워크 ACL을 만들 수도 있습니다. 사용자 지정 네트워크 ACL은 VPC에 보안 계층을 더합니다.
네트워크 ACL 사용에는 추가 요금이 없습니다.

VPC의 각 서브넷은 반드시 하나의 네트워크 ACL과 연결되어야 합니다.
명시적으로 연결하지 않으면 기본 네트워크 ACL에 자동으로 연결됩니다.
하나의 네트워크 ACL을 여러 서브넷에 연결할 수 있지만,
서브넷 하나는 한 번에 하나의 네트워크 ACL에만 연결될 수 있습니다.
새로 연결하면 이전 연결은 제거됩니다.
`, SRC_NACL)

add('concept-nacl-rules', 'Network ACL 규칙과 평가 순서', `
네트워크 ACL은 인바운드 규칙과 아웃바운드 규칙을 가집니다.
각 규칙은 트래픽을 허용하거나 거부할 수 있습니다.
각 규칙은 1부터 32766까지의 번호를 가지며, 가장 낮은 번호부터 순서대로 평가해
허용할지 거부할지 결정합니다. 트래픽이 어떤 규칙에 맞으면 그 규칙이 적용되고
그 뒤의 규칙은 평가하지 않습니다.
나중에 새 규칙을 끼워 넣을 수 있도록 10이나 100 같은 간격으로 규칙을 만드는 것이 권장됩니다.

네트워크 ACL 규칙은 트래픽이 서브넷에 들어오고 나갈 때 평가되며,
서브넷 안에서 라우팅되는 트래픽에는 적용되지 않습니다.
`, SRC_NACL)

add('concept-nacl-vs-sg', 'Network ACL과 Security Group의 차이', `
네트워크 ACL은 상태가 없습니다(stateless). 이전에 보내거나 받은 트래픽에 대한 정보를 저장하지 않습니다.
예를 들어 서브넷으로 들어오는 특정 인바운드 트래픽을 허용하는 네트워크 ACL 규칙을 만들어도,
그 트래픽에 대한 응답은 자동으로 허용되지 않습니다.

이것은 Security Group이 동작하는 방식과 대비됩니다.
Security Group은 상태를 저장합니다(stateful). 이전에 보내거나 받은 트래픽에 대한 정보를 저장합니다.
예를 들어 Security Group이 EC2 인스턴스로 들어오는 인바운드 트래픽을 허용하면,
그에 대한 응답은 아웃바운드 Security Group 규칙과 상관없이 자동으로 허용됩니다.

정리하면 네트워크 ACL은 서브넷 수준에서 동작하고 거부 규칙을 쓸 수 있으며 번호 순서대로 평가되고
서브넷 하나에 하나만 연결됩니다. Security Group은 리소스 수준에서 동작하고 허용 규칙만 쓸 수 있으며
모든 규칙을 합쳐서 판단하고 하나의 리소스에 여러 개를 연결할 수 있습니다.
`, SRC_NACL)

/* ─── CIDR ───────────────────────────────────────── */

add('concept-cidr', 'CIDR 표기와 0.0.0.0/0의 의미', `
Security Group 규칙의 출발지나 목적지에는 CIDR 블록 표기로 IP 범위를 지정합니다.
IP 주소 뒤에 붙는 /숫자는 앞에서부터 몇 비트가 고정인지를 나타내며, 고정 비트가 많을수록 범위가 좁습니다.
포함되는 IPv4 주소 개수는 2의 (32 - 프리픽스)제곱으로 계산됩니다.

/32 는 1개로 특정 서버 한 대를 가리킵니다.
/25 는 128개입니다.
/24 는 256개로 보통 서브넷 하나에 해당합니다.
/16 은 65,536개로 보통 VPC 하나에 해당합니다.
/8 은 16,777,216개입니다.
/0 은 4,294,967,296개로 모든 IPv4 주소를 가리킵니다.

규칙에 단일 IP 주소를 지정할 때 IPv4는 /32 프리픽스를, IPv6는 /128 프리픽스를 반드시 사용해야 합니다.
예를 들어 203.0.113.1/32 와 같이 씁니다. 범위는 203.0.113.0/24 처럼 CIDR 블록 표기로 씁니다.

0.0.0.0/0(IPv4)이나 ::/0(IPv6)을 지정하면 누구든 어느 IP 주소에서나
지정한 프로토콜로 인스턴스에 접근할 수 있게 됩니다.
`, `${SRC_SG_RULES} / ${SRC_SG} · 주소 개수는 2^(32-prefix)로 계산`)

/* ─── IAM ────────────────────────────────────────── */

add('concept-iam-identities', 'IAM 사용자·그룹·역할', `
IAM 신원(identity)에는 IAM 사용자, IAM 그룹, IAM 역할이 있습니다.
신원은 하나 이상의 정책과 연결될 수 있고, 정책은 그 신원이 어떤 리소스에 대해
어떤 조건에서 무엇을 할 수 있는지를 정합니다.

IAM 사용자는 한 사람 또는 하나의 애플리케이션에 해당하는, 계정 안의 신원이며 특정 권한을 가집니다.
IAM 사용자 그룹은 IAM 사용자들의 모음을 나타내는 신원입니다.
IAM 역할은 계정 안의 신원으로 특정 권한을 가지며, IAM 사용자와 비슷하지만 특정 사람과 연결되어 있지 않습니다.

외부 자격 증명 공급자의 기존 신원을 연동할 수 있으며, 그 신원들은 IAM 역할을 맡아 AWS 리소스에 접근합니다.

AWS 계정을 처음 만들면 모든 서비스와 리소스에 완전한 접근 권한을 가진 신원 하나로 시작하는데,
이것을 루트 사용자(root user)라고 합니다.
`, SRC_IAM_ID)

add('concept-iam-groups', 'IAM 그룹의 성질', `
IAM 사용자 그룹은 IAM 사용자들의 모음입니다. 여러 사용자에게 한 번에 권한을 지정할 수 있어
권한 관리가 쉬워집니다.

예를 들어 Admins라는 사용자 그룹을 만들어 일반적인 관리자 권한을 주면,
그 그룹에 속한 사용자는 자동으로 그 권한을 갖습니다.
새로 합류한 사람에게 관리자 권한이 필요하면 그 그룹에 추가하면 됩니다.
조직 안에서 직무가 바뀌면 그 사용자의 권한을 직접 수정하는 대신,
이전 IAM 그룹에서 빼고 알맞은 새 그룹에 넣으면 됩니다.

사용자 그룹에 자격 증명 기반 정책을 붙이면 그 그룹의 모든 사용자가 그 정책의 권한을 받습니다.
사용자 그룹은 정책에서 Principal로 지정할 수 없습니다.
그룹은 인증이 아니라 권한과 관계된 것이고, Principal은 인증된 IAM 개체이기 때문입니다.

그룹의 중요한 성질은 다음과 같습니다.
하나의 사용자 그룹은 많은 사용자를 담을 수 있고, 한 사용자는 여러 사용자 그룹에 속할 수 있습니다.
사용자 그룹은 중첩할 수 없습니다. 그룹은 사용자만 담을 수 있고 다른 IAM 그룹은 담을 수 없습니다.
계정의 모든 사용자를 자동으로 포함하는 기본 사용자 그룹은 없습니다. 필요하면 직접 만들어 사용자를 넣어야 합니다.
`, SRC_IAM_GROUP)

/* ─── 출력 ──────────────────────────────────────── */

writeFileSync(OUT, JSON.stringify(docs, null, 2))
console.log(`생성: ${docs.length}건 → ${OUT}`)
const lens = docs.map((d) => d.content.length)
console.log(`길이: 최소 ${Math.min(...lens)} / 평균 ${Math.round(lens.reduce((a, b) => a + b) / lens.length)} / 최대 ${Math.max(...lens)}`)

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
