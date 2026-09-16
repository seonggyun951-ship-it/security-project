// 설계에서 '판정에 쓸 사실'을 뽑아 src/lib/design-facts.json으로 만든다.
//
// rules.js는 순수 함수라 파일을 못 읽는다. 그래서 값을 JSON으로 뽑아 두고
// rules.js가 import한다(Vite·Node 둘 다 JSON import 지원).
//
// 값을 손으로 적지 않는다. design/virtual-company.yaml 하나에서 읽는다.
// 설계를 바꾸면 이 스크립트를 다시 돌리는 것만으로 판정 근거가 따라온다 —
// rules.js에 CIDR을 박아두면 설계는 바뀌었는데 판정만 옛날 값으로 남는다.
//
// 사용법:
//   node scripts/rag/build-design-facts.mjs

import { writeFileSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { parse } from 'yaml'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(HERE, '../..')
const SRC = resolve(ROOT, 'design/virtual-company.yaml')
// JSON이 아니라 JS 모듈로 뽑는다. Node는 JSON import에 속성을 요구하고
// 번들러마다 문법이 갈리는데, export default면 양쪽에서 속성 없이 그냥 import된다.
const OUT = resolve(ROOT, 'src/lib/design-facts.js')

const D = parse(readFileSync(SRC, 'utf8'))
const aws = D.boundaries.aws

// VPC 하나를 판정용 사실로. class가 무엇을 여는가/닫는가를 가른다.
//   app        운영 앱 (외부 공개, 인바운드 ALB로만)
//   env        일반 환경 (인바운드 차단)
//   general_db 일반 DB (인터넷 격리, 피어링으로만)
//   pii_db     개인정보 DB (인터넷 격리, 엔드포인트+DB접근제어로만, 대역 직접 접근 금지)
const classOf = (v) =>
  v.classification === 'pii' ? 'pii_db'
    : v.classification === 'general' ? 'general_db'
      : v.internet_facing ? 'app' : 'env'

const cidrs = aws.vpcs.map((v) => ({
  cidr: v.cidr,
  vpc: v.name,
  env: v.env,
  class: classOf(v),
  internet_facing: !!v.internet_facing,
  // 이 대역에 앱이 직접 붙으면 안 되는가 (데이터 계층은 엔드포인트/피어링 경유)
  direct_access_forbidden: classOf(v) === 'pii_db' || classOf(v) === 'general_db',
  // 개인정보 대역은 별도로 표시 — 판정 문구가 달라진다
  pii: classOf(v) === 'pii_db',
}))

const facts = {
  // 이 파일은 자동 생성이다. 손으로 고치지 말 것 — build-design-facts.mjs를 돌린다.
  _generated: 'scripts/rag/build-design-facts.mjs (design/virtual-company.yaml에서)',
  account: aws.id,
  region: aws.region,
  cidrs,
  // 사내망 — 우리가 만든 VPC 대역 전체. rules.js의 INTERNAL_CIDRS가 이걸 쓴다.
  internal_cidrs: cidrs.map((c) => c.cidr),
  // 나가는 고정 IP (참고용)
  nat_egress_ips: aws.nat_egress_ips,
}

const banner = `// 자동 생성 파일 — 손으로 고치지 말 것.\n`
  + `// scripts/rag/build-design-facts.mjs 가 design/virtual-company.yaml에서 만든다.\n`
writeFileSync(OUT, banner + 'export default ' + JSON.stringify(facts, null, 2) + '\n')
console.log(`생성: ${OUT}`)
console.log('\n대역 → 분류:')
for (const c of cidrs) {
  console.log(`  ${c.cidr.padEnd(18)} ${c.vpc.padEnd(10)} ${c.class}${c.direct_access_forbidden ? '  · 직접 접근 금지' : ''}`)
}
