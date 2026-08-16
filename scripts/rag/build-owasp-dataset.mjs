// OWASP Top 10 (2021)을 지식 베이스용 문서로 만든다.
//
// MITRE가 "공격자가 어떻게 하는가"라면 OWASP는 "무엇을 잘못 만들면 뚫리는가"에 가깝다.
// 이 앱은 WAF 규칙도 다루는데 AWS 관리형 규칙 그룹이 OWASP 기준으로 짜여 있어,
// "이 WAF 규칙이 무엇을 막아주나"를 설명할 때 근거가 된다.
//
// 항목 하나가 6~11KB로 길다. 통째로 한 조각에 넣으면 임베딩이 뭉뚱그려져
// "예방 방법"을 물었을 때 "공격 예시"가 걸리는 식이 된다. 소제목 단위로 쪼갠다.
//
// 사용법:
//   node scripts/rag/build-owasp-dataset.mjs           # 만들어서 파일로만 저장
//   node scripts/rag/build-owasp-dataset.mjs --push    # 적재까지 (SB_SERVICE_KEY 필요)

import { writeFileSync, existsSync, readFileSync, mkdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const CACHE_DIR = resolve(HERE, '.cache-owasp')
const OUT = resolve(HERE, 'owasp-dataset.json')
const BASE = 'https://raw.githubusercontent.com/OWASP/Top10/master/2021/docs/en'
const FN_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/rag-index'

const ITEMS = [
  { id: 'A01:2021', file: 'A01_2021-Broken_Access_Control.md', ko: '취약한 접근 통제' },
  { id: 'A02:2021', file: 'A02_2021-Cryptographic_Failures.md', ko: '암호화 실패' },
  { id: 'A03:2021', file: 'A03_2021-Injection.md', ko: '인젝션' },
  { id: 'A04:2021', file: 'A04_2021-Insecure_Design.md', ko: '안전하지 않은 설계' },
  { id: 'A05:2021', file: 'A05_2021-Security_Misconfiguration.md', ko: '보안 설정 오류' },
  { id: 'A06:2021', file: 'A06_2021-Vulnerable_and_Outdated_Components.md', ko: '취약하거나 오래된 구성요소' },
  { id: 'A07:2021', file: 'A07_2021-Identification_and_Authentication_Failures.md', ko: '식별·인증 실패' },
  { id: 'A08:2021', file: 'A08_2021-Software_and_Data_Integrity_Failures.md', ko: '소프트웨어·데이터 무결성 실패' },
  { id: 'A09:2021', file: 'A09_2021-Security_Logging_and_Monitoring_Failures.md', ko: '보안 로깅·모니터링 실패' },
  { id: 'A10:2021', file: 'A10_2021-Server-Side_Request_Forgery_(SSRF).md', ko: '서버 측 요청 위조(SSRF)' },
]

// 원문에 섞인 표·링크·주석을 걷어낸다. 임베딩에 도움이 안 되고 자리만 차지한다.
function clean(text) {
  return String(text || '')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')   // 링크는 글자만 남긴다
    .replace(/<[^>]+>/g, '')
    .replace(/^\s*\|.*\|\s*$/gm, '')            // 표는 통째로 뺀다 (CWE 목록 등)
    .replace(/^[-*]\s+/gm, '· ')
    .replace(/`{1,3}/g, '')
    .replace(/\s*\n\s*\n\s*/g, '\n')
    .replace(/[ \t]{2,}/g, ' ')
    .trim()
}

async function fetchDoc(file) {
  if (!existsSync(CACHE_DIR)) mkdirSync(CACHE_DIR, { recursive: true })
  const path = resolve(CACHE_DIR, file)
  if (existsSync(path)) return readFileSync(path, 'utf8')

  const res = await fetch(`${BASE}/${file}`)
  if (!res.ok) throw new Error(`${file} 내려받기 실패: ${res.status}`)
  const text = await res.text()
  writeFileSync(path, text)
  return text
}

const docs = []

for (const item of ITEMS) {
  const raw = await fetchDoc(item.file)

  // '## 소제목' 기준으로 자른다. 첫 덩어리는 제목 앞 도입부다.
  const parts = raw.split(/^##\s+/m)
  const sections = []
  for (let i = 1; i < parts.length; i++) {
    const [head, ...rest] = parts[i].split('\n')
    sections.push({ title: head.trim(), body: clean(rest.join('\n')) })
  }
  // 소제목이 없으면 통째로 하나
  if (sections.length === 0) sections.push({ title: '개요', body: clean(raw) })

  for (const s of sections) {
    // 너무 짧은 조각은 검색에 걸려도 쓸모가 없다 (제목만 있는 경우 등)
    if (s.body.length < 120) continue

    docs.push({
      source: 'owasp',
      ref: `${item.id} ${s.title}`,
      content: [
        `OWASP Top 10 (2021) ${item.id} — ${item.ko}`,
        `항목: ${s.title}`,
        '',
        s.body.slice(0, 1800),
      ].join('\n'),
      meta: { item: item.id, item_ko: item.ko, section: s.title },
    })
  }
}

writeFileSync(OUT, JSON.stringify(docs, null, 2))
console.log(`생성: ${docs.length}건 → ${OUT}`)
const byItem = docs.reduce((a, d) => (a[d.meta.item] = (a[d.meta.item] || 0) + 1, a), {})
console.log('항목별:', Object.entries(byItem).map(([k, v]) => `${k}:${v}`).join(', '))

if (!process.argv.includes('--push')) {
  console.log('\n적재하려면 --push (SB_SERVICE_KEY 필요)')
  process.exit(0)
}

const key = process.env.SB_SERVICE_KEY
if (!key) { console.error('SB_SERVICE_KEY가 없습니다'); process.exit(1) }

const CHUNK = 64
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
    console.error(`  ${i}~${i + slice.length} 실패:`, body.error || JSON.stringify(body.failures).slice(0, 200))
    continue
  }
  sent += body.inserted
  console.log(`  ${Math.min(i + CHUNK, docs.length)}/${docs.length} 적재됨`)
}
console.log(`\n적재 완료: ${sent}건`)
