// CISA KEV — 실제로 악용이 확인된 취약점 목록.
//
// 취약점 스캔 결과에는 CVE가 수십, 수백 개씩 나온다. 그중 무엇을 먼저 고쳐야
// 하는지가 문제인데, KEV에 올라와 있다는 것은 "이론상 위험"이 아니라
// "실제로 악용된 적이 있다"는 뜻이라 우선순위를 가르는 기준이 된다.
// 랜섬웨어에 쓰였는지도 표시되어 있다.
//
// 원본은 CISA가 공개하는 JSON 목록이다. 매주 갱신되므로 캐시를 지우고 다시 받으면 된다.
//
// 사용법:
//   node scripts/rag/build-kev-dataset.mjs           # 만들어서 파일로만
//   node scripts/rag/build-kev-dataset.mjs --push    # 적재까지

import { writeFileSync, existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const CACHE = resolve(HERE, '.cache-kev.json')
const OUT = resolve(HERE, 'kev-dataset.json')
const SRC = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
const FN_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/rag-index'

const clean = (t) => String(t || '').replace(/\s+/g, ' ').trim()

async function load() {
  if (existsSync(CACHE)) {
    console.log('캐시 사용:', CACHE)
    return JSON.parse(readFileSync(CACHE, 'utf8'))
  }
  console.log('CISA KEV 내려받는 중...')
  const res = await fetch(SRC)
  if (!res.ok) throw new Error(`내려받기 실패: ${res.status}`)
  const text = await res.text()
  writeFileSync(CACHE, text)
  return JSON.parse(text)
}

const catalog = await load()
const vulns = catalog.vulnerabilities || []

const docs = []
for (const v of vulns) {
  const desc = clean(v.shortDescription)
  if (!v.cveID || !desc) continue

  const ransomware = String(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known'
  const cwes = (v.cwes || []).join(', ')

  // 한국어 문장을 앞에 둔다. 원문이 영어라 그대로 두면 한국어 질문과 잘 붙지 않는다.
  // 뒤에 원문 설명을 붙여 세부 내용도 검색되게 한다.
  const content = [
    `${v.cveID} — ${clean(v.vulnerabilityName)}`,
    `영향 제품: ${clean(v.vendorProject)} ${clean(v.product)}`,
    `이 취약점은 실제로 악용된 것이 확인되어 CISA의 악용된 취약점 목록(KEV)에 ${v.dateAdded}에 등재되었습니다.`,
    ransomware
      ? '랜섬웨어 공격에 사용된 것으로 알려져 있습니다. 우선적으로 조치해야 합니다.'
      : '랜섬웨어 사용 여부는 확인되지 않았습니다.',
    cwes ? `약점 분류: ${cwes}` : null,
    '',
    desc.slice(0, 900),
    v.requiredAction ? `\n조치: ${clean(v.requiredAction).slice(0, 400)}` : null,
  ].filter((x) => x !== null).join('\n')

  docs.push({
    source: 'kev',
    ref: v.cveID,
    content,
    meta: {
      vendor: clean(v.vendorProject),
      product: clean(v.product),
      date_added: v.dateAdded,
      ransomware,
      cwes: v.cwes || [],
    },
  })
}

writeFileSync(OUT, JSON.stringify(docs, null, 2))
console.log(`생성: ${docs.length}건 → ${OUT}`)
console.log(`  랜섬웨어에 쓰인 것: ${docs.filter((d) => d.meta.ransomware).length}건`)
const byVendor = docs.reduce((a, d) => (a[d.meta.vendor] = (a[d.meta.vendor] || 0) + 1, a), {})
console.log(`  제조사 상위: ${Object.entries(byVendor).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([k, v]) => `${k}:${v}`).join(', ')}`)

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
  try {
    const res = await fetch(FN_URL, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ documents: slice }),
    })
    const body = await res.json()
    if (!body.ok) {
      console.error(`  ${i}~${i + slice.length} 실패:`, body.error || JSON.stringify(body.failures).slice(0, 160))
      continue
    }
    sent += body.inserted
    if ((i / CHUNK) % 4 === 0 || i + CHUNK >= docs.length) {
      console.log(`  ${Math.min(i + CHUNK, docs.length)}/${docs.length} 적재됨`)
    }
  } catch (e) {
    console.error(`  ${i}~${i + slice.length} 오류:`, String(e).slice(0, 140))
  }
}
console.log(`\n적재 완료: ${sent}건`)
