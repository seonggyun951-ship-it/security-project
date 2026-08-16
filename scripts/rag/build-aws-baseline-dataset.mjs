// AWS 보안 기준선을 지식 베이스용 문서로 만든다.
//
// 규칙 엔진은 우리가 직접 짠 몇 가지만 본다(SG 포트·CIDR, S3 몇 항목, GCP 방화벽).
// 실제 AWS 운영에서 지켜야 할 것은 훨씬 많다 — 키 순환, MFA, 로그 보존, 암호화 같은 것들.
// 그런 기준선이 없으면 규칙에 없는 질문에 근거 없이 답하게 된다.
//
// 원본은 Prowler의 체크 메타데이터다. 체크마다 제목·설명·위험·조치·심각도가 정리돼 있고
// CIS Benchmark와 AWS Foundational Security Best Practices에 맞춰 관리된다.
// (Prowler는 Apache 2.0)
//
// 사용법:
//   node scripts/rag/build-aws-baseline-dataset.mjs           # 만들어서 파일로만
//   node scripts/rag/build-aws-baseline-dataset.mjs --push    # 적재까지

import { writeFileSync, existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const CACHE = resolve(HERE, '.cache-aws-baseline.json')
const OUT = resolve(HERE, 'aws-baseline-dataset.json')
const TREE = 'https://api.github.com/repos/prowler-cloud/prowler/git/trees/master?recursive=1'
const RAW = 'https://raw.githubusercontent.com/prowler-cloud/prowler/master'
const FN_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/rag-index'

const CONCURRENCY = 12   // raw.githubusercontent에 무리가 가지 않는 선

const SEVERITY_KO = { critical: '치명적', high: '높음', medium: '보통', low: '낮음', informational: '참고' }

// 원문이 마크다운 강조를 쓴다. 임베딩에는 방해만 되므로 걷어낸다.
const clean = (t) => String(t || '')
  .replace(/\*\*/g, '')
  .replace(/`/g, '')
  .replace(/\s*\n\s*/g, ' ')
  .replace(/[ \t]{2,}/g, ' ')
  .trim()

async function loadChecks() {
  if (existsSync(CACHE)) {
    console.log('캐시 사용:', CACHE)
    return JSON.parse(readFileSync(CACHE, 'utf8'))
  }

  console.log('체크 목록 받는 중...')
  const treeRes = await fetch(TREE)
  if (!treeRes.ok) throw new Error(`목록 실패: ${treeRes.status}`)
  const tree = await treeRes.json()
  const paths = tree.tree
    .filter((x) => x.path.startsWith('prowler/providers/aws/services/') && x.path.endsWith('.metadata.json'))
    .map((x) => x.path)

  console.log(`체크 ${paths.length}개 내려받는 중...`)
  const out = []
  for (let i = 0; i < paths.length; i += CONCURRENCY) {
    const group = paths.slice(i, i + CONCURRENCY)
    const got = await Promise.all(group.map(async (p) => {
      try {
        const r = await fetch(`${RAW}/${p}`)
        if (!r.ok) return null
        return await r.json()
      } catch { return null }
    }))
    out.push(...got.filter(Boolean))
    if ((i / CONCURRENCY) % 10 === 0) console.log(`  ${Math.min(i + CONCURRENCY, paths.length)}/${paths.length}`)
  }
  writeFileSync(CACHE, JSON.stringify(out))
  return out
}

const checks = await loadChecks()
const docs = []

for (const c of checks) {
  const title = clean(c.CheckTitle)
  const desc = clean(c.Description)
  const risk = clean(c.Risk)
  const fix = clean(c.Remediation?.Recommendation?.Text)
  if (!title || (!desc && !risk)) continue

  const severity = SEVERITY_KO[String(c.Severity || '').toLowerCase()] || c.Severity || '-'
  const service = c.ServiceName || c.CheckID?.split('_')[0] || 'aws'

  // 검색에 걸릴 정보를 앞에 모으고, 위험과 조치를 함께 담는다.
  // "왜 문제냐"와 "그래서 어떻게 하냐"가 한 조각에 있어야 설명을 만들 때 쓸모가 있다.
  const content = [
    `AWS 보안 기준 — ${title}`,
    `서비스: ${service} · 심각도: ${severity}`,
    desc ? `\n설명: ${desc.slice(0, 700)}` : '',
    risk ? `\n위험: ${risk.slice(0, 700)}` : '',
    fix ? `\n조치: ${fix.slice(0, 700)}` : '',
  ].filter(Boolean).join('\n')

  docs.push({
    source: 'aws_baseline',
    ref: c.CheckID,
    content,
    meta: {
      service,
      severity: String(c.Severity || '').toLowerCase(),
      categories: c.Categories || [],
      url: c.RelatedUrl || null,
    },
  })
}

writeFileSync(OUT, JSON.stringify(docs, null, 2))
console.log(`\n생성: ${docs.length}건 → ${OUT}`)
const bySvc = docs.reduce((a, d) => (a[d.meta.service] = (a[d.meta.service] || 0) + 1, a), {})
console.log('서비스 상위:', Object.entries(bySvc).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, v]) => `${k}:${v}`).join(', '))
const bySev = docs.reduce((a, d) => (a[d.meta.severity] = (a[d.meta.severity] || 0) + 1, a), {})
console.log('심각도:', Object.entries(bySev).map(([k, v]) => `${k}:${v}`).join(', '))

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
      console.error(`  ${i}~${i + slice.length} 실패:`, body.error || JSON.stringify(body.failures).slice(0, 200))
      continue
    }
    sent += body.inserted
    console.log(`  ${Math.min(i + CHUNK, docs.length)}/${docs.length} 적재됨`)
  } catch (e) {
    console.error(`  ${i}~${i + slice.length} 오류:`, String(e).slice(0, 150))
  }
}
console.log(`\n적재 완료: ${sent}건`)
