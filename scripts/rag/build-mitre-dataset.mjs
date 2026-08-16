// MITRE ATT&CK 기법을 지식 베이스용 문서로 만든다.
//
// 규칙 엔진은 "이 설정이 위험하다"까지만 안다. 왜 위험한지, 공격자가 실제로
// 어떻게 악용하는지는 여기서 온다. 규칙에 없는 조합을 물었을 때 기댈 곳이기도 하다.
//
// 원본은 MITRE가 공개하는 STIX 번들(약 54MB)이다. 한 번 받아두고 캐시를 쓴다.
//
// 사용법:
//   node scripts/rag/build-mitre-dataset.mjs           # 만들어서 파일로만 저장
//   node scripts/rag/build-mitre-dataset.mjs --push    # 적재까지 (SB_SERVICE_KEY 필요)

import { writeFileSync, existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const CACHE = resolve(HERE, '.cache-mitre.json')
const OUT = resolve(HERE, 'mitre-dataset.json')
const SRC = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'
const FN_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/rag-index'

// 설명에 섞인 참고 표시를 걷어낸다. 임베딩에 도움이 안 되고 자리만 차지한다.
//   [Valid Accounts](https://attack.mitre.org/techniques/T1078) → Valid Accounts
//   (Citation: Someone 2020)                                    → 삭제
function clean(text) {
  return String(text || '')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/\(Citation:[^)]*\)/g, '')
    .replace(/<[^>]+>/g, '')
    .replace(/\s*\n\s*\n\s*/g, '\n')
    .replace(/[ \t]{2,}/g, ' ')
    .trim()
}

const TACTIC_KO = {
  'reconnaissance': '정찰',
  'resource-development': '자원 개발',
  'initial-access': '초기 침투',
  'execution': '실행',
  'persistence': '지속성 확보',
  'privilege-escalation': '권한 상승',
  'defense-evasion': '방어 회피',
  'credential-access': '자격 증명 접근',
  'discovery': '내부 정찰',
  'lateral-movement': '측면 이동',
  'collection': '수집',
  'command-and-control': '명령 제어',
  'exfiltration': '유출',
  'impact': '영향',
}

async function load() {
  if (existsSync(CACHE)) {
    console.log('캐시 사용:', CACHE)
    return JSON.parse(readFileSync(CACHE, 'utf8'))
  }
  console.log('MITRE STIX 내려받는 중... (약 54MB)')
  const res = await fetch(SRC)
  if (!res.ok) throw new Error(`내려받기 실패: ${res.status}`)
  const text = await res.text()
  writeFileSync(CACHE, text)
  return JSON.parse(text)
}

const bundle = await load()
const objects = bundle.objects

const attackId = (o) =>
  (o.external_references || []).find((r) => r.source_name === 'mitre-attack')?.external_id || null

// 유효한 기법만. 폐기(deprecated)되거나 철회(revoked)된 것은 지금 쓰는 지식이 아니다.
const techniques = objects.filter(
  (o) => o.type === 'attack-pattern' && !o.x_mitre_deprecated && !o.revoked && attackId(o),
)

// 하위 기법은 이름이 "SSH"처럼 짧아 그것만으로는 뜻이 통하지 않는다.
// 상위 기법 이름을 붙여 "Remote Services: SSH"로 만든다.
const byId = new Map(techniques.map((t) => [attackId(t), t]))
function fullName(t) {
  const id = attackId(t)
  if (!t.x_mitre_is_subtechnique) return t.name
  const parent = byId.get(id.split('.')[0])
  return parent ? `${parent.name}: ${t.name}` : t.name
}

const docs = []
for (const t of techniques) {
  const id = attackId(t)
  const tactics = (t.kill_chain_phases || [])
    .filter((p) => p.kill_chain_name === 'mitre-attack')
    .map((p) => TACTIC_KO[p.phase_name] || p.phase_name)
  const platforms = t.x_mitre_platforms || []
  const desc = clean(t.description)
  if (!desc) continue

  // 검색이 걸릴 만한 정보를 앞쪽에 모은다.
  // 설명이 아주 긴 기법이 있어 잘라낸다 — 임베딩 모델 입력 한계도 있고,
  // 뒤쪽은 대개 세부 사례라 검색 정확도에 크게 기여하지 않는다.
  const content = [
    `MITRE ATT&CK ${id} — ${fullName(t)}`,
    tactics.length ? `전술: ${tactics.join(', ')}` : null,
    platforms.length ? `대상 플랫폼: ${platforms.join(', ')}` : null,
    '',
    desc.slice(0, 1500),
  ].filter((x) => x !== null).join('\n')

  docs.push({
    source: 'mitre',
    ref: id,
    content,
    meta: {
      name: fullName(t),
      tactics: (t.kill_chain_phases || []).map((p) => p.phase_name),
      platforms,
      is_subtechnique: !!t.x_mitre_is_subtechnique,
    },
  })
}

writeFileSync(OUT, JSON.stringify(docs, null, 2))
console.log(`생성: ${docs.length}건 → ${OUT}`)

const cloud = docs.filter((d) => (d.meta.platforms || []).some((p) => /IaaS|Containers|SaaS|Identity|Network/i.test(p)))
console.log(`  이 중 클라우드·네트워크 관련: ${cloud.length}건`)

if (!process.argv.includes('--push')) {
  console.log('\n적재하려면 --push (SB_SERVICE_KEY 필요)')
  process.exit(0)
}

const key = process.env.SB_SERVICE_KEY
if (!key) { console.error('SB_SERVICE_KEY가 없습니다'); process.exit(1) }

// Edge Function이 32건씩 임베딩하며 호출 사이에 쉰다.
// 한 요청에 너무 많이 담으면 함수 실행 시간 제한에 걸리므로 여기서도 쪼갠다.
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
