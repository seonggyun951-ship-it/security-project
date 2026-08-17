// MITRE ATT&CK 완화책(mitigation).
//
// 지식 베이스에 공격 기법은 697건 있는데 "그래서 어떻게 막는지"가 없었다.
// 설명을 만들 때 공격 설명은 MITRE에서 오고 막는 방법은 규칙 엔진 문장을
// 되풀이하는 식이 되었다.
//
// 완화책마다 어떤 기법에 적용되는지도 함께 담는다. STIX 번들의 relationship에
// mitigates 관계가 들어 있어 그것으로 잇는다. 기법 ID가 문서 안에 있어야
// "SSH 전체개방" 같은 질문에서 관련 완화책이 걸린다.
//
// 원본은 build-mitre-dataset.mjs가 받아둔 캐시를 함께 쓴다.
//
// 사용법:
//   node --max-old-space-size=4096 scripts/rag/build-mitigation-dataset.mjs [--push]

import { writeFileSync, existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const CACHE = resolve(HERE, '.cache-mitre.json')
const OUT = resolve(HERE, 'mitigation-dataset.json')
const SRC = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'
const FN_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/rag-index'

// 완화책 이름의 한국어 표기.
// 원문이 영어라 "권한 상승 막는 방법" 같은 한국어 질문에 잘 걸리지 않는다.
// 이름을 옮겨 적어 검색이 붙게 한다. 설명 본문은 원문 그대로 둔다.
const NAME_KO = {
  'Network Segmentation': '네트워크 분리',
  'Filter Network Traffic': '네트워크 트래픽 필터링',
  'Limit Access to Resource Over Network': '네트워크를 통한 리소스 접근 제한',
  'Multi-factor Authentication': '다중 인증(MFA)',
  'Password Policies': '비밀번호 정책',
  'Account Use Policies': '계정 사용 정책',
  'User Account Management': '사용자 계정 관리',
  'Privileged Account Management': '특권 계정 관리',
  'User Account Control': '사용자 계정 컨트롤',
  'Restrict File and Directory Permissions': '파일·디렉터리 권한 제한',
  'Encrypt Sensitive Information': '민감 정보 암호화',
  'Data Backup': '데이터 백업',
  'Audit': '감사',
  'Update Software': '소프트웨어 갱신',
  'Vulnerability Scanning': '취약점 스캔',
  'Application Isolation and Sandboxing': '애플리케이션 격리·샌드박스',
  'Execution Prevention': '실행 차단',
  'Exploit Protection': '익스플로잇 보호',
  'Antivirus/Antimalware': '백신·안티멀웨어',
  'Behavior Prevention on Endpoint': '엔드포인트 행위 차단',
  'Disable or Remove Feature or Program': '기능·프로그램 비활성화 또는 제거',
  'Limit Software Installation': '소프트웨어 설치 제한',
  'Software Configuration': '소프트웨어 설정',
  'Operating System Configuration': '운영체제 설정',
  'Boot Integrity': '부팅 무결성',
  'Code Signing': '코드 서명',
  'Credential Access Protection': '자격 증명 접근 보호',
  'Active Directory Configuration': '액티브 디렉터리 설정',
  'Network Intrusion Prevention': '네트워크 침입 방지',
  'SSL/TLS Inspection': 'SSL/TLS 검사',
  'Restrict Web-Based Content': '웹 콘텐츠 제한',
  'Threat Intelligence Program': '위협 인텔리전스',
  'User Training': '사용자 교육',
  'Pre-compromise': '침해 이전 단계',
  'Do Not Mitigate': '완화 불가',
  'Remote Data Storage': '원격 데이터 저장',
  'Application Developer Guidance': '애플리케이션 개발 지침',
  'Limit Hardware Installation': '하드웨어 설치 제한',
  'Environment Variable Permissions': '환경 변수 권한',
  'Data Loss Prevention': '데이터 유출 방지(DLP)',
  'Privileged Process Integrity': '특권 프로세스 무결성',
  'Out-of-Band Communications Channel': '대역 외 통신 채널',
  'Restrict Registry Permissions': '레지스트리 권한 제한',
  'Restrict Library Loading': '라이브러리 로딩 제한',
}

const clean = (t) => String(t || '')
  .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
  .replace(/\(Citation:[^)]*\)/g, '')
  .replace(/<[^>]+>/g, '')
  .replace(/\s*\n\s*\n\s*/g, '\n')
  .replace(/[ \t]{2,}/g, ' ')
  .trim()

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

// STIX id → 기법 정보. 완화책이 어떤 기법을 막는지 잇는 데 쓴다.
const techniqueById = new Map()
for (const o of objects) {
  if (o.type === 'attack-pattern' && !o.x_mitre_deprecated && !o.revoked && attackId(o)) {
    techniqueById.set(o.id, { id: attackId(o), name: o.name, sub: !!o.x_mitre_is_subtechnique })
  }
}
// 하위 기법 이름 보완 ("SSH" → "Remote Services: SSH")
const byAttackId = new Map([...techniqueById.values()].map((t) => [t.id, t]))
for (const t of techniqueById.values()) {
  if (!t.sub) continue
  const parent = byAttackId.get(t.id.split('.')[0])
  if (parent) t.name = `${parent.name}: ${t.name}`
}

// 완화책 → 막아주는 기법 목록
const mitigates = new Map()
for (const o of objects) {
  if (o.type !== 'relationship' || o.relationship_type !== 'mitigates') continue
  if (o.x_mitre_deprecated || o.revoked) continue
  const tech = techniqueById.get(o.target_ref)
  if (!tech) continue
  if (!mitigates.has(o.source_ref)) mitigates.set(o.source_ref, [])
  mitigates.get(o.source_ref).push(tech)
}

const mitigations = objects.filter(
  (o) => o.type === 'course-of-action' && !o.x_mitre_deprecated && !o.revoked && attackId(o),
)

const docs = []
for (const m of mitigations) {
  const id = attackId(m)
  const desc = clean(m.description)
  if (!desc) continue

  const covered = (mitigates.get(m.id) || []).sort((a, b) => a.id.localeCompare(b.id))

  // 막아주는 기법이 많으면 문서가 길어진다. 앞쪽만 적고 나머지는 개수로 알린다.
  const shown = covered.slice(0, 18)
  const rest = covered.length - shown.length

  // 원문이 영어이고 문장이 추상적이라 한국어 질문과 잘 붙지 않는다.
  // 이름이 알려진 것들은 한국어 표기를 함께 적어 검색이 걸리게 한다.
  const ko = NAME_KO[m.name]

  const content = [
    `MITRE ATT&CK 완화책 ${id} — ${m.name}${ko ? ` (${ko})` : ''}`,
    ko ? `이 완화책은 ${ko}에 해당합니다. 공격을 막거나 피해를 줄이는 방법입니다.` : null,
    '',
    desc.slice(0, 1200),
    covered.length > 0 ? '' : null,
    covered.length > 0
      ? `이 완화책이 대응하는 공격 기법 (${covered.length}개): `
        + shown.map((t) => `${t.id} ${t.name}`).join(', ')
        + (rest > 0 ? ` 외 ${rest}개` : '')
      : null,
  ].filter((x) => x !== null).join('\n')

  docs.push({
    source: 'mitigation',
    ref: id,
    content,
    meta: {
      name: m.name,
      technique_count: covered.length,
      technique_ids: covered.map((t) => t.id),
    },
  })
}

writeFileSync(OUT, JSON.stringify(docs, null, 2))
console.log(`생성: ${docs.length}건 → ${OUT}`)
const linked = docs.filter((d) => d.meta.technique_count > 0).length
console.log(`  기법과 연결된 것: ${linked}건`)
console.log(`  대응 기법이 많은 것: ${docs.slice().sort((a, b) => b.meta.technique_count - a.meta.technique_count)
  .slice(0, 3).map((d) => `${d.ref}(${d.meta.technique_count})`).join(', ')}`)

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
