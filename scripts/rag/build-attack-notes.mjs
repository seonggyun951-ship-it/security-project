// 근거로 쓰는 MITRE 기법과 OWASP 항목에 한국어 해설을 덧붙인다.
//
// 두 자료는 원문이 영어다. 제목과 전술만 한국어 라벨을 달아 뒀더니 화면 발췌에도
// 설명 생성에도 영어 단락이 그대로 나갔다. ISMS-P는 원문이 한국어인 데다 인증기준과
// 확인사항이 문장으로 있어 "무엇을 해야 하는가"까지 읽히는데, 이쪽은 "무엇인지"조차
// 안 읽혔다.
//
// 전부 옮기지는 않는다. MITRE 697건·OWASP 59건 중 실제로 근거가 되는 것은
// scan.js의 ATTACK_MAP·OWASP_MAP에 적힌 14종뿐이다. 그것만 손으로 쓴다 —
// 기계 번역으로 697건을 밀면 검수할 수 없는 문장이 지식에 쌓인다.
//
// 완화책은 손으로 적지 않고 원본에서 뽑는다. STIX 번들에 course-of-action이
// attack-pattern을 mitigates 하는 관계가 들어 있다(1,448건). 어느 기법에 어떤
// 완화책이 붙는지는 MITRE가 정한 것이지 우리가 판단할 일이 아니다.
//
// 사용법:
//   node scripts/rag/build-attack-notes.mjs           # 만들어서 보여주기만
//   node scripts/rag/build-attack-notes.mjs --push    # 적재까지 (SB_SERVICE_KEY 필요)

import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const MITRE_CACHE = resolve(HERE, '.cache-mitre.json')
const FN_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/rag-index'

// 한국어 문구 규칙은 scan.js의 CHECK_LABEL과 같다:
// 뜻을 먼저 쓰고 원어는 괄호에, 직역하지 않고, '-습니다'로 끝맺는다.
//
// title — 첫 줄. 화면이 이 줄을 근거의 제목으로 쓰므로 반드시 남겨야 한다.
//         원문 제목이 영어라 여기서 한국어로 바꿔 단다.
// what  — 공격자가 이 기법으로 무엇을 하는가 (한 문장)
// why   — 우리 설정이 왜 이 기법을 불러오는가 (점검 결과와 이어지는 대목)
const MITRE_NOTES = {
  'T1021.004': {
    title: 'MITRE ATT&CK T1021.004 — 원격 서비스: SSH',
    what: '공격자가 훔친 계정으로 SSH에 로그인해 다른 서버로 옮겨 다닙니다.',
    why: 'SSH 포트가 인터넷에 열려 있으면 자격증명만 손에 넣으면 바로 들어올 수 있습니다.',
  },
  'T1021.001': {
    title: 'MITRE ATT&CK T1021.001 — 원격 서비스: 원격 데스크톱(RDP)',
    what: '공격자가 훔친 계정으로 원격 데스크톱에 접속해 화면을 그대로 조작합니다.',
    why: '3389 포트가 인터넷에 열려 있으면 무차별 대입의 표적이 되고, 뚫리면 서버를 직접 다루게 됩니다.',
  },
  'T1190': {
    title: 'MITRE ATT&CK T1190 — 외부에 노출된 서비스 공격',
    what: '인터넷에 드러난 서비스의 취약점을 찔러 침투합니다. 초기 침투에서 가장 흔한 경로입니다.',
    why: '포트를 전부 열어 두거나 퍼블릭 IP를 붙이면 공격자가 찾아 볼 수 있는 면이 그만큼 넓어집니다.',
  },
  'T1552.005': {
    title: 'MITRE ATT&CK T1552.005 — 방치된 자격증명: 인스턴스 메타데이터',
    what: '인스턴스 메타데이터 서비스에 질의해 그 서버에 붙은 임시 자격증명을 꺼내 갑니다.',
    why: 'IMDSv2를 끄면 서버 안에서 요청 한 번으로 자격증명이 나옵니다. 서버 측 요청 위조(SSRF)와 엮이면 밖에서도 꺼낼 수 있습니다.',
  },
  'T1530': {
    title: 'MITRE ATT&CK T1530 — 클라우드 저장소에서 데이터 수집',
    what: '클라우드 저장소에 담긴 데이터를 그대로 가져갑니다.',
    why: '버킷이 공개돼 있으면 침투 과정 없이 주소만 알면 내려받을 수 있습니다.',
  },
  'T1110': {
    title: 'MITRE ATT&CK T1110 — 무차별 대입',
    what: '비밀번호를 반복해서 찍어 맞힙니다. 흔한 비밀번호를 여러 계정에 돌려 보는 방식도 씁니다.',
    why: '길이·복잡도·재사용 제한이 느슨하면 시도 횟수 안에 맞을 확률이 올라갑니다.',
  },
  'T1078.004': {
    title: 'MITRE ATT&CK T1078.004 — 유효 계정 악용: 클라우드 계정',
    what: '훔치거나 주운 클라우드 계정으로 정상 사용자처럼 로그인합니다. 침입 흔적이 정상 접속과 구별되지 않습니다.',
    why: 'MFA가 없거나 오래된 액세스 키가 남아 있으면 자격증명 하나로 그대로 들어옵니다.',
  },
  'T1548': {
    title: 'MITRE ATT&CK T1548 — 권한 상승 통제 우회',
    what: '권한 통제를 우회해 자기 권한을 관리자 수준까지 끌어올립니다.',
    why: '정책이 권한 부여·역할 변경을 허용하면 낮은 권한으로 시작해도 결국 전체를 쥘 수 있습니다.',
  },
  'T1685.002': {
    title: 'MITRE ATT&CK T1685.002 — 보안 도구 무력화: 클라우드 로그 끄기',
    what: '클라우드 로깅을 끄거나 지워 자기 행적을 남기지 않습니다.',
    why: '기록이 처음부터 꺼져 있으면 공격자가 지우는 수고조차 필요 없습니다. 침해를 나중에 되짚을 수단도 함께 사라집니다.',
  },
}

const OWASP_NOTES = {
  'A05:2021 How to Prevent': {
    title: 'OWASP A05:2021 — 보안 설정 오류 · 예방 방법',
    what: '필요 없는 기능이 켜져 있거나 기본값을 그대로 두어 생기는 문제입니다.',
    why: '쓰지 않는 포트·기능을 닫고, 기본 계정과 기본 설정을 바꾸고, 설정이 의도대로인지 반복해서 확인하라는 것이 이 항목의 요구입니다.',
  },
  'A01:2021 How to Prevent': {
    title: 'OWASP A01:2021 — 취약한 접근 통제 · 예방 방법',
    what: '권한이 없어야 할 대상이 자원에 닿는 문제입니다.',
    why: '기본을 거부로 두고 꼭 필요한 것만 허용하며, 권한 검사를 한곳에서 강제하라는 것이 이 항목의 요구입니다.',
  },
  'A07:2021 How to Prevent': {
    title: 'OWASP A07:2021 — 식별·인증 실패 · 예방 방법',
    what: '계정이 누구인지 확인하는 과정이 약한 문제입니다.',
    why: '다중 인증을 쓰고, 흔한 비밀번호를 막고, 무차별 대입 시도를 제한하라는 것이 이 항목의 요구입니다.',
  },
  'A09:2021 How to Prevent': {
    title: 'OWASP A09:2021 — 로깅·모니터링 실패 · 예방 방법',
    what: '무슨 일이 있었는지 남지 않아 침해를 늦게 아는 문제입니다.',
    why: '로그인·접근 실패 같은 중요한 사건을 남기고, 위변조되지 않게 보관하며, 이상 징후에 경보가 울리게 하라는 것이 이 항목의 요구입니다.',
  },
  'A02:2021 How to Prevent': {
    title: 'OWASP A02:2021 — 암호화 실패 · 예방 방법',
    what: '보호해야 할 데이터가 평문으로 놓이거나 약하게 암호화되는 문제입니다.',
    why: '저장할 때와 주고받을 때 모두 암호화하고, 오래된 알고리즘을 쓰지 말고, 키를 안전하게 관리하라는 것이 이 항목의 요구입니다.',
  },
}

// STIX에서 기법별 완화책을 뽑는다.
function loadMitigations() {
  if (!existsSync(MITRE_CACHE)) {
    console.error(`STIX 캐시가 없습니다: ${MITRE_CACHE}`)
    console.error('먼저 build-mitre-dataset.mjs를 한 번 돌리세요.')
    process.exit(1)
  }
  const objs = JSON.parse(readFileSync(MITRE_CACHE, 'utf8')).objects || []
  const extId = (o) =>
    ((o.external_references || []).find((r) => r.source_name === 'mitre-attack') || {}).external_id

  const techByStix = new Map()
  const coaByStix = new Map()
  for (const o of objs) {
    if (o.type === 'attack-pattern') techByStix.set(o.id, extId(o))
    else if (o.type === 'course-of-action') coaByStix.set(o.id, { id: extId(o), name: o.name })
  }

  const out = {}
  for (const o of objs) {
    if (o.type !== 'relationship' || o.relationship_type !== 'mitigates') continue
    const t = techByStix.get(o.target_ref)
    const m = coaByStix.get(o.source_ref)
    if (!t || !m?.id) continue
    ;(out[t] ||= []).push(m.id)
  }
  return out
}

// 완화책 이름은 이미 한국어로 옮겨 둔 것이 지식 베이스에 있다(mitigation 44건).
// STIX의 영어 이름을 그대로 쓰지 않고 그쪽을 끌어다 쓴다 — 같은 이름을 두 벌로
// 관리하면 한쪽만 고쳐진다.
async function loadKoreanNames() {
  const key = process.env.SB_SERVICE_KEY
  if (!key) return {}
  const { createClient } = await import('@supabase/supabase-js')
  const db = createClient('https://phqiejtztwhychazikim.supabase.co', key)
  const { data, error } = await db.from('knowledge').select('ref, content').eq('source', 'mitigation')
  if (error) { console.error('완화책 이름을 못 읽었습니다:', error.message); return {} }
  const out = {}
  for (const row of data || []) {
    // 'MITRE ATT&CK 완화책 M1032 — Multi-factor Authentication (다중 인증(MFA))'
    const head = String(row.content).split('\n')[0]
    const m = head.match(/—\s*(.+)$/)
    if (m) out[row.ref] = m[1].trim()
  }
  return out
}

const mitigations = loadMitigations()
const koNames = await loadKoreanNames()
const docs = []

for (const [ref, note] of Object.entries(MITRE_NOTES)) {
  // 한국어 이름이 있으면 그것으로, 없으면 번호만 적는다.
  const fixes = (mitigations[ref] || []).map((id) => (koNames[id] ? `${id} ${koNames[id]}` : id))
  docs.push({
    source: 'mitre',
    ref,
    // 한국어를 맨 앞에 둔다. 화면 발췌는 앞 220자만 보여주고,
    // 설명 생성도 앞부분을 잘라 쓰기 때문에 뒤에 붙이면 없는 것과 같다.
    // 첫 줄은 반드시 제목이어야 한다 — 화면이 lines[0]을 근거의 제목으로 쓴다.
    content_prefix: [
      note.title,
      `무엇을 하는 공격인가: ${note.what}`,
      `우리 설정과의 관계: ${note.why}`,
      ...(fixes.length ? [`MITRE가 제시한 완화책: ${fixes.join(' · ')}`] : []),
    ].join('\n'),
  })
}

for (const [ref, note] of Object.entries(OWASP_NOTES)) {
  docs.push({
    source: 'owasp',
    ref,
    content_prefix: [
      note.title,
      `무엇이 문제인가: ${note.what}`,
      `무엇을 하라는 것인가: ${note.why}`,
    ].join('\n'),
  })
}

console.log(`한국어 해설 ${docs.length}건 (MITRE ${Object.keys(MITRE_NOTES).length} · OWASP ${Object.keys(OWASP_NOTES).length})`)
for (const d of docs) {
  const fixes = d.source === 'mitre' ? (mitigations[d.ref] || []).length : 0
  console.log(`  [${d.source}] ${d.ref}${d.source === 'mitre' ? ` · 완화책 ${fixes}개` : ''}`)
}

if (!process.argv.includes('--push')) {
  console.log('\n적재하려면 --push (SB_SERVICE_KEY 필요)')
  process.exit(0)
}

const key = process.env.SB_SERVICE_KEY
if (!key) { console.error('SB_SERVICE_KEY가 없습니다'); process.exit(1) }

const res = await fetch(FN_URL, {
  method: 'POST',
  headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
  body: JSON.stringify({ prefix: docs }),
})
const body = await res.json()
console.log('\n' + JSON.stringify(body))
