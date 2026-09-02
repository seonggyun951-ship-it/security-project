// ISMS-P 인증기준 101개를 지식 베이스용 문서로 만든다.
//
// AWS 기준선(aws_baseline)이 "AWS가 권하는 설정"이라면 이쪽은 "국내 인증에서 요구하는 것"이다.
// 같은 위반을 두고 "AWS 기준에 어긋난다"에서 그치지 않고 "ISMS-P 2.6.1 네트워크 접근에
// 걸린다"까지 말할 수 있게 된다.
//
// 한국어 자료라는 점도 크다. 지식이 대부분 영어라 한국어 질문과는 좌표 거리가 멀어
// 점수가 안 나왔다(MITRE·OWASP가 0.3대). 한국어 문서가 늘면 그 격차가 줄어든다.
//
// 저작권 — 안내서 원문의 표시를 따른다:
//   "본 안내서 내용의 무단전재를 금하며, 가공･인용할 때는 출처를 밝혀 주시기 바랍니다."
// 가공은 허용되므로 항목을 쪼개 넣되, 문서마다 출처를 적는다. 그리고 '세부 설명'(해설
// 본문)은 넣지 않는다 — 그건 옮기면 인용이 아니라 전재에 가깝다. 인증기준과 확인사항까지만.
//
// PDF와 만들어진 데이터셋은 저장소에 두지 않는다(.gitignore). 원문을 재배포하지 않기
// 위해서이고, 필요하면 이 스크립트가 다시 받아 만든다.
//
// 사용법:
//   node scripts/rag/build-ismsp-dataset.mjs           # 만들어서 파일로만 저장
//   node scripts/rag/build-ismsp-dataset.mjs --push    # 적재까지 (SB_SERVICE_KEY 필요)

import { writeFileSync, existsSync, readFileSync, mkdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { PDFParse } from 'pdf-parse'

const HERE = dirname(fileURLToPath(import.meta.url))
const CACHE_DIR = resolve(HERE, '.cache-ismsp')
const PDF_PATH = resolve(CACHE_DIR, 'isms-p-guide.pdf')
const TXT_PATH = resolve(CACHE_DIR, 'isms-p-guide.txt')
const OUT = resolve(HERE, 'ismsp-dataset.json')
const FN_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/rag-index'

// 개인정보 포털 자료실의 「ISMS-P 인증기준 안내서」(2023.11)
const PDF_URL = 'https://www.privacy.go.kr/cmm/fms/FileDown.do?atchFileId=ATCH_000000000880227&fileSn=1'
const REFERER = 'https://www.privacy.go.kr/front/bbs/bbsView.do?bbsNo=BBSMSTR_000000000049&bbscttNo=20677'

const SOURCE_NOTE =
  '출처: 개인정보보호위원회·과학기술정보통신부 ' +
  '「정보보호 및 개인정보보호 관리체계 인증기준 안내서」 2023.11.'

// 불릿이 사설 사용 영역(U+E000~U+F8FF) 문자다. 글꼴에 심어둔 기호라 유니코드 표준
// 문자가 아니고 \s로도 안 걸린다(U+F09F 등). 기호를 소스에 직접 적으면 편집 과정에서
// 이스케이프가 풀려 문자 클래스 범위가 뒤집히므로 코드값으로만 쓴다.
const BULLETS = new RegExp('^[\\s\\u2022\\u00b7\\u25b6\\u2013\\u2014\\-\\ue000-\\uf8ff]+')
const stripBullet = (s) => s.replace(BULLETS, '').trim()
const tidy = (s) =>
  s.replace(BULLETS, '').replace(/\s+/g, ' ').replace(/\s*·\s*/g, '·').trim()

async function loadText() {
  if (existsSync(TXT_PATH)) return readFileSync(TXT_PATH, 'utf8')

  mkdirSync(CACHE_DIR, { recursive: true })
  if (!existsSync(PDF_PATH)) {
    console.log('안내서 PDF를 받는 중...')
    const res = await fetch(PDF_URL, { headers: { Referer: REFERER, 'User-Agent': 'Mozilla/5.0' } })
    if (!res.ok) throw new Error(`PDF 내려받기 실패: HTTP ${res.status}`)
    writeFileSync(PDF_PATH, Buffer.from(await res.arrayBuffer()))
  }

  console.log('PDF에서 글자를 뽑는 중...')
  const parser = new PDFParse({ data: new Uint8Array(readFileSync(PDF_PATH)) })
  const { text } = await parser.getText()
  await parser.destroy()
  writeFileSync(TXT_PATH, text, 'utf8')
  return text
}

const text = await loadText()
const lines = text.split('\n').map((l) => l.replace(/\t/g, ' ').replace(/\s+/g, ' ').trim())

// 대분류 이름(2.6. 접근통제). 목차에 페이지 번호와 함께 나온다.
const groups = new Map()
for (const s of lines) {
  const m = s.match(/^(\d\.\d+)\. (.+?)\s*\d{1,3}$/)
  if (m && !groups.has(m[1])) groups.set(m[1], m[2].trim())
}

const CHAPTER = {
  1: '관리체계 수립 및 운영',
  2: '보호대책 요구사항',
  3: '개인정보 처리단계별 요구사항',
}

// 쪽 머리말과, 책등 색인이 한 글자씩 세로로 떨어져 나온 줄을 버린다.
const noise = /^(제\d장.*|정보보호 및 개인정보보호.*|-- \d+ of \d+ --|\d{1,3}|[가-힣])$/

// 본문은 항목마다 같은 뼈대다:
//   항 목 / 인증기준 / 주요 확인사항 / 관련 법규 / 세부 설명
// 머리말이 값과 같은 줄일 때도 있고 다음 줄부터일 때도 있어 둘 다 받는다.
const items = []
let cur = null
let section = null

const flush = () => {
  if (!cur) return
  delete cur.pending
  delete cur.standardDone
  items.push(cur)
}

for (const s of lines) {
  const head = s.match(/^항 ?목 (\d\.\d+\.\d+) (.+)$/)
  if (head) {
    flush()
    cur = { no: head[1], title: head[2].trim(), standard: '', checks: [], laws: [] }
    section = null
    continue
  }
  if (!cur) continue

  // '인증기준'은 항목마다 한 번뿐이다. 세부 설명 안에서 이 말이 다시 나오는 항목이
  // 있어(1.2.4) 그때 수집 모드로 되돌아가면 해설이 통째로 딸려 들어온다.
  const std = s.match(/^인증기준 ?(.*)$/)
  if (std && !cur.standardDone) {
    section = 'standard'
    cur.standardDone = true
    if (std[1]) cur.standard = std[1]
    continue
  }
  if (/^주요 ?확인사항/.test(s)) { section = 'checks'; continue }
  const law = s.match(/^관련 ?법규 ?(.*)$/)
  if (law) { section = 'laws'; const t = stripBullet(law[1]); if (t) cur.laws.push(t); continue }
  if (/^세부 ?설명/.test(s)) { section = 'done'; continue }
  if (section === 'done' || !s || noise.test(s)) continue

  if (section === 'standard') {
    cur.standard += (cur.standard ? ' ' : '') + s
  } else if (section === 'checks') {
    const t = stripBullet(s)
    if (!t) continue
    // 질문 하나가 여러 줄에 걸쳐 있다. 물음표가 나올 때까지 모았다가 한 건으로 만든다.
    if (/\?$/.test(t)) { cur.checks.push(((cur.pending || '') + ' ' + t).trim()); cur.pending = '' }
    else cur.pending = ((cur.pending || '') + ' ' + t).trim()
  } else if (section === 'laws') {
    const t = stripBullet(s)
    if (t) cur.laws.push(t)
  }
}
flush()

for (const it of items) {
  it.standard = tidy(it.standard)
  it.checks = it.checks.map(tidy).filter(Boolean)
  it.laws = it.laws.map(tidy).filter(Boolean)
}

// 여기서 멈춰야 할 것들. 조용히 반쪽짜리를 적재하면 나중에 왜 검색이 헛도는지 못 찾는다.
if (items.length !== 101) throw new Error(`항목 수가 101이 아닙니다: ${items.length}`)
const broken = items.filter((i) => !i.standard || i.checks.length === 0)
if (broken.length) throw new Error(`내용이 빈 항목: ${broken.map((i) => i.no).join(', ')}`)

// 항목 하나가 곧 통제 하나라 쪼개지 않는다. 인증기준 105자 + 확인사항 서넛이면
// 400~600자로, 임베딩이 뭉뚱그려지지 않는 크기다.
const docs = items.map((it) => {
  const group = it.no.replace(/\.\d+$/, '')
  const groupName = groups.get(group) || ''
  const chapter = CHAPTER[it.no[0]] || ''
  return {
    source: 'ismsp',
    ref: `${it.no} ${it.title}`,
    content: [
      `ISMS-P 인증기준 ${it.no} — ${it.title}`,
      `영역: ${chapter} > ${group}. ${groupName}`,
      '',
      `인증기준: ${it.standard}`,
      '',
      '주요 확인사항:',
      ...it.checks.map((c) => `· ${c}`),
      ...(it.laws.length ? ['', `관련 법규: ${it.laws.join(' / ')}`] : []),
      '',
      SOURCE_NOTE,
    ].join('\n'),
    meta: {
      no: it.no,
      title: it.title,
      group: `${group}. ${groupName}`,
      chapter,
      laws: it.laws,
    },
  }
})

writeFileSync(OUT, JSON.stringify(docs, null, 2))
console.log(`생성: ${docs.length}건 → ${OUT}`)
const byChapter = docs.reduce((a, d) => (a[d.meta.chapter] = (a[d.meta.chapter] || 0) + 1, a), {})
console.log('영역별:', Object.entries(byChapter).map(([k, v]) => `${k} ${v}`).join(' · '))
const lens = docs.map((d) => d.content.length)
console.log(`길이: 평균 ${Math.round(lens.reduce((a, b) => a + b) / lens.length)}자 · 최장 ${Math.max(...lens)}자`)

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
