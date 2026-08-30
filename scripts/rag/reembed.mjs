// 지식 베이스 전체를 다시 임베딩한다.
//
// 임베딩 모델을 바꾸면 기존 벡터는 못 쓴다. 모델마다 좌표계가 달라서, 질문만 새 모델로
// 바꿔 넣으면 검색 결과가 뒤죽박죽이 된다. 전부 다시 만들어야 한다.
//
// 임베딩 자체는 rag-index 함수가 한다. NIM 키가 Supabase 시크릿에만 있고, 그걸 로컬로
// 꺼내오지 않는 편이 낫기 때문이다. 이 스크립트는 남은 게 0이 될 때까지 부르기만 한다.
//
// 한 번 호출로 다 끝내지 않는 이유는 함수 실행 시간 제한이다. NIM 무료 티어가 분당
// 40회라 호출 사이에 간격도 둬야 해서, 3,000건이면 한 번에 담을 수 없다.
//
// 사용법:
//   SB_SERVICE_KEY=... node scripts/rag/reembed.mjs

const FN_URL = 'https://phqiejtztwhychazikim.supabase.co/functions/v1/rag-index'
const CHUNK = 64   // 한 번 호출에 처리할 건수

const key = process.env.SB_SERVICE_KEY
if (!key) { console.error('SB_SERVICE_KEY가 없습니다'); process.exit(1) }

const t0 = Date.now()
let total = 0
let round = 0

while (true) {
  round++
  const res = await fetch(FN_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ reembed: { limit: CHUNK } }),
  })
  const body = await res.json().catch(() => ({ ok: false, error: `HTTP ${res.status}` }))

  if (body.updated === undefined) {
    console.error('응답이 이상합니다:', JSON.stringify(body).slice(0, 300))
    break
  }

  total += body.updated
  const sec = Math.round((Date.now() - t0) / 1000)
  console.log(`  ${round}회차: ${body.updated}건 처리 · 남은 ${body.remaining}건 · ${sec}초 경과`)
  if (body.errors?.length) console.error('    실패:', body.errors.slice(0, 3).join(' | '))

  if (body.remaining === 0) break

  // 진행이 하나도 없으면 계속 불러봐야 같은 결과다. 원인을 보고 멈춘다.
  if (body.updated === 0) {
    console.error('진행이 없어 중단합니다. 위 실패 사유를 확인하세요.')
    break
  }
}

console.log(`\n완료: ${total}건 · ${Math.round((Date.now() - t0) / 1000)}초`)
