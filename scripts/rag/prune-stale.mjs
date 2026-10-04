// 적재 뒤 옛 문서를 지운다. 정책·판정 사례처럼 '우리 코드에서 만들어내는' 출처에만 쓴다.
//
// rag-index는 (출처, 내용 해시)가 같을 때만 덮어쓴다. 값이 바뀌어 내용이 달라지면
// 새 문서가 추가될 뿐 옛 문서는 그대로 남는다. 그러면 검색에 옛 판정(예: 10.99가 없는
// 사내망 목록)이 섞여 나오고, LLM은 그걸 확신에 차서 말한다 — 2026-10에 실제로 겪었다.
//
// 방금 넣은 내용과 다른 문서만 지운다. 호출하는 쪽은 적재가 전부 성공했을 때만 불러야 한다.
// KEV·MITRE처럼 밖에서 받아오는 출처에는 쓰지 않는다 — 한 번에 다 받는다는 보장이 없다.

const REST = 'https://phqiejtztwhychazikim.supabase.co/rest/v1/knowledge'

export async function pruneStale(source, docs, key) {
  const auth = { Authorization: `Bearer ${key}`, apikey: key }
  const res = await fetch(`${REST}?source=eq.${source}&select=id,ref,content`, { headers: auth })
  if (!res.ok) throw new Error(`기존 문서 조회 실패 (${res.status}): ${await res.text()}`)
  const current = await res.json()

  const fresh = new Set(docs.map((d) => d.content))
  const stale = current.filter((row) => !fresh.has(row.content))
  if (stale.length === 0) {
    console.log(`정리할 옛 ${source} 문서 없음`)
    return 0
  }

  // id를 한 번에 너무 많이 붙이면 URL이 길어진다. 나눠서 지운다.
  for (let i = 0; i < stale.length; i += 100) {
    const ids = stale.slice(i, i + 100).map((s) => s.id).join(',')
    const del = await fetch(`${REST}?id=in.(${ids})`, { method: 'DELETE', headers: auth })
    if (!del.ok) throw new Error(`옛 문서 삭제 실패 (${del.status}): ${await del.text()}`)
  }
  console.log(`옛 ${source} 문서 ${stale.length}건 삭제: ${stale.map((s) => s.ref).join(', ')}`)
  return stale.length
}
