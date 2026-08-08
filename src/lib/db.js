import { supabase } from './supabase'

// Supabase 조회는 에러를 흘려보내기 쉬운 구조다.
//   const { data } = await supabase.from(...)   // error를 안 받으면
//   setRows(data || [])                          // RLS 거부·네트워크 실패가 "0건"과 구분되지 않는다
// 실제로 VPC 드롭다운이 비어 보이던 문제의 원인을 찾는 데 이 패턴이 시간을 잡아먹었다.
// 조회는 전부 이 함수를 거쳐서 실패를 화면과 콘솔 양쪽에 드러낸다.
export async function fetchRows(query, context) {
  const { data, error } = await query
  if (error) {
    console.error(`[${context}] 조회 실패:`, error.message)
    return { rows: [], error: `${context}을(를) 불러오지 못했습니다: ${error.message}` }
  }
  return { rows: data || [], error: null }
}

// 쓰기(update/delete)용.
// 주의: RLS가 막은 update/delete는 에러를 내지 않고 "0건 변경"으로 돌아온다.
//       error만 확인하면 차단당했는데도 성공으로 보인다.
//       그래서 호출부에서 반드시 .select()를 붙이고, 여기서 영향받은 행 수까지 확인한다.
export async function runWrite(query, context) {
  const { data, error } = await query
  if (error) {
    console.error(`[${context}] 실패:`, error.message)
    return { ok: false, error: `${context} 실패: ${error.message}` }
  }
  if (Array.isArray(data) && data.length === 0) {
    console.error(`[${context}] 대상 0건 — 권한 없음 또는 이미 처리됨`)
    return { ok: false, error: `${context}하지 못했습니다. 권한이 없거나 이미 처리된 신청입니다.` }
  }
  return { ok: true, error: null }
}

// Edge Function 호출 공통 — 인증 헤더 부착과 비정상 응답 처리를 한 곳에서 한다.
// 기존에는 페이지마다 fetch를 따로 짜서 res.ok를 확인하지 않는 곳이 있었다.
export async function callFunction(name, body = {}) {
  const base = import.meta.env.VITE_SUPABASE_URL
  try {
    const { data: { session } } = await supabase.auth.getSession()
    if (!session) return { ok: false, error: '로그인이 필요합니다' }

    const res = await fetch(`${base}/functions/v1/${name}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${session.access_token}`,
      },
      body: JSON.stringify(body),
    })

    const text = await res.text()
    let json
    try {
      json = JSON.parse(text)
    } catch {
      // 함수가 죽어서 HTML 에러 페이지를 뱉는 경우가 있다. 원문을 남겨야 원인을 안다.
      console.error(`[${name}] JSON이 아닌 응답 (HTTP ${res.status}):`, text.slice(0, 300))
      return { ok: false, error: `${name} 응답을 해석할 수 없습니다 (HTTP ${res.status})` }
    }

    if (!res.ok || json.ok === false) {
      const msg = json.error || `HTTP ${res.status}`
      console.error(`[${name}] 실패:`, msg)
      return { ok: false, error: msg, ...json }
    }
    return json
  } catch (e) {
    console.error(`[${name}] 호출 에러:`, e)
    return { ok: false, error: String(e?.message || e) }
  }
}
