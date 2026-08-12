import { useState, useEffect } from 'react'
import { supabase } from './supabase'

// 신청 insert 시 RLS가 requester_id = auth.uid()를 요구한다.
// 컴포넌트 state의 user는 로딩 전일 수 있으므로, 제출 시점에 직접 확인한다.
export async function requireUser() {
  const { data, error } = await supabase.auth.getUser()
  if (error || !data?.user) throw new Error('로그인이 만료되었습니다. 다시 로그인해주세요.')
  return data.user
}

// useIsAdmin은 사이드바·라우트 가드·시작 화면에서 동시에 호출된다.
// 각자 조회하면 같은 쿼리가 여러 번 나가고 메뉴가 늦게 뜨므로, 진행 중인 조회를 공유한다.
let adminCheck = null

async function fetchIsAdmin() {
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return false
  const { data, error } = await supabase
    .from('admins').select('user_id').eq('user_id', user.id).maybeSingle()
  if (error) {
    console.error('관리자 확인 실패:', error.message)
    return false
  }
  return !!data
}

// 로그인/로그아웃 시 캐시를 버린다. 계정이 바뀌었는데 이전 권한이 남으면 안 된다.
supabase.auth.onAuthStateChange(() => { adminCheck = null })

// 관리자 여부. null = 확인 중, true/false = 확인 완료.
// admins 테이블은 본인 행만 select 가능하도록 RLS가 걸려 있다.
export function useIsAdmin() {
  const [isAdmin, setIsAdmin] = useState(null)

  useEffect(() => {
    let alive = true
    adminCheck ??= fetchIsAdmin()
    adminCheck.then((v) => { if (alive) setIsAdmin(v) })
    return () => { alive = false }
  }, [])

  return isAdmin
}
