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

// 승인/거부 알림에 붙일 처리자 표시.
// 관리자가 여러 명이 될 수 있으므로 누가 처리했는지 남긴다.
// 거부 알림에 '승인자'라고 적히면 어색하므로 label로 구분한다.
// 알림 문구를 만들다 실패해도 본 기능이 막히면 안 되므로 빈 문자열로 넘어간다.
export async function approverLine(label = '승인자') {
  try {
    const { data: { session } } = await supabase.auth.getSession()
    const email = session?.user?.email
    return email ? `\n${label}: ${email}` : ''
  } catch {
    return ''
  }
}

// 현재 로그인한 사용자 id. 없으면 null.
// '내 신청 현황'을 본인 것으로 거르는 데 쓴다.
// 관리자는 RLS상 전체 신청이 보이므로 프론트에서도 걸러야 남의 신청이 섞이지 않는다.
export async function currentUserId() {
  const { data: { session } } = await supabase.auth.getSession()
  return session?.user?.id || null
}

const NOT_ADMIN = { isAdmin: false, isSuper: false }

async function fetchAdminInfo() {
  // getUser()는 서버에 한 번 더 다녀오지만, 여기서는 user id만 있으면 된다.
  // getSession()은 로컬 저장소에서 읽어 네트워크 호출이 없다.
  const { data: { session } } = await supabase.auth.getSession()
  const user = session?.user
  if (!user) return NOT_ADMIN
  const { data, error } = await supabase
    .from('admins').select('user_id, is_super').eq('user_id', user.id).maybeSingle()
  if (error) {
    console.error('관리자 확인 실패:', error.message)
    return NOT_ADMIN
  }
  return { isAdmin: !!data, isSuper: !!data?.is_super }
}

// 로그인/로그아웃 시 캐시를 버린다. 계정이 바뀌었는데 이전 권한이 남으면 안 된다.
supabase.auth.onAuthStateChange(() => { adminCheck = null })

function useAdminInfo() {
  const [info, setInfo] = useState(null)

  useEffect(() => {
    let alive = true
    adminCheck ??= fetchAdminInfo()
    adminCheck.then((v) => { if (alive) setInfo(v) })
    return () => { alive = false }
  }, [])

  return info
}

// 관리자 여부. null = 확인 중, true/false = 확인 완료.
// admins 테이블은 본인 행만 select 가능하도록 RLS가 걸려 있다.
export function useIsAdmin() {
  const info = useAdminInfo()
  return info === null ? null : info.isAdmin
}

// 최고 관리자 여부. 계정 생성/삭제와 관리자 권한 변경을 할 수 있다.
// 화면 노출 판단용이고, 실제 차단은 admin-users 함수가 한다.
export function useIsSuperAdmin() {
  const info = useAdminInfo()
  return info === null ? null : info.isSuper
}
