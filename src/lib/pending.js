import { useState, useEffect } from 'react'
import { supabase } from './supabase'

// 승인 대기 건수를 사이드바 배지에 표시하기 위한 훅.
//
// 페이지를 새로고침하지 않는다. 갱신되는 것은 이 훅이 들고 있는 숫자뿐이고,
// 사이드바와 본문은 형제 컴포넌트라 작성 중이던 폼 입력은 영향을 받지 않는다.
//
// 갱신 시점: 30초마다 / 다른 창 갔다 돌아왔을 때 / 승인·거부 직후(pendingChanged)
const POLL_MS = 30000
const EVENT = 'pending-changed'

// 승인·거부 후 즉시 배지를 맞추고 싶을 때 호출한다.
export function pendingChanged() {
  window.dispatchEvent(new Event(EVENT))
}

// isSuper: 최고 관리자만 awaiting_super(1차 승인된 삭제)를 처리할 수 있으므로 그때만 함께 센다.
// 일반 관리자에게는 자기가 처리할 수 없는 건이 배지에 남으면 안 된다.
export function usePendingCounts(enabled, isSuper = false) {
  const [counts, setCounts] = useState({ aws: 0, gcp: 0 })

  useEffect(() => {
    if (!enabled) return
    let alive = true
    const statuses = isSuper ? ['pending', 'awaiting_super'] : ['pending']

    const load = async () => {
      const [aws, gcp] = await Promise.all([
        supabase.from('aws_requests').select('id', { count: 'exact', head: true }).in('status', statuses),
        supabase.from('gcp_requests').select('id', { count: 'exact', head: true }).in('status', statuses),
      ])
      if (!alive) return
      if (aws.error) console.error('대기 건수 조회 실패(AWS):', aws.error.message)
      if (gcp.error) console.error('대기 건수 조회 실패(GCP):', gcp.error.message)
      setCounts({ aws: aws.count || 0, gcp: gcp.count || 0 })
    }

    load()
    const timer = setInterval(load, POLL_MS)
    // 탭을 다시 열었을 때는 즉시 맞춘다 (30초를 기다리지 않도록)
    const onFocus = () => load()
    window.addEventListener('focus', onFocus)
    window.addEventListener(EVENT, load)

    return () => {
      alive = false
      clearInterval(timer)
      window.removeEventListener('focus', onFocus)
      window.removeEventListener(EVENT, load)
    }
  }, [enabled, isSuper])

  return counts
}
