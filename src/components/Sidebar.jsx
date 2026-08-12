import { NavLink, useLocation } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { useIsAdmin, useIsSuperAdmin } from '../lib/auth'
import { usePendingCounts } from '../lib/pending'

// 사이드바 메뉴 — 그룹 단위로 흐름이 보이게 구성
export const NAV_GROUPS = [
  {
    label: '개요',
    items: [
      // 같은 '/' 경로지만 보는 사람에 따라 다른 화면이 뜬다(App.jsx RootPage).
      // 관리자는 전체 현황 대시보드, 신청자는 신청 종류 선택 화면.
      { title: '대시보드', path: '/', adminOnly: true },
      { title: '홈', path: '/', requesterOnly: true },
    ],
  },
  {
    label: 'AWS 신청',
    items: [
      { title: 'Security Group', path: '/request/sg' },
      { title: 'WAF', path: '/request/waf' },
      { title: 'IAM 계정', path: '/request/iam' },
      { title: 'VPC / 서브넷', path: '/request/infra-network' },
      { title: 'EC2 인스턴스', path: '/request/infra-compute' },
    ],
  },
  {
    label: 'AWS 관리',
    items: [
      { title: '관리자 승인', path: '/cloud-automation', adminOnly: true, badge: 'aws' },
      { title: 'AWS 현황', path: '/aws-status', adminOnly: true },
    ],
  },
  {
    label: 'GCP 신청',
    items: [
      { title: 'Firewall', path: '/gcp/firewall' },
      { title: 'Cloud Armor', path: '/gcp/armor' },
      { title: 'IAM 서비스 계정', path: '/gcp/iam' },
    ],
  },
  {
    label: 'GCP 관리',
    items: [
      { title: '관리자 승인', path: '/gcp/approval', adminOnly: true, badge: 'gcp' },
    ],
  },
  {
    label: '설정',
    items: [
      { title: '계정 관리', path: '/admin/users', superOnly: true },
    ],
  },
  {
    label: '보안 점검',
    items: [
      { title: '클라우드 설정 점검', path: '/cloud' },
      { title: '취약점 스캔', path: '/vuln' },
      { title: '로그 분석', path: '/log' },
      { title: '개인정보 유출 체크', path: '/privacy' },
      { title: '피싱 URL 탐지', path: '/phishing' },
    ],
  },
]

export default function Sidebar({ onLogout }) {
  const [open, setOpen] = useState(false)
  const location = useLocation()
  const isAdmin = useIsAdmin()
  const isSuper = useIsSuperAdmin()
  // 관리자만 대기 건수를 센다. 신청자는 승인 메뉴 자체가 없다.
  const pending = usePendingCounts(isAdmin === true, isSuper === true)

  // 모바일에서 메뉴 선택 후 자동으로 닫기
  useEffect(() => { setOpen(false) }, [location.pathname])

  // 권한 확인이 끝나기 전(isAdmin === null)에는 어느 쪽 전용 메뉴도 보여주지 않는다.
  // 잠깐이라도 관리자 메뉴가 스쳐 보이거나, 메뉴가 두 번 바뀌는 걸 막기 위함.
  const visible = (item) => {
    if (item.superOnly) return isSuper === true
    if (item.adminOnly) return isAdmin === true
    if (item.requesterOnly) return isAdmin === false
    return true
  }
  const groups = NAV_GROUPS
    .map((g) => ({ ...g, items: g.items.filter(visible) }))
    .filter((g) => g.items.length > 0)

  return (
    <>
      <button className="sb-toggle" onClick={() => setOpen(true)} aria-label="메뉴 열기">☰</button>
      {open && <div className="sb-backdrop" onClick={() => setOpen(false)} />}

      <aside className={`sb ${open ? 'is-open' : ''}`}>
        <div className="sb-brand">Security Dashboard</div>

        <nav className="sb-nav">
          {groups.map((group) => (
            <div key={group.label} className="sb-group">
              <div className="sb-group-label">{group.label}</div>
              {group.items.map((item) => (
                <NavLink
                  key={item.path}
                  to={item.path}
                  end={item.path === '/'}
                  className={({ isActive }) => `sb-link ${isActive ? 'is-active' : ''}`}
                >
                  <span className="sb-link-text">{item.title}</span>
                  {item.badge && pending[item.badge] > 0 && (
                    <span className="sb-badge" title={`승인 대기 ${pending[item.badge]}건`}>
                      {pending[item.badge]}
                    </span>
                  )}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        <button className="sb-logout" onClick={() => confirm('로그아웃 하시겠습니까?') && onLogout()}>
          로그아웃
        </button>
      </aside>
    </>
  )
}
