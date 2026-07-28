import { NavLink, useLocation } from 'react-router-dom'
import { useEffect, useState } from 'react'

// 사이드바 메뉴 — 그룹 단위로 흐름이 보이게 구성
export const NAV_GROUPS = [
  {
    label: 'AWS 자동화',
    items: [
      { icon: '🏠', title: '대시보드', path: '/' },
      { icon: '📝', title: '보안 설정 신청', path: '/aws-request' },
      { icon: '✅', title: '관리자 승인', path: '/cloud-automation' },
      { icon: '📡', title: 'AWS 현황', path: '/aws-status' },
    ],
  },
  {
    label: '보안 점검',
    items: [
      { icon: '☁️', title: '클라우드 설정 점검', path: '/cloud' },
      { icon: '🔍', title: '취약점 스캔', path: '/vuln' },
      { icon: '📋', title: '로그 분석', path: '/log' },
      { icon: '🔒', title: '개인정보 유출 체크', path: '/privacy' },
      { icon: '🎣', title: '피싱 URL 탐지', path: '/phishing' },
    ],
  },
]

export default function Sidebar({ onLogout }) {
  const [open, setOpen] = useState(false)
  const location = useLocation()

  // 모바일에서 메뉴 선택 후 자동으로 닫기
  useEffect(() => { setOpen(false) }, [location.pathname])

  return (
    <>
      <button className="sb-toggle" onClick={() => setOpen(true)} aria-label="메뉴 열기">☰</button>
      {open && <div className="sb-backdrop" onClick={() => setOpen(false)} />}

      <aside className={`sb ${open ? 'is-open' : ''}`}>
        <div className="sb-brand">🛡️ Security</div>

        <nav className="sb-nav">
          {NAV_GROUPS.map((group) => (
            <div key={group.label} className="sb-group">
              <div className="sb-group-label">{group.label}</div>
              {group.items.map((item) => (
                <NavLink
                  key={item.path}
                  to={item.path}
                  end={item.path === '/'}
                  className={({ isActive }) => `sb-link ${isActive ? 'is-active' : ''}`}
                >
                  <span className="sb-link-icon">{item.icon}</span>
                  <span className="sb-link-text">{item.title}</span>
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
