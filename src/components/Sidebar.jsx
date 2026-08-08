import { NavLink, useLocation } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { useIsAdmin } from '../lib/auth'

// 사이드바 메뉴 — 그룹 단위로 흐름이 보이게 구성
export const NAV_GROUPS = [
  {
    label: '개요',
    items: [
      { title: '대시보드', path: '/' },
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
      { title: '관리자 승인', path: '/cloud-automation', adminOnly: true },
      { title: 'AWS 현황', path: '/aws-status' },
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
      { title: '관리자 승인', path: '/gcp/approval', adminOnly: true },
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

  // 모바일에서 메뉴 선택 후 자동으로 닫기
  useEffect(() => { setOpen(false) }, [location.pathname])

  // 관리자 전용 메뉴는 확인 완료 후 관리자에게만 노출 (확인 중에는 감춤)
  const groups = NAV_GROUPS
    .map((g) => ({ ...g, items: g.items.filter((i) => !i.adminOnly || isAdmin === true) }))
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
