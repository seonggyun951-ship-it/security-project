import { NavLink, useLocation } from 'react-router-dom'
import { NAV_GROUPS } from './Sidebar'

// 신청자용 껍데기.
//
// 관리자는 '훑는' 사람이라 메뉴가 늘 보이는 사이드바가 맞지만,
// 신청자는 '쓰는' 사람이라 화면을 2~3개만 오간다.
// 17개짜리 사이드바 대신 상단 탭으로 줄이고 본문을 가운데로 모은다.
const TABS = [
  { label: '홈', path: '/', group: null },
  { label: 'AWS 신청', path: '/request/sg', group: 'AWS 신청' },
  { label: 'GCP 신청', path: '/gcp/firewall', group: 'GCP 신청' },
  { label: '보안 점검', path: '/cloud', group: '보안 점검' },
]

const itemsOf = (label) =>
  (NAV_GROUPS.find((g) => g.label === label)?.items || []).filter((i) => !i.adminOnly && !i.superOnly)

export default function RequesterShell({ children, onLogout, email }) {
  const { pathname } = useLocation()

  // 현재 어느 탭에 속한 화면인지 — 하위 메뉴를 보여줄지 판단한다
  const active = TABS.find((t) => t.group && itemsOf(t.group).some((i) => i.path === pathname))
  const subItems = active ? itemsOf(active.group) : []

  return (
    <div className="rs">
      <header className="rs-top">
        <span className="rs-brand">Security Console</span>
        <nav className="rs-tabs">
          {TABS.map((t) => {
            const on = t.group
              ? active?.group === t.group
              : pathname === '/'
            return (
              <NavLink key={t.label} to={t.path} className={`rs-tab ${on ? 'is-active' : ''}`}>
                {t.label}
              </NavLink>
            )
          })}
        </nav>
        <span className="rs-user">{email}</span>
        <button className="rs-out" onClick={() => confirm('로그아웃 하시겠습니까?') && onLogout()}>
          로그아웃
        </button>
      </header>

      {/* 선택한 분류 안의 신청 종류 — 탭에 다 넣으면 너무 많아서 한 단계 아래로 내렸다 */}
      {subItems.length > 0 && (
        <div className="rs-sub">
          {subItems.map((i) => (
            <NavLink key={i.path} to={i.path}
              className={({ isActive }) => `rs-subtab ${isActive ? 'is-active' : ''}`}>
              {i.title}
            </NavLink>
          ))}
        </div>
      )}

      <main className="rs-main">{children}</main>
    </div>
  )
}
