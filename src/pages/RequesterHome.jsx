import { Link } from 'react-router-dom'
import { NAV_GROUPS } from '../components/Sidebar'

// 신청자(비관리자)가 로그인 후 처음 보는 화면.
// 관리자용 대시보드는 전체 신청 통계와 리소스 현황을 담고 있어 신청자에게는 보여주지 않는다.
// 메뉴 목록은 사이드바와 같은 정의(NAV_GROUPS)를 재사용해서, 신청 종류가 늘어도 따로 고칠 필요가 없다.
const SECTIONS = [
  {
    key: 'AWS 신청',
    title: 'AWS 신청하기',
    desc: 'Security Group, WAF, IAM 계정, VPC/서브넷, EC2 인스턴스를 신청합니다.',
  },
  {
    key: 'GCP 신청',
    title: 'GCP 신청하기',
    desc: 'Firewall, Cloud Armor, IAM 서비스 계정을 신청합니다.',
  },
]

export default function RequesterHome() {
  const sections = SECTIONS
    .map((s) => ({
      ...s,
      items: (NAV_GROUPS.find((g) => g.label === s.key)?.items || []).filter((i) => !i.adminOnly),
    }))
    .filter((s) => s.items.length > 0)

  return (
    <div className="ac-page">
      <h2 className="ac-title">무엇을 신청하시겠어요?</h2>
      <p className="ac-sub">신청하면 관리자 검토 후 실제 클라우드에 반영됩니다.</p>

      <div className="ac-grid">
        {sections.map((s) => (
          <div key={s.key} className="ac-card ac-card-wide">
            <div className="ac-card-title">{s.title}</div>
            <p className="ac-sub" style={{ marginBottom: 12 }}>{s.desc}</p>
            <div className="rh-links">
              {s.items.map((item) => (
                <Link key={item.path} to={item.path} className="rh-link">
                  <span className="rh-link-text">{item.title}</span>
                  <span className="rh-link-arrow">→</span>
                </Link>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
