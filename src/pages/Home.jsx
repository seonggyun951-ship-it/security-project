import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

const mainModules = [
  { id: 'cloud', icon: '☁️', title: '클라우드 설정 점검', desc: 'AWS/GCP/Azure 보안 설정 검토', path: '/cloud' },
  { id: 'aws-request', icon: '📝', title: '보안 설정 신청', desc: 'SG 규칙 · WAF 규칙 · IAM 계정 신청', path: '/aws-request' },
  { id: 'cloud-automation', icon: '✅', title: '승인함', desc: '신청 검토·승인 후 AWS 반영', path: '/cloud-automation' },
  { id: 'aws-status', icon: '📡', title: 'AWS 현황', desc: '설정 자동 수집 · 변경 이력 추적', path: '/aws-status' },
]

const otherModules = [
  { id: 'vuln', icon: '🔍', title: '취약점 스캔', desc: '시스템 및 네트워크 취약점 탐지', path: '/vuln' },
  { id: 'log', icon: '📋', title: '로그 분석', desc: '서버 로그 패턴 이상 탐지', path: '/log' },
  { id: 'privacy', icon: '🔒', title: '개인정보 유출 체크', desc: '민감 정보 노출 여부 확인', path: '/privacy' },
  { id: 'phishing', icon: '🎣', title: '피싱 URL 탐지', desc: '악성 URL 및 피싱 사이트 탐지', path: '/phishing' },
]

export default function Home({ onLogout }) {
  const navigate = useNavigate()
  const [showOther, setShowOther] = useState(false)

  return (
    <div className="home">
      <div className="home-header">
        <h1>🛡️ Security Dashboard</h1>
        <p>보안 분석 도구 모음</p>
        <button className="logout-btn" onClick={() => confirm('로그아웃 하시겠습니까?') && onLogout()}>로그아웃</button>
      </div>
      <div className="module-grid">
        {mainModules.map(m => (
          <div key={m.id} className="module-card" onClick={() => navigate(m.path)}>
            <div className="module-icon">{m.icon}</div>
            <div className="module-title">{m.title}</div>
            <div className="module-desc">{m.desc}</div>
            <div className="module-arrow">→</div>
          </div>
        ))}
      </div>

      <button className="other-toggle" onClick={() => setShowOther(!showOther)}>
        기타 {showOther ? '▲' : '▼'}
      </button>
      {showOther && (
        <div className="module-grid mt16">
          {otherModules.map(m => (
            <div key={m.id} className="module-card" onClick={() => navigate(m.path)}>
              <div className="module-icon">{m.icon}</div>
              <div className="module-title">{m.title}</div>
              <div className="module-desc">{m.desc}</div>
              <div className="module-arrow">→</div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
