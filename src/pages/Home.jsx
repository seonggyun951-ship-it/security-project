import { useNavigate } from 'react-router-dom'

const modules = [
  { id: 'vuln', icon: '🔍', title: '취약점 스캔', desc: '시스템 및 네트워크 취약점 탐지', path: '/vuln' },
  { id: 'log', icon: '📋', title: '로그 분석', desc: '서버 로그 패턴 이상 탐지', path: '/log' },
  { id: 'privacy', icon: '🔒', title: '개인정보 유출 체크', desc: '민감 정보 노출 여부 확인', path: '/privacy' },
  { id: 'cloud', icon: '☁️', title: '클라우드 설정 점검', desc: 'AWS/GCP/Azure 보안 설정 검토', path: '/cloud' },
  { id: 'phishing', icon: '🎣', title: '피싱 URL 탐지', desc: '악성 URL 및 피싱 사이트 탐지', path: '/phishing' },
]

export default function Home() {
  const navigate = useNavigate()

  return (
    <div className="home">
      <div className="home-header">
        <h1>🛡️ Security Dashboard</h1>
        <p>보안 분석 도구 모음</p>
      </div>
      <div className="module-grid">
        {modules.map(m => (
          <div key={m.id} className="module-card" onClick={() => navigate(m.path)}>
            <div className="module-icon">{m.icon}</div>
            <div className="module-title">{m.title}</div>
            <div className="module-desc">{m.desc}</div>
            <div className="module-arrow">→</div>
          </div>
        ))}
      </div>
    </div>
  )
}
