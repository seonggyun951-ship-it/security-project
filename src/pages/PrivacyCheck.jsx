import { useState } from 'react'

/* ─── Mock Breach Database ───────────────────────── */
const MOCK_DB = [
  {
    name: 'Facebook',
    icon: '📘',
    date: '2019-04-03',
    count: '5억 3,300만',
    dataTypes: ['이메일', '전화번호', '이름', '생년월일', '위치 정보'],
    severity: 'critical',
    desc: '전 세계 Facebook 사용자 5.33억 명의 개인정보가 해커 포럼에 공개되었습니다.',
  },
  {
    name: 'LinkedIn',
    icon: '💼',
    date: '2021-06-29',
    count: '7억',
    dataTypes: ['이메일', '비밀번호(해시)', '이름', '직업 정보', '전화번호'],
    severity: 'high',
    desc: '스크래핑으로 LinkedIn 사용자 7억 건 데이터가 유출되었습니다.',
  },
  {
    name: 'Adobe Creative Cloud',
    icon: '🎨',
    date: '2019-10-23',
    count: '1억 5,300만',
    dataTypes: ['이메일', '비밀번호(암호화)', '아이디', '결제 관련 정보'],
    severity: 'high',
    desc: '보안 설정 오류로 Adobe Creative Cloud 데이터베이스가 일시적으로 공개 노출되었습니다.',
  },
  {
    name: 'Twitter / X',
    icon: '🐦',
    date: '2022-12-24',
    count: '4억',
    dataTypes: ['이메일', '전화번호', '아이디', '팔로워 수'],
    severity: 'high',
    desc: 'API 취약점으로 Twitter 4억 명의 이메일-전화번호 쌍이 수집, 유출되었습니다.',
  },
  {
    name: 'Canva',
    icon: '🖌️',
    date: '2019-05-24',
    count: '1억 3,900만',
    dataTypes: ['이메일', '아이디', '이름', '비밀번호(bcrypt)'],
    severity: 'medium',
    desc: '해커가 Canva 서버에 침입해 사용자 정보를 탈취했습니다.',
  },
]

const SEV_COLORS = {
  critical: { color: '#9333ea', bg: 'rgba(147,51,234,0.08)', label: '치명적' },
  high:     { color: '#ef4444', bg: 'rgba(239,68,68,0.08)',  label: '높음' },
  medium:   { color: '#f59e0b', bg: 'rgba(245,158,11,0.08)', label: '중간' },
}

function pickBreaches(email) {
  const lower = email.toLowerCase()
  const seed  = [...lower].reduce((acc, c) => acc + c.charCodeAt(0), 0)
  // Always pick 2–3 breaches deterministically from the mock db
  const idx1 = seed % MOCK_DB.length
  const idx2 = (seed + 2) % MOCK_DB.length
  const idx3 = (seed + 4) % MOCK_DB.length
  const picked = [MOCK_DB[idx1], MOCK_DB[idx2]]
  if (seed % 3 !== 0) picked.push(MOCK_DB[idx3])
  // deduplicate
  return [...new Map(picked.map(b => [b.name, b])).values()]
}

function maskEmail(email) {
  const [local, domain] = email.split('@')
  if (!domain) return email
  const masked = local.length > 2 ? local[0] + '*'.repeat(local.length - 2) + local[local.length - 1] : local[0] + '*'
  return `${masked}@${domain}`
}

export default function PrivacyCheck() {
  const [email, setEmail]     = useState('')
  const [result, setResult]   = useState(null)
  const [loading, setLoading] = useState(false)

  const check = () => {
    if (!email.trim()) return
    setLoading(true)
    setResult(null)
    // Simulate API delay
    setTimeout(() => {
      setResult({ email: email.trim(), breaches: pickBreaches(email.trim()) })
      setLoading(false)
    }, 900)
  }

  const riskScore = result ? Math.min(result.breaches.reduce((s, b) => {
    return s + (b.severity === 'critical' ? 40 : b.severity === 'high' ? 25 : 15)
  }, 0), 100) : 0

  const riskColor = riskScore >= 70 ? '#ef4444' : riskScore >= 40 ? '#f59e0b' : '#10b981'
  const riskLabel = riskScore >= 70 ? '고위험' : riskScore >= 40 ? '주의' : '안전'

  return (
    <div className="pc-page">
      <h2 className="pc-title">🔒 개인정보 유출 체크</h2>
      <p className="pc-sub">이메일 주소가 알려진 데이터 유출 사고에 포함되었는지 확인합니다.</p>

      <div className="pc-demo-banner">
        ⚠️ 현재 데모 모드 — 실제 API 연동 전 Mock 데이터로 동작합니다.
      </div>

      <div className="pc-input-row">
        <input
          className="pc-input"
          type="email"
          value={email}
          onChange={e => setEmail(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && check()}
          placeholder="example@email.com"
          autoComplete="off"
        />
        <button className="pc-btn" onClick={check} disabled={!email.trim() || loading}>
          {loading ? '조회 중...' : '조회하기'}
        </button>
      </div>

      {loading && (
        <div className="pc-loading">
          <div className="pc-spinner" />
          <span>데이터베이스 조회 중...</span>
        </div>
      )}

      {result && !loading && (
        <div className="pc-results">
          {/* Risk gauge */}
          <div className="pc-risk-card">
            <div className="pc-risk-email">{maskEmail(result.email)}</div>
            <div className="pc-risk-row">
              <div className="pc-risk-gauge">
                <svg viewBox="0 0 120 70" width="120" height="70">
                  <path d="M10 60 A 50 50 0 0 1 110 60" fill="none" stroke="#334155" strokeWidth="12" strokeLinecap="round" />
                  <path
                    d="M10 60 A 50 50 0 0 1 110 60"
                    fill="none"
                    stroke={riskColor}
                    strokeWidth="12"
                    strokeLinecap="round"
                    strokeDasharray={`${riskScore * 1.57} 157`}
                  />
                  <text x="60" y="56" textAnchor="middle" fontSize="18" fontWeight="800" fill={riskColor}>{riskScore}</text>
                  <text x="60" y="68" textAnchor="middle" fontSize="9" fill="#64748b">/ 100</text>
                </svg>
              </div>
              <div className="pc-risk-info">
                <div className="pc-risk-label" style={{ color: riskColor }}>{riskLabel}</div>
                <div className="pc-risk-sub">{result.breaches.length}개 데이터 침해 발견</div>
                <div className="pc-risk-desc">
                  {riskScore >= 70
                    ? '개인정보가 여러 유출 사고에 노출되었습니다. 모든 서비스의 비밀번호를 즉시 변경하세요.'
                    : riskScore >= 40
                    ? '일부 서비스에서 개인정보가 유출되었습니다. 해당 서비스 비밀번호를 변경하세요.'
                    : '데이터 유출이 감지되지 않았습니다.'}
                </div>
              </div>
            </div>
          </div>

          {/* Breach list */}
          <p className="pc-section-label">유출 이력</p>
          <div className="pc-breaches">
            {result.breaches.map((b, i) => {
              const cfg = SEV_COLORS[b.severity] || SEV_COLORS.medium
              return (
                <div key={i} className="pc-breach" style={{ borderLeft: `4px solid ${cfg.color}`, background: cfg.bg }}>
                  <div className="pc-breach-header">
                    <span className="pc-breach-icon">{b.icon}</span>
                    <div className="pc-breach-info">
                      <div className="pc-breach-name">{b.name}</div>
                      <div className="pc-breach-meta">{b.date} · 피해 {b.count}명</div>
                    </div>
                    <span className="pc-breach-sev" style={{ background: cfg.color }}>{cfg.label}</span>
                  </div>
                  <div className="pc-breach-desc">{b.desc}</div>
                  <div className="pc-data-types">
                    {b.dataTypes.map(d => <span key={d} className="pc-data-chip">{d}</span>)}
                  </div>
                </div>
              )
            })}
          </div>

          {/* Recommendations */}
          <div className="pc-recommendations">
            <p className="pc-section-label">권장 조치</p>
            {[
              '모든 계정의 비밀번호를 고유하고 복잡한 값으로 변경하세요.',
              '이중 인증(2FA)을 활성화하세요.',
              '비밀번호 관리자(Password Manager) 사용을 권장합니다.',
              '유출된 서비스에서 계정 활동 내역을 확인하세요.',
            ].map((rec, i) => (
              <div key={i} className="pc-rec-item">
                <span className="pc-rec-icon">✅</span>
                <span>{rec}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
