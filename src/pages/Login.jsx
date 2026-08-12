import { useState } from 'react'
import { supabase } from '../lib/supabase'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const login = async () => {
    setError('')
    setLoading(true)
    const { error } = await supabase.auth.signInWithPassword({ email: email.trim(), password })
    if (error) {
      setError('아이디 또는 비밀번호가 틀렸습니다.')
      setLoading(false)
      return
    }
    // HashRouter는 URL 해시를 그대로 들고 있어서, 로그아웃 전에 보던 페이지가 그대로 다시 열린다.
    // 계정이 바뀌면 권한도 달라지므로(관리자 페이지에 있다가 신청자로 로그인하는 등) 항상 홈에서 시작한다.
    window.location.hash = '#/'
    setLoading(false)
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <h1 className="login-title">Security Dashboard</h1>
        <input
          className="login-input"
          type="email"
          placeholder="이메일"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && login()}
          autoComplete="off"
        />
        <input
          className="login-input"
          type="password"
          placeholder="비밀번호"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && login()}
        />
        {error && <div className="login-error">{error}</div>}
        <button className="login-btn" onClick={login} disabled={loading || !email.trim() || !password}>
          {loading ? '로그인 중...' : '로그인'}
        </button>
      </div>
    </div>
  )
}
