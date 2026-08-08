import { useState, useEffect } from 'react'
import { HashRouter, Routes, Route } from 'react-router-dom'
import './index.css'
import { supabase } from './lib/supabase'
import Sidebar from './components/Sidebar'
import Login from './pages/Login'
import Home from './pages/Home'
import VulnScan from './pages/VulnScan'
import LogAnalysis from './pages/LogAnalysis'
import PrivacyCheck from './pages/PrivacyCheck'
import CloudCheck from './pages/CloudCheck'
import CloudAutomation from './pages/CloudAutomation'
import AwsRequest from './pages/AwsRequest'
import AwsStatus from './pages/AwsStatus'
import PhishingDetect from './pages/PhishingDetect'
import GcpRequest from './pages/GcpRequest'
import GcpApproval from './pages/GcpApproval'
import InfraRequest from './pages/InfraRequest'
import { useIsAdmin } from './lib/auth'

// 관리자 전용 라우트 — 사이드바에서 감춰도 URL을 직접 치면 들어와지므로 여기서도 막는다.
// (최종 차단은 RLS와 Edge Function이 하고, 이건 화면상 안내용)
function AdminRoute({ children }) {
  const isAdmin = useIsAdmin()
  if (isAdmin === null) return <div className="ac-page"><div className="ac-empty">권한 확인 중...</div></div>
  if (!isAdmin) {
    return (
      <div className="ac-page">
        <h2 className="ac-title">접근 권한 없음</h2>
        <p className="ac-sub">이 페이지는 관리자만 사용할 수 있습니다.</p>
      </div>
    )
  }
  return children
}

export default function App() {
  const [session, setSession] = useState(undefined)

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => setSession(data.session))
    const { data: listener } = supabase.auth.onAuthStateChange((_event, s) => setSession(s))
    return () => listener.subscription.unsubscribe()
  }, [])

  const logout = () => supabase.auth.signOut()

  if (session === undefined) return null
  if (!session) return <Login />

  return (
    <HashRouter>
      <div className="shell">
        <Sidebar onLogout={logout} />
        <main className="shell-main">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/vuln" element={<VulnScan />} />
            <Route path="/log" element={<LogAnalysis />} />
            <Route path="/privacy" element={<PrivacyCheck />} />
            <Route path="/cloud" element={<CloudCheck />} />
            <Route path="/request/sg" element={<AwsRequest resourceType="security_group" />} />
            <Route path="/request/waf" element={<AwsRequest resourceType="waf_web_acl" />} />
            <Route path="/request/iam" element={<AwsRequest resourceType="iam_user" />} />
            <Route path="/request/infra-network" element={<InfraRequest mode="network" />} />
            <Route path="/request/infra-compute" element={<InfraRequest mode="compute" />} />
            <Route path="/cloud-automation" element={<AdminRoute><CloudAutomation /></AdminRoute>} />
            <Route path="/aws-status" element={<AdminRoute><AwsStatus /></AdminRoute>} />
            <Route path="/phishing" element={<PhishingDetect />} />
            <Route path="/gcp/firewall" element={<GcpRequest resourceType="firewall_rule" />} />
            <Route path="/gcp/armor" element={<GcpRequest resourceType="cloud_armor" />} />
            <Route path="/gcp/iam" element={<GcpRequest resourceType="service_account" />} />
            <Route path="/gcp/approval" element={<AdminRoute><GcpApproval /></AdminRoute>} />
          </Routes>
        </main>
      </div>
    </HashRouter>
  )
}
