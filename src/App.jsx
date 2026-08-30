import { useState, useEffect } from 'react'
import { HashRouter, Routes, Route } from 'react-router-dom'
import './index.css'
import { supabase } from './lib/supabase'
import Sidebar from './components/Sidebar'
import RequesterShell from './components/RequesterShell'
import Login from './pages/Login'
import Home from './pages/Home'
import VulnScan from './pages/VulnScan'
import LogAnalysis from './pages/LogAnalysis'
import PrivacyCheck from './pages/PrivacyCheck'
import CloudCheck from './pages/CloudCheck'
import CloudAutomation from './pages/CloudAutomation'
import ApprovalHistory from './pages/ApprovalHistory'
import ScanFindings from './pages/ScanFindings'
import ScanHistory from './pages/ScanHistory'
import SecurityOverview from './pages/SecurityOverview'
import AwsRequest from './pages/AwsRequest'
import AwsStatus from './pages/AwsStatus'
import PhishingDetect from './pages/PhishingDetect'
import GcpRequest from './pages/GcpRequest'
import GcpApproval from './pages/GcpApproval'
import InfraRequest from './pages/InfraRequest'
import RequesterHome from './pages/RequesterHome'
import AdminUsers from './pages/AdminUsers'
import { useIsAdmin, useIsSuperAdmin } from './lib/auth'

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

// 최고 관리자 전용 라우트. 실제 차단은 admin-users 함수가 하고, 이건 화면상 안내용.
function SuperAdminRoute({ children }) {
  const isSuper = useIsSuperAdmin()
  if (isSuper === null) return <div className="ac-page"><div className="ac-empty">권한 확인 중...</div></div>
  if (!isSuper) {
    return (
      <div className="ac-page">
        <h2 className="ac-title">접근 권한 없음</h2>
        <p className="ac-sub">이 페이지는 최고 관리자만 사용할 수 있습니다.</p>
      </div>
    )
  }
  return children
}

// 시작 화면 분기 — 관리자는 전체 현황 대시보드, 신청자는 신청 종류를 고르는 화면.
// 대시보드는 전체 신청 통계와 리소스 현황을 담고 있어 신청자에게는 노출하지 않는다.
function RootPage() {
  const isAdmin = useIsAdmin()
  if (isAdmin === null) return <div className="ac-page"><div className="ac-empty">불러오는 중...</div></div>
  return isAdmin ? <Home /> : <RequesterHome />
}

// 관리자와 신청자는 하는 일이 반대라 껍데기를 나눈다.
//   관리자 — 여러 화면을 오가며 훑는다 → 메뉴가 늘 보이는 사이드바
//   신청자 — 화면 2~3개에서 쓴다     → 상단 탭 + 좁은 본문
// 권한 확인 중에는 사이드바를 보여준다(관리자가 대부분의 시간을 쓰는 쪽).
function Shell({ children, onLogout, email }) {
  const isAdmin = useIsAdmin()

  if (isAdmin === false) {
    return <RequesterShell onLogout={onLogout} email={email}>{children}</RequesterShell>
  }
  return (
    <div className="shell">
      <Sidebar onLogout={onLogout} />
      <main className="shell-main">{children}</main>
    </div>
  )
}

export default function App() {
  const [session, setSession] = useState(undefined)

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => setSession(data.session))
    const { data: listener } = supabase.auth.onAuthStateChange((_event, s) => setSession(s))
    return () => listener.subscription.unsubscribe()
  }, [])

  // 주소를 홈으로 되돌린 뒤 로그아웃한다.
  // 그러지 않으면 해시에 남은 페이지가 다음 로그인 때 그대로 다시 열린다.
  const logout = async () => {
    window.location.hash = '#/'
    await supabase.auth.signOut()
  }

  if (session === undefined) return null
  if (!session) return <Login />

  return (
    <HashRouter>
      <Shell onLogout={logout} email={session.user?.email}>
        <Routes>
            <Route path="/" element={<RootPage />} />
            <Route path="/vuln" element={<VulnScan />} />
            <Route path="/log" element={<LogAnalysis />} />
            <Route path="/privacy" element={<PrivacyCheck />} />
            <Route path="/cloud" element={<CloudCheck />} />
            <Route path="/request/sg" element={<AwsRequest resourceType="security_group" />} />
            <Route path="/request/waf" element={<AwsRequest resourceType="waf_web_acl" />} />
            <Route path="/request/iam" element={<AwsRequest resourceType="iam_user" />} />
            <Route path="/request/nacl" element={<AwsRequest resourceType="network_acl" />} />
            <Route path="/request/infra-network" element={<InfraRequest mode="network" />} />
            <Route path="/request/infra-compute" element={<InfraRequest mode="compute" />} />
            <Route path="/cloud-automation" element={<AdminRoute><CloudAutomation /></AdminRoute>} />
            <Route path="/approval-history" element={<AdminRoute><ApprovalHistory /></AdminRoute>} />
            <Route path="/aws-status" element={<AdminRoute><AwsStatus /></AdminRoute>} />
            <Route path="/security" element={<AdminRoute><SecurityOverview /></AdminRoute>} />
            <Route path="/scan" element={<ScanFindings />} />
            {/* scan_runs는 RLS가 관리자만 읽게 한다 — 화면도 같이 막는다 */}
            <Route path="/scan-history" element={<AdminRoute><ScanHistory /></AdminRoute>} />
            <Route path="/admin/users" element={<SuperAdminRoute><AdminUsers /></SuperAdminRoute>} />
            <Route path="/phishing" element={<PhishingDetect />} />
            <Route path="/gcp/firewall" element={<GcpRequest resourceType="firewall_rule" />} />
            <Route path="/gcp/armor" element={<GcpRequest resourceType="cloud_armor" />} />
            <Route path="/gcp/iam" element={<GcpRequest resourceType="service_account" />} />
            <Route path="/gcp/approval" element={<AdminRoute><GcpApproval /></AdminRoute>} />
        </Routes>
      </Shell>
    </HashRouter>
  )
}
