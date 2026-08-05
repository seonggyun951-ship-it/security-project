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
            <Route path="/cloud-automation" element={<CloudAutomation />} />
            <Route path="/aws-status" element={<AwsStatus />} />
            <Route path="/phishing" element={<PhishingDetect />} />
            <Route path="/gcp/firewall" element={<GcpRequest resourceType="firewall_rule" />} />
            <Route path="/gcp/armor" element={<GcpRequest resourceType="cloud_armor" />} />
            <Route path="/gcp/iam" element={<GcpRequest resourceType="service_account" />} />
            <Route path="/gcp/approval" element={<GcpApproval />} />
          </Routes>
        </main>
      </div>
    </HashRouter>
  )
}
