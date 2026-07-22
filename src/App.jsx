import { useState, useEffect } from 'react'
import { HashRouter, Routes, Route, useNavigate } from 'react-router-dom'
import './index.css'
import { supabase } from './lib/supabase'
import Login from './pages/Login'
import Home from './pages/Home'
import VulnScan from './pages/VulnScan'
import LogAnalysis from './pages/LogAnalysis'
import PrivacyCheck from './pages/PrivacyCheck'
import CloudCheck from './pages/CloudCheck'
import CloudAutomation from './pages/CloudAutomation'
import PhishingDetect from './pages/PhishingDetect'

function BackButton() {
  const navigate = useNavigate()
  return (
    <button className="back-btn" onClick={() => navigate('/')}>← 홈으로</button>
  )
}

function Layout({ children }) {
  return (
    <div className="app">
      <BackButton />
      <div className="page-content">{children}</div>
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

  const logout = () => supabase.auth.signOut()

  if (session === undefined) return null
  if (!session) return <Login />

  return (
    <HashRouter>
      <Routes>
        <Route path="/" element={<div className="app"><Home onLogout={logout} /></div>} />
        <Route path="/vuln" element={<Layout><VulnScan /></Layout>} />
        <Route path="/log" element={<Layout><LogAnalysis /></Layout>} />
        <Route path="/privacy" element={<Layout><PrivacyCheck /></Layout>} />
        <Route path="/cloud" element={<Layout><CloudCheck /></Layout>} />
        <Route path="/cloud-automation" element={<Layout><CloudAutomation /></Layout>} />
        <Route path="/phishing" element={<Layout><PhishingDetect /></Layout>} />
      </Routes>
    </HashRouter>
  )
}
