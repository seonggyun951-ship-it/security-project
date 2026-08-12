import { useState, useEffect } from 'react'
import { callFunction } from '../lib/db'
import ErrorBanner from '../components/ErrorBanner'

// 등급 정의. 카드 순서이자 목록 분류 기준이다.
const ROLES = [
  {
    key: 'super', label: '최고 관리자', cls: 'au-role-super',
    desc: '계정 생성·삭제와 권한 변경까지 가능합니다.',
  },
  {
    key: 'admin', label: '관리자', cls: 'au-role-admin',
    desc: '신청을 승인하거나 거부할 수 있습니다.',
  },
  {
    key: 'user', label: '일반 사용자', cls: 'au-role-user',
    desc: '신청만 할 수 있습니다.',
  },
]

// 최고 관리자 전용 계정 관리 화면.
// 계정 생성/삭제와 권한 변경은 service_role이 필요해 브라우저에서 직접 못 한다.
// 모든 동작은 admin-users Edge Function을 거치고, 거기서 최고 관리자인지 다시 확인한다.
export default function AdminUsers() {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(null)
  const [busyId, setBusyId] = useState(null)

  const [form, setForm] = useState({ email: '', password: '', make_admin: false })
  const [creating, setCreating] = useState(false)
  const [openRole, setOpenRole] = useState(null)

  const fetchUsers = async () => {
    setLoading(true)
    const res = await callFunction('admin-users', { action: 'list' })
    if (res.ok) {
      setUsers(res.users || [])
      setLoadError(null)
    } else {
      setUsers([])
      setLoadError(res.error)
    }
    setLoading(false)
  }

  useEffect(() => { fetchUsers() }, [])

  const createUser = async () => {
    const email = form.email.trim()
    if (!email) return alert('이메일을 입력해주세요')
    if (form.password.length < 8) return alert('비밀번호는 8자 이상이어야 합니다')

    setCreating(true)
    const res = await callFunction('admin-users', {
      action: 'create', email, password: form.password, make_admin: form.make_admin,
    })
    setCreating(false)
    if (!res.ok) return alert('계정 생성 실패: ' + res.error)

    // 비밀번호는 어디에도 저장하지 않는다. 이 시점에만 전달할 수 있다.
    alert(`계정이 생성되었습니다.\n\n이메일: ${email}\n비밀번호: ${form.password}\n\n비밀번호는 다시 확인할 수 없으니 지금 전달해주세요.`)
    setForm({ email: '', password: '', make_admin: false })
    await fetchUsers()
  }

  const setAdmin = async (u, makeAdmin) => {
    const msg = makeAdmin
      ? `${u.email} 에게 관리자 권한을 부여할까요?\n신청 승인/거부가 가능해집니다.`
      : `${u.email} 의 관리자 권한을 회수할까요?`
    if (!confirm(msg)) return

    setBusyId(u.id)
    const res = await callFunction('admin-users', { action: 'set_admin', user_id: u.id, make_admin: makeAdmin })
    setBusyId(null)
    if (!res.ok) return alert('변경 실패: ' + res.error)
    await fetchUsers()
  }

  const removeUser = async (u) => {
    if (!confirm(`${u.email} 계정을 삭제할까요?\n되돌릴 수 없습니다.`)) return
    setBusyId(u.id)
    const res = await callFunction('admin-users', { action: 'delete', user_id: u.id })
    setBusyId(null)
    if (!res.ok) return alert('삭제 실패: ' + res.error)
    await fetchUsers()
  }

  const resetPassword = async (u) => {
    const pw = prompt(`${u.email} 의 새 비밀번호를 입력하세요 (8자 이상)`)
    if (pw === null) return
    if (pw.length < 8) return alert('비밀번호는 8자 이상이어야 합니다')

    setBusyId(u.id)
    const res = await callFunction('admin-users', { action: 'reset_password', user_id: u.id, password: pw })
    setBusyId(null)
    if (!res.ok) return alert('변경 실패: ' + res.error)
    alert(`비밀번호가 변경되었습니다.\n\n${u.email}\n${pw}\n\n다시 확인할 수 없으니 지금 전달해주세요.`)
  }

  const roleOf = (u) => {
    if (u.is_super) return ROLES.find((r) => r.key === 'super')
    if (u.is_admin) return ROLES.find((r) => r.key === 'admin')
    return ROLES.find((r) => r.key === 'user')
  }

  const grouped = ROLES.map((r) => ({ ...r, items: users.filter((u) => roleOf(u).key === r.key) }))
  const openGroup = grouped.find((g) => g.key === openRole)

  return (
    <div className="ac-page">
      <h2 className="ac-title">계정 관리</h2>
      <p className="ac-sub">계정을 만들고 관리자 권한을 부여합니다. 최고 관리자만 사용할 수 있습니다.</p>

      <ErrorBanner message={loadError} onRetry={fetchUsers} />

      <div className="ac-grid">
        <div className="ac-card ac-card-wide">
          <div className="ac-card-title">계정 만들기</div>
          <div className="ac-form-row">
            <div className="ac-field">
              <label className="ac-label">이메일</label>
              <input className="ac-input" placeholder="user@example.com" value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })} />
            </div>
            <div className="ac-field">
              <label className="ac-label">비밀번호 (8자 이상)</label>
              <input className="ac-input" type="text" placeholder="전달할 초기 비밀번호" value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })} />
            </div>
          </div>
          <div className="ac-form-row">
            <div className="ac-field">
              <label className="ac-label">
                <input type="checkbox" checked={form.make_admin} style={{ marginRight: 6 }}
                  onChange={(e) => setForm({ ...form, make_admin: e.target.checked })} />
                생성과 동시에 관리자로 지정
              </label>
            </div>
          </div>
          <button className="ac-btn" onClick={createUser} disabled={creating}>
            {creating ? '생성 중...' : '계정 만들기'}
          </button>
          <p className="ac-sub" style={{ marginTop: 10, marginBottom: 0 }}>
            비밀번호는 저장되지 않습니다. 생성 직후 한 번만 표시되니 그때 전달해주세요.
          </p>
        </div>

        <div className="ac-card ac-card-wide ac-card-muted">
          <div className="ac-card-title">계정 목록 {users.length > 0 && <span className="ac-count-badge">{users.length}</span>}</div>
          {loading && <div className="ac-empty">불러오는 중...</div>}
          {!loading && users.length === 0 && !loadError && <div className="ac-empty">계정이 없습니다.</div>}

          {!loading && users.length > 0 && (
            <div className="au-cards">
              {grouped.map((g) => (
                <button
                  key={g.key}
                  className={`au-card au-card-${g.key}`}
                  onClick={() => g.items.length > 0 && setOpenRole(g.key)}
                  disabled={g.items.length === 0}
                >
                  <span className={`au-role ${g.cls}`}>{g.label}</span>
                  <span className="au-card-count">{g.items.length}</span>
                  <span className="au-card-desc">{g.desc}</span>
                  <span className="au-card-more">{g.items.length > 0 ? '목록 보기 →' : '없음'}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {openGroup && (
        <div className="ac-datepop-backdrop" onClick={() => setOpenRole(null)}>
          <div className="ac-modal" onClick={(e) => e.stopPropagation()}>
            <div className="ac-modal-head">
              <span className="ac-modal-title">
                {openGroup.label} <b>{openGroup.items.length}</b>명
              </span>
              <button className="ac-btn ac-btn-secondary" onClick={() => setOpenRole(null)}>닫기</button>
            </div>
            <div className="ac-modal-body">
              <div className="au-list">
                {openGroup.items.map((u) => {
                  const busy = busyId === u.id
                  return (
                    <div key={u.id} className="au-row">
                      <div className="au-main">
                        <span className="au-email">{u.email}</span>
                        {u.is_self && <span className="au-self">본인</span>}
                      </div>
                      <div className="au-meta">
                        최근 로그인: {u.last_sign_in_at ? new Date(u.last_sign_in_at).toLocaleString('ko-KR') : '없음'}
                      </div>
                      {/* 최고 관리자와 본인 계정은 이 화면에서 바꿀 수 없다 (스스로 잠기는 상황 방지) */}
                      {u.is_super || u.is_self ? (
                        <div className="au-meta au-locked">
                          {u.is_self ? '본인 계정은 여기서 변경할 수 없습니다.' : '최고 관리자 계정은 변경할 수 없습니다.'}
                        </div>
                      ) : (
                        <div className="au-actions">
                          {u.is_admin ? (
                            <button className="ac-btn ac-btn-secondary" disabled={busy} onClick={() => setAdmin(u, false)}>
                              관리자 해제
                            </button>
                          ) : (
                            <button className="ac-btn" disabled={busy} onClick={() => setAdmin(u, true)}>
                              관리자로 지정
                            </button>
                          )}
                          <button className="ac-btn ac-btn-secondary" disabled={busy} onClick={() => resetPassword(u)}>
                            비밀번호 재설정
                          </button>
                          <button className="ac-btn ac-btn-secondary" disabled={busy} onClick={() => removeUser(u)}>
                            {busy ? '처리 중...' : '계정 삭제'}
                          </button>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
