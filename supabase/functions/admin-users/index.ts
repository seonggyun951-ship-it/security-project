import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type'
}
const json = (body, status = 200) => new Response(JSON.stringify(body), {
  headers: { ...cors, 'Content-Type': 'application/json' }, status
})

// 계정 생성/삭제와 관리자 권한 부여/회수.
// 이 작업들은 service_role이 필요해서 브라우저에서 직접 할 수 없다(키가 노출되므로).
// 호출자가 최고 관리자인지 확인한 뒤에만 수행한다.
serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })
  try {
    const authHeader = req.headers.get('Authorization') || ''
    const token = authHeader.replace('Bearer ', '')
    const userClient = createClient(Deno.env.get('SUPABASE_URL'), Deno.env.get('SUPABASE_ANON_KEY'), {
      global: { headers: { Authorization: authHeader } }
    })
    const { data: { user }, error: authError } = await userClient.auth.getUser(token)
    if (authError || !user) return json({ ok: false, error: '로그인이 필요합니다' }, 401)

    const admin = createClient(Deno.env.get('SUPABASE_URL'), Deno.env.get('SUPABASE_SERVICE_ROLE_KEY'))

    const { data: me, error: meErr } = await admin
      .from('admins').select('user_id, is_super').eq('user_id', user.id).maybeSingle()
    if (meErr) throw meErr
    if (!me?.is_super) return json({ ok: false, error: '최고 관리자만 사용할 수 있습니다' }, 403)

    const { action, email, password, user_id, make_admin } = await req.json()

    // ---- 목록 ----
    if (action === 'list') {
      const { data: list, error } = await admin.auth.admin.listUsers({ page: 1, perPage: 200 })
      if (error) throw error
      const { data: admins, error: aErr } = await admin.from('admins').select('user_id, is_super')
      if (aErr) throw aErr
      const byId = new Map((admins || []).map((a) => [a.user_id, a]))

      const users = list.users.map((u) => ({
        id: u.id,
        email: u.email,
        created_at: u.created_at,
        last_sign_in_at: u.last_sign_in_at,
        is_admin: byId.has(u.id),
        is_super: !!byId.get(u.id)?.is_super,
        is_self: u.id === user.id,
      })).sort((a, b) => (a.email || '').localeCompare(b.email || ''))

      return json({ ok: true, users })
    }

    // ---- 계정 생성 ----
    if (action === 'create') {
      if (!email || !password) return json({ ok: false, error: '이메일과 비밀번호가 필요합니다' }, 400)
      if (password.length < 8) return json({ ok: false, error: '비밀번호는 8자 이상이어야 합니다' }, 400)

      const { data, error } = await admin.auth.admin.createUser({
        email, password, email_confirm: true,  // 메일 서버가 없으므로 바로 사용 가능하게 만든다
      })
      if (error) return json({ ok: false, error: error.message }, 400)

      // 생성과 동시에 관리자로 지정할 수 있다. 단 최고 관리자는 여기서 만들 수 없다.
      if (make_admin) {
        const { error: gErr } = await admin.from('admins')
          .insert({ user_id: data.user.id, email: data.user.email, is_super: false })
        if (gErr) return json({ ok: false, error: '계정은 만들었지만 관리자 지정 실패: ' + gErr.message }, 500)
      }
      return json({ ok: true, user: { id: data.user.id, email: data.user.email } })
    }

    // ---- 관리자 권한 부여/회수 ----
    if (action === 'set_admin') {
      if (!user_id) return json({ ok: false, error: 'user_id가 필요합니다' }, 400)
      if (user_id === user.id) return json({ ok: false, error: '본인 권한은 변경할 수 없습니다' }, 400)

      // 다른 최고 관리자는 이 화면에서 건드리지 못하게 한다(서로 강등시키는 상황 방지).
      const { data: target } = await admin.from('admins').select('is_super').eq('user_id', user_id).maybeSingle()
      if (target?.is_super) return json({ ok: false, error: '다른 최고 관리자의 권한은 변경할 수 없습니다' }, 400)

      if (make_admin) {
        const { data: u } = await admin.auth.admin.getUserById(user_id)
        const { error } = await admin.from('admins')
          .upsert({ user_id, email: u?.user?.email || null, is_super: false }, { onConflict: 'user_id' })
        if (error) throw error
      } else {
        const { error } = await admin.from('admins').delete().eq('user_id', user_id)
        if (error) throw error
      }
      return json({ ok: true })
    }

    // ---- 계정 삭제 ----
    if (action === 'delete') {
      if (!user_id) return json({ ok: false, error: 'user_id가 필요합니다' }, 400)
      if (user_id === user.id) return json({ ok: false, error: '본인 계정은 삭제할 수 없습니다' }, 400)

      const { data: target } = await admin.from('admins').select('is_super').eq('user_id', user_id).maybeSingle()
      if (target?.is_super) return json({ ok: false, error: '최고 관리자 계정은 삭제할 수 없습니다' }, 400)

      // admins 행은 user_id에 on delete cascade가 걸려 있어 함께 정리된다.
      const { error } = await admin.auth.admin.deleteUser(user_id)
      if (error) return json({ ok: false, error: error.message }, 400)
      return json({ ok: true })
    }

    // ---- 비밀번호 재설정 ----
    if (action === 'reset_password') {
      if (!user_id || !password) return json({ ok: false, error: 'user_id와 비밀번호가 필요합니다' }, 400)
      if (password.length < 8) return json({ ok: false, error: '비밀번호는 8자 이상이어야 합니다' }, 400)

      const { error } = await admin.auth.admin.updateUserById(user_id, { password })
      if (error) return json({ ok: false, error: error.message }, 400)
      return json({ ok: true })
    }

    return json({ ok: false, error: '알 수 없는 action: ' + action }, 400)
  } catch (e) {
    console.error('admin-users error:', e)
    return json({ ok: false, error: String(e) }, 500)
  }
})
