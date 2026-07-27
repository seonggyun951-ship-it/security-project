import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'
import {
  RESOURCE_META, WAF_MANAGED_RULE_GROUPS, WAF_FIELDS, WAF_POSITIONS, IAM_READONLY_POLICIES, ReqCard,
  emptyRule, parsePortRange, normalizeCidr,
  emptyWafRule,
} from '../lib/aws'

// 리소스 타입 선택 탭
const RESOURCE_TABS = [
  { key: 'security_group', label: '🛡️ Security Group' },
  { key: 'waf_web_acl', label: '🧱 WAF Web ACL' },
  { key: 'iam_user', label: '🔑 IAM 읽기전용 계정' },
]

function SgForm({ sgOptions, onSubmit, submitting }) {
  const [action, setAction] = useState('add_rules') // 'add_rules' | 'create_sg'
  const [form, setForm] = useState({ sg_id: '', sg_name: '', vpc_id: '', description: '', reason: '' })
  const [rules, setRules] = useState([emptyRule()])

  const updateRule = (i, patch) => setRules((prev) => prev.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  const addRule = () => setRules((prev) => [...prev, emptyRule()])
  const removeRule = (i) => setRules((prev) => prev.filter((_, idx) => idx !== i))

  const reset = () => {
    setForm({ sg_id: '', sg_name: '', vpc_id: '', description: '', reason: '' })
    setRules([emptyRule()])
  }

  const submit = async () => {
    if (action === 'add_rules' && !form.sg_id.trim()) return alert('SG ID는 필수입니다')
    if (action === 'create_sg' && (!form.sg_name.trim() || !form.vpc_id.trim())) return alert('SG 이름과 VPC ID는 필수입니다')
    const cleanRules = rules.filter((r) => r.cidr.trim()).map((r) => ({
      direction: r.direction, protocol: r.protocol, ...parsePortRange(r.port), cidr: normalizeCidr(r.cidr),
    }))
    if (cleanRules.length === 0) return alert('규칙을 최소 1개 이상 입력해주세요 (CIDR 필수)')

    const ok = await onSubmit({
      resource_type: 'security_group',
      action,
      title: action === 'create_sg' ? form.sg_name.trim() : (form.sg_id.trim()),
      target_id: action === 'add_rules' ? form.sg_id.trim() : null,
      payload: {
        sg_name: form.sg_name.trim() || null,
        vpc_id: action === 'create_sg' ? form.vpc_id.trim() : null,
        description: form.description.trim() || null,
        rules: cleanRules,
      },
      reason: form.reason.trim() || null,
    })
    if (ok) reset()
  }

  return (
    <>
      <div className="ac-filter-row">
        <button className={`ac-filter-btn ${action === 'add_rules' ? 'active' : ''}`} onClick={() => setAction('add_rules')}>기존 SG에 규칙 추가</button>
        <button className={`ac-filter-btn ${action === 'create_sg' ? 'active' : ''}`} onClick={() => setAction('create_sg')}>신규 SG 생성</button>
      </div>

      {action === 'add_rules' ? (
        <div className="ac-form-row">
          <div className="ac-field">
            <label className="ac-label">SG ID</label>
            <input className="ac-input" list="sg-options" placeholder="예: sg-0123abcd" value={form.sg_id} onChange={(e) => setForm({ ...form, sg_id: e.target.value })} />
            <datalist id="sg-options">
              {sgOptions.map((s) => <option key={s.resource_id} value={s.resource_id}>{s.resource_name}</option>)}
            </datalist>
          </div>
        </div>
      ) : (
        <>
          <div className="ac-form-row">
            <div className="ac-field">
              <label className="ac-label">새 SG 이름</label>
              <input className="ac-input" value={form.sg_name} onChange={(e) => setForm({ ...form, sg_name: e.target.value })} />
            </div>
            <div className="ac-field">
              <label className="ac-label">VPC ID</label>
              <input className="ac-input" placeholder="예: vpc-0123abcd" value={form.vpc_id} onChange={(e) => setForm({ ...form, vpc_id: e.target.value })} />
            </div>
          </div>
          <div className="ac-form-row">
            <div className="ac-field">
              <label className="ac-label">설명 (선택)</label>
              <input className="ac-input" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </div>
          </div>
        </>
      )}

      <div className="ac-card-title" style={{ fontSize: 13, marginTop: 16 }}>규칙</div>
      <div className="ac-rule-table">
        <div className="ac-rule-row ac-rule-head">
          <span>방향</span><span>프로토콜</span><span>포트</span><span>CIDR</span><span></span>
        </div>
        {rules.map((r, i) => (
          <div key={i} className="ac-rule-row">
            <select className="ac-input" value={r.direction} onChange={(e) => updateRule(i, { direction: e.target.value })}>
              <option value="ingress">인바운드</option>
              <option value="egress">아웃바운드</option>
            </select>
            <select className="ac-input" value={r.protocol} onChange={(e) => updateRule(i, { protocol: e.target.value })}>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
              <option value="-1">전체</option>
            </select>
            <input className="ac-input" placeholder="22 또는 1000-2000" value={r.port} onChange={(e) => updateRule(i, { port: e.target.value })} />
            <input className="ac-input" placeholder="1.2.3.4/32" value={r.cidr} onChange={(e) => updateRule(i, { cidr: e.target.value })} />
            {rules.length > 1
              ? <button className="ac-btn ac-btn-secondary ac-rule-del" onClick={() => removeRule(i)}>삭제</button>
              : <span />}
          </div>
        ))}
      </div>
      <button className="ac-btn ac-btn-secondary" onClick={addRule} style={{ marginTop: 8, marginBottom: 16 }}>+ 규칙 추가</button>

      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">신청 사유</label>
          <input className="ac-input" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} />
        </div>
      </div>
      <button className="ac-btn" onClick={submit} disabled={submitting}>{submitting ? '신청 중...' : '신청하기'}</button>
    </>
  )
}

function WafForm({ aclOptions, onSubmit, submitting }) {
  const [action, setAction] = useState('create_acl') // 'create_acl' | 'add_waf_rules'
  const [form, setForm] = useState({ acl_name: '', default_action: 'allow', target_id: '', reason: '' })
  const [groups, setGroups] = useState([]) // 선택된 관리형 규칙 그룹 name[]
  const [wafRules, setWafRules] = useState([emptyWafRule()])

  const toggleGroup = (name) => setGroups((prev) => prev.includes(name) ? prev.filter((n) => n !== name) : [...prev, name])
  const updateWafRule = (i, patch) => setWafRules((prev) => prev.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  const addWafRule = () => setWafRules((prev) => [...prev, emptyWafRule()])
  const removeWafRule = (i) => setWafRules((prev) => prev.filter((_, idx) => idx !== i))

  const reset = () => {
    setForm({ acl_name: '', default_action: 'allow', target_id: '', reason: '' })
    setGroups([])
    setWafRules([emptyWafRule()])
  }

  const submit = async () => {
    if (action === 'create_acl') {
      if (!form.acl_name.trim()) return alert('Web ACL 이름은 필수입니다')
      if (groups.length === 0) return alert('관리형 규칙을 최소 1개 이상 선택해주세요')
      const ok = await onSubmit({
        resource_type: 'waf_web_acl', action: 'create_acl',
        title: form.acl_name.trim(), target_id: null,
        payload: { acl_name: form.acl_name.trim(), default_action: form.default_action, managed_rule_groups: groups },
        reason: form.reason.trim() || null,
      })
      if (ok) reset()
      return
    }
    // add_waf_rules
    if (!form.target_id.trim()) return alert('대상 Web ACL을 선택해주세요')
    const selected = aclOptions.find((a) => a.resource_id === form.target_id.trim())
    const clean = wafRules.map((r) => {
      const base = { name: r.name.trim() }
      if (r.type === 'rate_limit') return { ...base, type: 'rate_limit', limit: Number(r.limit) || 2000 }
      if (r.type === 'string_match') return {
        ...base, type: 'string_match', field: r.field, position: r.position,
        header_name: r.field === 'header' ? r.header_name.trim() : null, pattern: r.pattern,
      }
      if (r.type === 'regex_match') return {
        ...base, type: 'regex_match', field: r.field,
        header_name: r.field === 'header' ? r.header_name.trim() : null, pattern: r.pattern,
      }
      const cidrs = (r.cidrs || '').split(',').map((c) => normalizeCidr(c)).filter(Boolean)
      return { ...base, type: 'ip_block', cidrs }
    }).filter((r) => r.name)
    if (clean.length === 0) return alert('규칙 이름을 최소 1개 이상 입력해주세요')
    if (clean.some((r) => r.type === 'ip_block' && r.cidrs.length === 0)) return alert('IP 차단 규칙은 CIDR을 최소 1개 입력해야 합니다')
    if (clean.some((r) => (r.type === 'string_match' || r.type === 'regex_match') && !(r.pattern || '').trim())) return alert('패턴 매칭 규칙은 패턴을 입력해야 합니다')
    if (clean.some((r) => (r.type === 'string_match' || r.type === 'regex_match') && r.field === 'header' && !r.header_name)) return alert('헤더 검사 규칙은 헤더 이름을 입력해야 합니다')

    const ok = await onSubmit({
      resource_type: 'waf_web_acl', action: 'add_waf_rules',
      title: selected?.resource_name || form.target_id.trim(),
      target_id: form.target_id.trim(),
      payload: { web_acl_name: selected?.resource_name || null, rules: clean },
      reason: form.reason.trim() || null,
    })
    if (ok) reset()
  }

  return (
    <>
      <div className="ac-filter-row">
        <button className={`ac-filter-btn ${action === 'create_acl' ? 'active' : ''}`} onClick={() => setAction('create_acl')}>신규 Web ACL 생성</button>
        <button className={`ac-filter-btn ${action === 'add_waf_rules' ? 'active' : ''}`} onClick={() => setAction('add_waf_rules')}>기존 Web ACL에 규칙 추가</button>
      </div>

      {action === 'create_acl' ? (
        <>
          <div className="ac-form-row">
            <div className="ac-field">
              <label className="ac-label">Web ACL 이름</label>
              <input className="ac-input" value={form.acl_name} onChange={(e) => setForm({ ...form, acl_name: e.target.value })} />
            </div>
            <div className="ac-field">
              <label className="ac-label">기본 액션</label>
              <select className="ac-input" value={form.default_action} onChange={(e) => setForm({ ...form, default_action: e.target.value })}>
                <option value="allow">허용 (Allow)</option>
                <option value="block">차단 (Block)</option>
              </select>
            </div>
          </div>
          <div className="ac-card-title" style={{ fontSize: 13, marginTop: 16 }}>관리형 규칙 그룹 (선택)</div>
          <div className="ac-check-list">
            {WAF_MANAGED_RULE_GROUPS.map((g) => (
              <label key={g.name} className={`ac-check ${groups.includes(g.name) ? 'active' : ''}`}>
                <input type="checkbox" checked={groups.includes(g.name)} onChange={() => toggleGroup(g.name)} />
                <span>{g.label}</span>
              </label>
            ))}
          </div>
        </>
      ) : (
        <>
          <div className="ac-form-row">
            <div className="ac-field">
              <label className="ac-label">대상 Web ACL</label>
              <select className="ac-input" value={form.target_id} onChange={(e) => setForm({ ...form, target_id: e.target.value })}>
                <option value="">선택...</option>
                {aclOptions.map((a) => <option key={a.resource_id} value={a.resource_id}>{a.resource_name}</option>)}
              </select>
            </div>
          </div>
          <div className="ac-card-title" style={{ fontSize: 13, marginTop: 16 }}>추가할 규칙</div>
          <div className="ac-waf-rules">
            {wafRules.map((r, i) => (
              <div key={i} className="ac-waf-rule">
                <div className="ac-form-row">
                  <div className="ac-field">
                    <label className="ac-label">유형</label>
                    <select className="ac-input" value={r.type} onChange={(e) => updateWafRule(i, { type: e.target.value })}>
                      <option value="ip_block">IP 차단</option>
                      <option value="rate_limit">요청 속도 제한</option>
                      <option value="string_match">문자열 매칭</option>
                      <option value="regex_match">정규식 매칭</option>
                    </select>
                  </div>
                  <div className="ac-field">
                    <label className="ac-label">규칙 이름</label>
                    <input className="ac-input" placeholder="예: block-bad-ips" value={r.name} onChange={(e) => updateWafRule(i, { name: e.target.value })} />
                  </div>
                </div>
                {r.type === 'ip_block' && (
                  <div className="ac-form-row">
                    <div className="ac-field">
                      <label className="ac-label">차단 CIDR (쉼표로 구분)</label>
                      <input className="ac-input" placeholder="1.2.3.4, 10.0.0.0/24" value={r.cidrs} onChange={(e) => updateWafRule(i, { cidrs: e.target.value })} />
                    </div>
                  </div>
                )}
                {r.type === 'rate_limit' && (
                  <div className="ac-form-row">
                    <div className="ac-field">
                      <label className="ac-label">5분당 요청 한도 (초과 시 차단)</label>
                      <input className="ac-input" type="number" placeholder="2000" value={r.limit} onChange={(e) => updateWafRule(i, { limit: e.target.value })} />
                    </div>
                  </div>
                )}
                {(r.type === 'string_match' || r.type === 'regex_match') && (
                  <>
                    <div className="ac-form-row">
                      <div className="ac-field">
                        <label className="ac-label">검사 대상</label>
                        <select className="ac-input" value={r.field} onChange={(e) => updateWafRule(i, { field: e.target.value })}>
                          {WAF_FIELDS.map((f) => <option key={f.key} value={f.key}>{f.label}</option>)}
                        </select>
                      </div>
                      {r.field === 'header' && (
                        <div className="ac-field">
                          <label className="ac-label">헤더 이름</label>
                          <input className="ac-input" placeholder="예: User-Agent" value={r.header_name} onChange={(e) => updateWafRule(i, { header_name: e.target.value })} />
                        </div>
                      )}
                      {r.type === 'string_match' && (
                        <div className="ac-field">
                          <label className="ac-label">조건</label>
                          <select className="ac-input" value={r.position} onChange={(e) => updateWafRule(i, { position: e.target.value })}>
                            {WAF_POSITIONS.map((p) => <option key={p.key} value={p.key}>{p.label}</option>)}
                          </select>
                        </div>
                      )}
                    </div>
                    <div className="ac-form-row">
                      <div className="ac-field">
                        <label className="ac-label">{r.type === 'regex_match' ? '정규식 패턴' : '문자열'}</label>
                        <input className="ac-input" placeholder={r.type === 'regex_match' ? '예: (?i)(union|select).*from' : "예: /admin"} value={r.pattern} onChange={(e) => updateWafRule(i, { pattern: e.target.value })} />
                      </div>
                    </div>
                  </>
                )}
                {wafRules.length > 1 && <button className="ac-btn ac-btn-secondary" onClick={() => removeWafRule(i)}>이 규칙 삭제</button>}
              </div>
            ))}
          </div>
          <button className="ac-btn ac-btn-secondary" onClick={addWafRule} style={{ marginTop: 8, marginBottom: 16 }}>+ 규칙 추가</button>
        </>
      )}

      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">신청 사유</label>
          <input className="ac-input" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} />
        </div>
      </div>
      <button className="ac-btn" onClick={submit} disabled={submitting}>{submitting ? '신청 중...' : '신청하기'}</button>
    </>
  )
}

function IamUserForm({ onSubmit, submitting }) {
  const [form, setForm] = useState({ user_name: '', policy_arn: IAM_READONLY_POLICIES[0].arn, reason: '' })

  const reset = () => setForm({ user_name: '', policy_arn: IAM_READONLY_POLICIES[0].arn, reason: '' })

  const submit = async () => {
    const userName = form.user_name.trim()
    if (!userName) return alert('계정 이름은 필수입니다')
    if (!/^[\w+=,.@-]+$/.test(userName)) return alert('계정 이름에 사용할 수 없는 문자가 있습니다 (영문/숫자/+=,.@- 만 허용)')
    if (!form.reason.trim()) return alert('신청 사유는 필수입니다 (승인자가 액세스키 발급 여부를 판단하는 근거로 사용됩니다)')

    const ok = await onSubmit({
      resource_type: 'iam_user', action: 'create_readonly_user',
      title: userName, target_id: null,
      payload: { user_name: userName, policy_arn: form.policy_arn },
      reason: form.reason.trim(),
    })
    if (ok) reset()
  }

  return (
    <>
      <p className="ac-cred-note">읽기 전용 IAM 계정을 신청합니다. 승인자가 사유를 보고 액세스키 발급 여부를 결정합니다.</p>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">계정 이름</label>
          <input className="ac-input" placeholder="예: readonly-hong" value={form.user_name} onChange={(e) => setForm({ ...form, user_name: e.target.value })} />
        </div>
        <div className="ac-field">
          <label className="ac-label">권한</label>
          <select className="ac-input" value={form.policy_arn} onChange={(e) => setForm({ ...form, policy_arn: e.target.value })}>
            {IAM_READONLY_POLICIES.map((p) => <option key={p.arn} value={p.arn}>{p.label}</option>)}
          </select>
        </div>
      </div>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">신청 사유 (필수)</label>
          <input className="ac-input" placeholder="예: 배포 로그 확인용 3일간 필요" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} />
        </div>
      </div>
      <button className="ac-btn" onClick={submit} disabled={submitting}>{submitting ? '신청 중...' : '신청하기'}</button>
    </>
  )
}

export default function AwsRequest() {
  const [resourceType, setResourceType] = useState('security_group')
  const [sgOptions, setSgOptions] = useState([])
  const [aclOptions, setAclOptions] = useState([])
  const [myRequests, setMyRequests] = useState([])
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [user, setUser] = useState(null)

  const dedupeByResource = (rows) => {
    const seen = new Set()
    return (rows || []).filter((s) => (seen.has(s.resource_id) ? false : (seen.add(s.resource_id), true)))
  }

  const fetchOptions = async () => {
    const { data } = await supabase.from('aws_resource_snapshots')
      .select('resource_id, resource_name, resource_type').order('collected_at', { ascending: false }).limit(400)
    setSgOptions(dedupeByResource((data || []).filter((s) => s.resource_type === 'security_group')))
    setAclOptions(dedupeByResource((data || []).filter((s) => s.resource_type === 'waf_web_acl')))
  }

  const fetchMyRequests = async (uid) => {
    setLoading(true)
    let q = supabase.from('aws_requests').select('*').order('requested_at', { ascending: false }).limit(50)
    if (uid) q = q.eq('requester_id', uid)
    const { data } = await q
    setMyRequests(data || [])
    setLoading(false)
  }

  useEffect(() => {
    supabase.auth.getUser().then(({ data }) => {
      setUser(data.user)
      fetchMyRequests(data.user?.id)
    })
    fetchOptions()
  }, [])

  const submitRequest = async (req) => {
    setSubmitting(true)
    const { error } = await supabase.from('aws_requests').insert({
      ...req,
      requester_id: user?.id || null,
      requester_email: user?.email || null,
    })
    setSubmitting(false)
    if (error) { alert('신청 실패: ' + error.message); return false }
    await fetchMyRequests(user?.id)
    alert('신청되었습니다. 승인자 검토 후 반영됩니다.')
    return true
  }

  return (
    <div className="ac-page">
      <h2 className="ac-title">📝 AWS 리소스 신청</h2>
      <p className="ac-sub">필요한 SG/WAF 설정을 신청하면 승인자 검토 후 실제 AWS에 반영됩니다.</p>

      <div className="ac-grid">
        <div className="ac-card ac-card-wide">
          <div className="ac-card-title">신청서 작성</div>
          <div className="ac-filter-row">
            {RESOURCE_TABS.map((t) => (
              <button key={t.key} className={`ac-filter-btn ${resourceType === t.key ? 'active' : ''}`} onClick={() => setResourceType(t.key)}>
                {t.label}
              </button>
            ))}
          </div>
          {resourceType === 'security_group' && <SgForm sgOptions={sgOptions} onSubmit={submitRequest} submitting={submitting} />}
          {resourceType === 'waf_web_acl' && <WafForm aclOptions={aclOptions} onSubmit={submitRequest} submitting={submitting} />}
          {resourceType === 'iam_user' && <IamUserForm onSubmit={submitRequest} submitting={submitting} />}
        </div>

        <div className="ac-card ac-card-wide">
          <div className="ac-card-title">내 신청 현황</div>
          {loading && <div className="ac-empty">불러오는 중...</div>}
          {!loading && myRequests.length === 0 && <div className="ac-empty">아직 신청 내역이 없습니다.</div>}
          <div className="ac-snapshot-list">
            {myRequests.map((r) => <ReqCard key={r.id} r={r} />)}
          </div>
        </div>
      </div>
    </div>
  )
}
