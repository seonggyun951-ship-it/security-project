import { useState } from 'react'
import {
  WAF_MANAGED_RULE_GROUPS, WAF_FIELDS, WAF_POSITIONS, IAM_READONLY_POLICIES,
  emptyRule, parsePortRange, normalizeCidr, emptyWafRule,
} from '../../lib/aws'

const SENSITIVE_PORTS = [22, 3389, 3306, 5432, 1433, 6379, 27017]
const MIN_CIDR_PREFIX = 24
const MAX_RULES = 50
const EXPIRY_OPTIONS = [
  { value: '', label: '만료 없음 (영구)' },
  { value: '1', label: '1일' },
  { value: '3', label: '3일' },
  { value: '7', label: '1주' },
  { value: '14', label: '2주' },
  { value: '30', label: '1개월' },
  { value: '90', label: '3개월' },
]

function validateSgRulesClient(rules) {
  const warnings = []
  for (const r of rules) {
    if (r.cidr === '0.0.0.0/0' || r.cidr === '::/0') {
      warnings.push(`전체 개방(${r.cidr})은 허용되지 않습니다`)
    }
    const prefix = parseInt((r.cidr || '').split('/')[1])
    if (!isNaN(prefix) && prefix < MIN_CIDR_PREFIX) {
      warnings.push(`CIDR ${r.cidr}: /${MIN_CIDR_PREFIX} 이상만 허용 (현재 /${prefix})`)
    }
    const ports = [r.from_port, r.to_port].filter((p) => p != null)
    for (const port of ports) {
      if (SENSITIVE_PORTS.includes(port) && r.direction === 'ingress') {
        warnings.push(`포트 ${port}은 민감 포트입니다 (승인 시 추가 검토 대상)`)
      }
    }
  }
  if (rules.length > MAX_RULES) {
    warnings.push(`규칙 수가 ${MAX_RULES}개를 초과합니다`)
  }
  return warnings
}

export function SgForm({ sgOptions, onSubmit, submitting }) {
  const [action, setAction] = useState('add_rules')
  const [form, setForm] = useState({ sg_id: '', sg_name: '', vpc_id: '', description: '', reason: '', expires_in_days: '' })
  const [rules, setRules] = useState([emptyRule()])

  const updateRule = (i, patch) => setRules((prev) => prev.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  const addRule = () => setRules((prev) => [...prev, emptyRule()])
  const removeRule = (i) => setRules((prev) => prev.filter((_, idx) => idx !== i))

  const reset = () => {
    setForm({ sg_id: '', sg_name: '', vpc_id: '', description: '', reason: '', expires_in_days: '' })
    setRules([emptyRule()])
  }

  const submit = async () => {
    if (action === 'add_rules' && !form.sg_id.trim()) return alert('SG ID는 필수입니다')
    if (action === 'create_sg' && (!form.sg_name.trim() || !form.vpc_id.trim())) return alert('SG 이름과 VPC ID는 필수입니다')
    const cleanRules = rules.filter((r) => r.cidr.trim()).map((r) => ({
      direction: r.direction, protocol: r.protocol, ...parsePortRange(r.port), cidr: normalizeCidr(r.cidr),
    }))
    if (cleanRules.length === 0) return alert('규칙을 최소 1개 이상 입력해주세요 (CIDR 필수)')

    const warnings = validateSgRulesClient(cleanRules)
    const blocked = warnings.filter((w) => w.includes('허용되지 않습니다') || w.includes('이상만 허용') || w.includes('초과'))
    if (blocked.length > 0) return alert('신청 불가:\n' + blocked.join('\n'))
    if (warnings.length > 0 && !confirm('주의사항:\n' + warnings.join('\n') + '\n\n그래도 신청하시겠습니까?')) return

    const expiresAt = form.expires_in_days
      ? new Date(Date.now() + Number(form.expires_in_days) * 86400000).toISOString()
      : null

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
        expires_at: expiresAt,
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
        <div className="ac-field">
          <label className="ac-label">만료 기간</label>
          <select className="ac-input" value={form.expires_in_days} onChange={(e) => setForm({ ...form, expires_in_days: e.target.value })}>
            {EXPIRY_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
      </div>
      <button className="ac-btn" onClick={submit} disabled={submitting}>{submitting ? '신청 중...' : '신청하기'}</button>
    </>
  )
}

export function WafForm({ aclOptions, onSubmit, submitting }) {
  const [action, setAction] = useState('create_acl') // 'create_acl' | 'add_waf_rules'
  const [form, setForm] = useState({ acl_name: '', default_action: 'allow', target_id: '', reason: '' })
  const [groups, setGroups] = useState([]) // 선택된 관리형 규칙 그룹 name[]
  const [wafRules, setWafRules] = useState([emptyWafRule()])

  const toggleGroup = (name) => setGroups((prev) => prev.includes(name) ? prev.filter((n) => n !== name) : [...prev, name])
  const updateWafRule = (i, patch) => setWafRules((prev) => prev.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  const addWafRule = () => setWafRules((prev) => [...prev, emptyWafRule()])
  const removeWafRule = (i) => setWafRules((prev) => prev.filter((_, idx) => idx !== i))

  const reset = () => {
    setForm({ acl_name: '', default_action: 'allow', scope: 'REGIONAL', target_id: '', reason: '' })
    setGroups([])
    setWafRules([emptyWafRule()])
  }

  const submit = async () => {
    if (action === 'create_acl') {
      if (!form.acl_name.trim()) return alert('Web ACL 이름은 필수입니다')
      // 기본 액션이 '차단'이면 그 자체가 정책이므로 관리형 규칙 없이도 의미가 있다.
      // 반면 '허용' + 규칙 0개는 아무 요청도 걸러내지 않는 빈 껍데기라서 막는다.
      if (form.default_action !== 'block' && groups.length === 0) {
        return alert(
          '기본 액션이 "허용"이면 관리형 규칙을 최소 1개 선택해야 합니다.\n' +
          '규칙이 없으면 아무 요청도 차단하지 않는 Web ACL이 됩니다.\n\n' +
          '규칙 없이 만들려면 기본 액션을 "차단"으로 선택해주세요.'
        )
      }
      const ok = await onSubmit({
        resource_type: 'waf_web_acl', action: 'create_acl',
        title: form.acl_name.trim(), target_id: null,
        payload: {
          acl_name: form.acl_name.trim(),
          default_action: form.default_action,
          scope: form.scope,
          managed_rule_groups: groups,
        },
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
      // 스코프는 사용자가 고르는 게 아니라 대상 ACL이 이미 가진 값이다.
      // 수집 시 CLOUDFRONT ACL은 region에 'CLOUDFRONT'로 표시해둔다.
      payload: {
        web_acl_name: selected?.resource_name || null,
        scope: selected?.region === 'CLOUDFRONT' ? 'CLOUDFRONT' : 'REGIONAL',
        rules: clean,
      },
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
          <div className="ac-form-row">
            <div className="ac-field">
              <label className="ac-label">적용 범위 (Scope)</label>
              <select className="ac-input" value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value })}>
                <option value="REGIONAL">리전 (ALB, API Gateway, AppSync)</option>
                <option value="CLOUDFRONT">글로벌 (CloudFront)</option>
              </select>
              <p className="ac-sub" style={{ marginTop: 6, marginBottom: 0 }}>
                {form.scope === 'CLOUDFRONT'
                  ? 'CloudFront용 Web ACL은 us-east-1에 생성됩니다. CloudFront 배포에만 연결할 수 있습니다.'
                  : '현재 리전에 생성됩니다. CloudFront에는 연결할 수 없습니다.'}
              </p>
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
                {aclOptions.map((a) => (
                  <option key={a.resource_id} value={a.resource_id}>
                    {a.resource_name} {a.region === 'CLOUDFRONT' ? '(글로벌)' : '(리전)'}
                  </option>
                ))}
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

export function IamUserForm({ onSubmit, submitting }) {
  const [form, setForm] = useState({ user_name: '', policy_arn: IAM_READONLY_POLICIES[0].arn, issue_key: false, reason: '' })

  const reset = () => setForm({ user_name: '', policy_arn: IAM_READONLY_POLICIES[0].arn, issue_key: false, reason: '' })

  const submit = async () => {
    const userName = form.user_name.trim()
    if (!userName) return alert('계정 이름은 필수입니다')
    if (!/^[\w+=,.@-]+$/.test(userName)) return alert('계정 이름에 사용할 수 없는 문자가 있습니다 (영문/숫자/+=,.@- 만 허용)')
    if (!form.reason.trim()) return alert('신청 사유는 필수입니다 (승인자가 액세스키 발급 여부를 판단하는 근거로 사용됩니다)')

    const ok = await onSubmit({
      resource_type: 'iam_user', action: 'create_readonly_user',
      title: userName, target_id: null,
      // 신청자의 희망일 뿐이고, 실제 발급 여부는 승인자가 버튼으로 최종 결정한다.
      payload: { user_name: userName, policy_arn: form.policy_arn, issue_key: form.issue_key },
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
          <label className="ac-label">
            <input type="checkbox" checked={form.issue_key} style={{ marginRight: 6 }}
              onChange={(e) => setForm({ ...form, issue_key: e.target.checked })} />
            액세스 키 발급도 함께 요청
          </label>
          <p className="ac-sub" style={{ marginTop: 6, marginBottom: 0 }}>
            {form.issue_key
              ? 'CLI·SDK로 접근할 때 필요합니다. Secret Key는 발급 직후 한 번만 표시됩니다.'
              : '콘솔 로그인만 필요하면 체크하지 않아도 됩니다. 나중에 다시 신청할 수 있습니다.'}
          </p>
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

