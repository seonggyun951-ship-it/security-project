import { useState } from 'react'
import { NACL_PROTOCOLS, normalizeCidr, parsePortRange } from '../../lib/aws'

// 네트워크 ACL 규칙 신청.
//
// SG 폼과 다른 점만 남긴다:
//   · 규칙 번호가 있다. 낮은 번호부터 먼저 맞는 하나만 적용되므로 순서가 곧 의미다.
//   · 허용/거부를 고른다. 거부 규칙은 막는 쪽이라 점검에서 걸리지 않는다.
//   · 스테이트리스라 응답용 임시 포트를 따로 열어야 한다 — 그래서 자주 쓰는 조합을
//     '자주 쓰는 규칙' 버튼으로 넣어둔다. 손으로 매번 적으면 3389를 빠뜨린다.

const emptyNaclRule = () => ({
  rule_no: '', direction: 'ingress', action: 'allow', protocol: 'tcp', port: '', cidr: '',
})

// 기본 NACL을 좁힐 때 쓰는 한 벌. Terraform이 환경 VPC에 넣은 것과 같은 구성이다
// (terraform/envs/modules/vpc-env/network_acl.tf).
//
// 번호 순서가 곧 정책이다. 민감 포트 거부(80~)를 임시 포트 허용(120)보다 앞에 둬야
// 응답용으로 연 1024-65535에 RDP·DB 포트가 딸려 들어가지 않는다.
const SENSITIVE_DENY = [3389, 3306, 5432, 1433, 6379, 27017]

const PRESET_WEB = [
  ...SENSITIVE_DENY.map((p, i) => ({
    rule_no: String(80 + i), direction: 'ingress', action: 'deny',
    protocol: 'tcp', port: String(p), cidr: '0.0.0.0/0',
  })),
  { rule_no: '100', direction: 'ingress', action: 'allow', protocol: 'tcp', port: '80',         cidr: '0.0.0.0/0' },
  { rule_no: '110', direction: 'ingress', action: 'allow', protocol: 'tcp', port: '443',        cidr: '0.0.0.0/0' },
  { rule_no: '120', direction: 'ingress', action: 'allow', protocol: 'tcp', port: '1024-65535', cidr: '0.0.0.0/0' },
]

function toPayloadRules(rules) {
  return rules
    .filter((r) => String(r.rule_no).trim() && r.cidr.trim())
    .map((r) => ({
      rule_no: Number(r.rule_no),
      direction: r.direction,
      action: r.action,
      protocol: r.protocol,
      // 프로토콜이 '전체'면 포트 개념이 없다 (AWS도 PortRange를 받지 않는다)
      ...(r.protocol === '-1' ? { from_port: null, to_port: null } : parsePortRange(r.port)),
      cidr: normalizeCidr(r.cidr),
    }))
}

function RuleTable({ rules, setRules, showPreset }) {
  const update = (i, patch) => setRules((prev) => prev.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  const add = () => setRules((prev) => [...prev, emptyNaclRule()])
  const remove = (i) => setRules((prev) => prev.filter((_, idx) => idx !== i))

  return (
    <>
      <div className="ac-card-title" style={{ fontSize: 13, marginTop: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ flex: 1 }}>규칙</span>
        {showPreset && (
          <button className="ac-btn ac-btn-secondary" style={{ padding: '2px 8px', fontSize: 11 }}
            title="웹 서비스용 최소 구성 — 3389 거부를 앞 번호에 두고 임시 포트를 엽니다"
            onClick={() => setRules(PRESET_WEB.map((r) => ({ ...r })))}>
            자주 쓰는 규칙 넣기
          </button>
        )}
      </div>

      {/* 칸이 7개라 카드 폭을 넘길 수 있다. 접지 않고 표만 가로로 스크롤시킨다 —
          번호·방향·허용/거부가 한 줄에 같이 보여야 어떤 규칙인지 읽힌다. */}
      <div className="ac-nacl-wrap">
        <div className="ac-rule-table">
          <div className="ac-rule-row ac-nacl-row ac-rule-head">
            <span>번호</span><span>방향</span><span>허용/거부</span><span>프로토콜</span><span>포트</span><span>CIDR</span><span></span>
          </div>
          {rules.map((r, i) => (
            <div key={i} className="ac-rule-row ac-nacl-row">
              <input className="ac-input" type="number" min="1" max="32766" placeholder="100"
                value={r.rule_no} onChange={(e) => update(i, { rule_no: e.target.value })} />
              <select className="ac-input" value={r.direction} onChange={(e) => update(i, { direction: e.target.value })}>
                <option value="ingress">인바운드</option>
                <option value="egress">아웃바운드</option>
              </select>
              <select className="ac-input" value={r.action} onChange={(e) => update(i, { action: e.target.value })}>
                <option value="allow">허용</option>
                <option value="deny">거부</option>
              </select>
              <select className="ac-input" value={r.protocol} onChange={(e) => update(i, { protocol: e.target.value })}>
                {NACL_PROTOCOLS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
              </select>
              <input className="ac-input" placeholder="80 또는 1024-65535" disabled={r.protocol === '-1'}
                value={r.protocol === '-1' ? '' : r.port} onChange={(e) => update(i, { port: e.target.value })} />
              <input className="ac-input" placeholder="0.0.0.0/0" value={r.cidr}
                onChange={(e) => update(i, { cidr: e.target.value })} />
              <button className="ac-btn ac-btn-secondary" onClick={() => remove(i)} disabled={rules.length === 1}>−</button>
            </div>
          ))}
        </div>
      </div>
      <button className="ac-btn ac-btn-secondary" style={{ marginTop: 6 }} onClick={add}>규칙 추가</button>
    </>
  )
}

export function NaclForm({ naclOptions, prefill, onSubmit, submitting }) {
  // 점검 결과에서 '조치 신청'으로 넘어오면 대상과 규칙이 채워져 온다.
  const [form, setForm] = useState({
    nacl_id: prefill?.nacl_id || '',
    reason: prefill?.reason || '',
  })
  const [rules, setRules] = useState(
    prefill?.rules?.length ? prefill.rules.map((r) => ({ ...emptyNaclRule(), ...r })) : [emptyNaclRule()])

  const reset = () => { setForm({ nacl_id: '', reason: '' }); setRules([emptyNaclRule()]) }

  const submit = async () => {
    if (!form.nacl_id.trim()) return alert('NACL ID는 필수입니다')
    const clean = toPayloadRules(rules)
    if (clean.length === 0) return alert('규칙을 최소 1개 이상 입력해주세요 (번호와 CIDR 필수)')

    const seen = new Set()
    for (const r of clean) {
      const key = `${r.direction}-${r.rule_no}`
      if (seen.has(key)) return alert(`규칙 번호 ${r.rule_no}(${r.direction})가 중복됩니다. 방향별로 번호가 하나씩이어야 합니다.`)
      seen.add(key)
    }

    const picked = naclOptions.find((o) => o.resource_id === form.nacl_id.trim())
    const ok = await onSubmit({
      resource_type: 'network_acl',
      action: 'add_nacl_rules',
      title: form.nacl_id.trim(),
      target_id: form.nacl_id.trim(),
      payload: { nacl_id: form.nacl_id.trim(), nacl_name: picked?.resource_name || null, rules: clean },
      reason: form.reason.trim() || null,
    })
    if (ok) reset()
  }

  return (
    <>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">NACL ID</label>
          <input className="ac-input" list="nacl-options" placeholder="예: acl-0123abcd"
            value={form.nacl_id} onChange={(e) => setForm({ ...form, nacl_id: e.target.value })} />
          <datalist id="nacl-options">
            {naclOptions.map((o) => <option key={o.resource_id} value={o.resource_id}>{o.resource_name}</option>)}
          </datalist>
        </div>
      </div>

      {prefill?.check_id && (
        <div className="ac-note ac-note-warn">
          보안 점검 <b>{prefill.check_id}</b>에서 걸린 항목을 고치는 신청입니다.
          앞 번호에 거부 규칙을 넣어 해당 포트를 막습니다 — <b>번호가 낮은 규칙이 먼저 적용</b>되므로,
          이 NACL에 이미 있는 규칙과 번호가 겹치지 않는지 확인하세요.
        </div>
      )}

      <div className="ac-note">
        NACL은 <b>스테이트리스</b>입니다. 나간 요청의 응답이 자동으로 돌아오지 않으므로
        임시 포트(1024-65535) 인바운드를 함께 열어야 합니다. 그 범위에 3389(RDP)가 들어가니
        더 낮은 번호에 3389 거부 규칙을 같이 넣으세요.
      </div>

      <RuleTable rules={rules} setRules={setRules} showPreset />

      <div className="ac-form-row" style={{ marginTop: 12 }}>
        <div className="ac-field">
          <label className="ac-label">신청 사유 (선택)</label>
          <input className="ac-input" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} />
        </div>
      </div>

      <button className="ac-btn" onClick={submit} disabled={submitting}>
        {submitting ? '신청 중...' : '신청하기'}
      </button>
    </>
  )
}

export function NaclDeleteForm({ naclOptions, onSubmit, submitting }) {
  const [form, setForm] = useState({ nacl_id: '', reason: '' })
  const [rules, setRules] = useState([emptyNaclRule()])

  const reset = () => { setForm({ nacl_id: '', reason: '' }); setRules([emptyNaclRule()]) }

  const submit = async () => {
    if (!form.nacl_id.trim()) return alert('NACL ID는 필수입니다')
    const clean = toPayloadRules(rules)
    if (clean.length === 0) return alert('지울 규칙의 번호와 방향을 입력해주세요')
    if (!form.reason.trim()) return alert('삭제는 사유가 필요합니다')

    const picked = naclOptions.find((o) => o.resource_id === form.nacl_id.trim())
    const ok = await onSubmit({
      resource_type: 'network_acl',
      action: 'delete_nacl_rules',
      title: form.nacl_id.trim(),
      target_id: form.nacl_id.trim(),
      payload: { nacl_id: form.nacl_id.trim(), nacl_name: picked?.resource_name || null, rules: clean },
      reason: form.reason.trim(),
    })
    if (ok) reset()
  }

  return (
    <>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">NACL ID</label>
          <input className="ac-input" list="nacl-options-del" placeholder="예: acl-0123abcd"
            value={form.nacl_id} onChange={(e) => setForm({ ...form, nacl_id: e.target.value })} />
          <datalist id="nacl-options-del">
            {naclOptions.map((o) => <option key={o.resource_id} value={o.resource_id}>{o.resource_name}</option>)}
          </datalist>
        </div>
      </div>

      <div className="ac-note ac-note-warn">
        지울 때 실제로 쓰이는 값은 <b>규칙 번호와 방향</b>입니다(AWS가 그 둘로 규칙을 찾습니다).
        나머지 칸은 관리자가 무엇을 지우는지 알아보라고 함께 적어 두는 것입니다.
        <b> 허용 규칙을 지우면 그 서브넷 통신이 즉시 끊깁니다.</b>
      </div>

      <RuleTable rules={rules} setRules={setRules} />

      <div className="ac-form-row" style={{ marginTop: 12 }}>
        <div className="ac-field">
          <label className="ac-label">삭제 사유 (필수)</label>
          <input className="ac-input" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} />
        </div>
      </div>

      <button className="ac-btn ac-btn-danger" onClick={submit} disabled={submitting}>
        {submitting ? '신청 중...' : '삭제 신청'}
      </button>
    </>
  )
}
