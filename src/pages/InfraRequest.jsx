import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'
import { REQ_STATUS_META, reqTitle, reqDetailLines } from '../lib/aws'

const AZ_OPTIONS = [
  { value: 'ap-northeast-2a', label: '2a' },
  { value: 'ap-northeast-2b', label: '2b' },
  { value: 'ap-northeast-2c', label: '2c' },
  { value: 'ap-northeast-2d', label: '2d' },
]

const INSTANCE_TYPES = ['t3.micro', 't3.small', 't3.medium', 't2.micro', 't2.small']

const INFRA_TYPES = {
  network: [
    { key: 'vpc', label: 'VPC', action: 'create_vpc' },
    { key: 'subnet', label: '서브넷', action: 'create_subnet' },
    { key: 'internet_gateway', label: 'Internet Gateway', action: 'create_igw' },
    { key: 'route_table', label: '라우팅 테이블', action: 'create_route_table' },
  ],
  compute: [
    { key: 'ec2_instance', label: 'EC2 인스턴스', action: 'create_ec2' },
  ],
}

const PAGE_META = {
  network: { title: 'VPC / 서브넷 신청', sub: 'VPC, 서브넷, IGW, 라우팅 테이블을 신청합니다. 승인 후 자동 적용됩니다.' },
  compute: { title: 'EC2 인스턴스 신청', sub: 'EC2 인스턴스를 신청합니다. 승인 후 자동 적용됩니다.' },
}

function VpcForm({ onSubmit, submitting }) {
  const [form, setForm] = useState({ name: '', cidr_block: '10.0.0.0/16', dns_hostnames: true, reason: '' })
  const reset = () => setForm({ name: '', cidr_block: '10.0.0.0/16', dns_hostnames: true, reason: '' })

  const submit = async () => {
    if (!form.name.trim()) return alert('VPC 이름은 필수입니다')
    if (!form.cidr_block.trim()) return alert('CIDR 블록은 필수입니다')
    const ok = await onSubmit({
      resource_type: 'vpc', action: 'create_vpc', title: form.name.trim(),
      payload: { name: form.name.trim(), cidr_block: form.cidr_block.trim(), dns_hostnames: form.dns_hostnames },
      reason: form.reason.trim() || null,
    })
    if (ok) reset()
  }

  return (
    <>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">VPC 이름</label>
          <input className="ac-input" placeholder="예: my-vpc" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </div>
        <div className="ac-field">
          <label className="ac-label">CIDR 블록</label>
          <input className="ac-input" placeholder="10.0.0.0/16" value={form.cidr_block} onChange={(e) => setForm({ ...form, cidr_block: e.target.value })} />
        </div>
      </div>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">
            <input type="checkbox" checked={form.dns_hostnames} onChange={(e) => setForm({ ...form, dns_hostnames: e.target.checked })} style={{ marginRight: 6 }} />
            DNS 호스트네임 활성화
          </label>
        </div>
      </div>
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

function SubnetForm({ onSubmit, submitting }) {
  const [form, setForm] = useState({ name: '', vpc_id: '', cidr_block: '', availability_zone: 'ap-northeast-2a', public_ip: true, reason: '' })
  const reset = () => setForm({ name: '', vpc_id: '', cidr_block: '', availability_zone: 'ap-northeast-2a', public_ip: true, reason: '' })

  const submit = async () => {
    if (!form.vpc_id.trim()) return alert('VPC ID는 필수입니다')
    if (!form.cidr_block.trim()) return alert('CIDR 블록은 필수입니다')
    const ok = await onSubmit({
      resource_type: 'subnet', action: 'create_subnet', title: form.name.trim() || form.cidr_block.trim(),
      payload: { name: form.name.trim(), vpc_id: form.vpc_id.trim(), cidr_block: form.cidr_block.trim(), availability_zone: form.availability_zone, public_ip: form.public_ip },
      reason: form.reason.trim() || null,
    })
    if (ok) reset()
  }

  return (
    <>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">서브넷 이름</label>
          <input className="ac-input" placeholder="예: public-subnet-a" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </div>
        <div className="ac-field">
          <label className="ac-label">VPC ID</label>
          <input className="ac-input" placeholder="vpc-0123abcd" value={form.vpc_id} onChange={(e) => setForm({ ...form, vpc_id: e.target.value })} />
        </div>
      </div>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">CIDR 블록</label>
          <input className="ac-input" placeholder="10.0.1.0/24" value={form.cidr_block} onChange={(e) => setForm({ ...form, cidr_block: e.target.value })} />
        </div>
        <div className="ac-field">
          <label className="ac-label">가용 영역</label>
          <select className="ac-input" value={form.availability_zone} onChange={(e) => setForm({ ...form, availability_zone: e.target.value })}>
            {AZ_OPTIONS.map((az) => <option key={az.value} value={az.value}>{az.label}</option>)}
          </select>
        </div>
      </div>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">
            <input type="checkbox" checked={form.public_ip} onChange={(e) => setForm({ ...form, public_ip: e.target.checked })} style={{ marginRight: 6 }} />
            퍼블릭 IP 자동 할당
          </label>
        </div>
      </div>
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

function Ec2Form({ onSubmit, submitting }) {
  const [form, setForm] = useState({ name: '', instance_type: 't3.micro', subnet_id: '', security_group_ids: '', reason: '' })
  const reset = () => setForm({ name: '', instance_type: 't3.micro', subnet_id: '', security_group_ids: '', reason: '' })

  const submit = async () => {
    if (!form.subnet_id.trim()) return alert('서브넷 ID는 필수입니다')
    const sgIds = form.security_group_ids.split(',').map((s) => s.trim()).filter(Boolean)
    if (sgIds.length === 0) return alert('Security Group ID를 최소 1개 입력해주세요')
    const ok = await onSubmit({
      resource_type: 'ec2_instance', action: 'create_ec2', title: form.name.trim() || form.instance_type,
      payload: { name: form.name.trim(), instance_type: form.instance_type, subnet_id: form.subnet_id.trim(), security_group_ids: sgIds },
      reason: form.reason.trim() || null,
    })
    if (ok) reset()
  }

  return (
    <>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">인스턴스 이름</label>
          <input className="ac-input" placeholder="예: web-server-1" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </div>
        <div className="ac-field">
          <label className="ac-label">인스턴스 타입</label>
          <select className="ac-input" value={form.instance_type} onChange={(e) => setForm({ ...form, instance_type: e.target.value })}>
            {INSTANCE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
      </div>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">서브넷 ID</label>
          <input className="ac-input" placeholder="subnet-0123abcd" value={form.subnet_id} onChange={(e) => setForm({ ...form, subnet_id: e.target.value })} />
        </div>
        <div className="ac-field">
          <label className="ac-label">Security Group IDs (쉼표 구분)</label>
          <input className="ac-input" placeholder="sg-0123abcd" value={form.security_group_ids} onChange={(e) => setForm({ ...form, security_group_ids: e.target.value })} />
        </div>
      </div>
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

function IgwForm({ onSubmit, submitting }) {
  const [form, setForm] = useState({ name: '', vpc_id: '', reason: '' })
  const reset = () => setForm({ name: '', vpc_id: '', reason: '' })

  const submit = async () => {
    if (!form.vpc_id.trim()) return alert('VPC ID는 필수입니다')
    const ok = await onSubmit({
      resource_type: 'internet_gateway', action: 'create_igw', title: form.name.trim() || 'IGW',
      payload: { name: form.name.trim(), vpc_id: form.vpc_id.trim() },
      reason: form.reason.trim() || null,
    })
    if (ok) reset()
  }

  return (
    <>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">IGW 이름</label>
          <input className="ac-input" placeholder="예: my-igw" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </div>
        <div className="ac-field">
          <label className="ac-label">연결할 VPC ID</label>
          <input className="ac-input" placeholder="vpc-0123abcd" value={form.vpc_id} onChange={(e) => setForm({ ...form, vpc_id: e.target.value })} />
        </div>
      </div>
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

function RouteTableForm({ onSubmit, submitting }) {
  const [form, setForm] = useState({ name: '', vpc_id: '', gateway_id: '', subnet_ids: '', reason: '' })
  const reset = () => setForm({ name: '', vpc_id: '', gateway_id: '', subnet_ids: '', reason: '' })

  const submit = async () => {
    if (!form.vpc_id.trim()) return alert('VPC ID는 필수입니다')
    const subnetIds = form.subnet_ids.split(',').map((s) => s.trim()).filter(Boolean)
    const routes = form.gateway_id.trim() ? [{ cidr_block: '0.0.0.0/0', gateway_id: form.gateway_id.trim() }] : []
    const ok = await onSubmit({
      resource_type: 'route_table', action: 'create_route_table', title: form.name.trim() || 'RT',
      payload: { name: form.name.trim(), vpc_id: form.vpc_id.trim(), routes, subnet_ids: subnetIds },
      reason: form.reason.trim() || null,
    })
    if (ok) reset()
  }

  return (
    <>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">라우팅 테이블 이름</label>
          <input className="ac-input" placeholder="예: public-rt" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </div>
        <div className="ac-field">
          <label className="ac-label">VPC ID</label>
          <input className="ac-input" placeholder="vpc-0123abcd" value={form.vpc_id} onChange={(e) => setForm({ ...form, vpc_id: e.target.value })} />
        </div>
      </div>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">IGW ID (0.0.0.0/0 → IGW 라우트 추가)</label>
          <input className="ac-input" placeholder="igw-0123abcd (선택)" value={form.gateway_id} onChange={(e) => setForm({ ...form, gateway_id: e.target.value })} />
        </div>
        <div className="ac-field">
          <label className="ac-label">연결할 서브넷 IDs (쉼표 구분)</label>
          <input className="ac-input" placeholder="subnet-abc, subnet-def" value={form.subnet_ids} onChange={(e) => setForm({ ...form, subnet_ids: e.target.value })} />
        </div>
      </div>
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

const FORM_MAP = {
  vpc: VpcForm,
  subnet: SubnetForm,
  ec2_instance: Ec2Form,
  internet_gateway: IgwForm,
  route_table: RouteTableForm,
}

function MyReqRow({ r }) {
  const [open, setOpen] = useState(false)
  const meta = REQ_STATUS_META[r.status] || { label: r.status, color: '#94a3b8' }
  const detail = reqDetailLines(r)
  const d = new Date(r.requested_at)

  return (
    <div className="ac-myreq">
      <div className="ac-myreq-top" onClick={() => setOpen((v) => !v)}>
        <span className="ac-req-status" style={{ background: meta.color, fontSize: 11, padding: '2px 8px', borderRadius: 4 }}>{meta.label}</span>
        <span className="ac-myreq-title">{reqTitle(r)}</span>
        <span className="ac-expand-icon">{open ? '▲' : '▼'}</span>
      </div>
      {open && (
        <div className="ac-myreq-body">
          {detail.map((line, i) => <div key={i} className="ac-req-reason">{line}</div>)}
          {r.reason && <div className="ac-req-reason">사유: {r.reason}</div>}
          {r.result?.created_id && <div className="ac-req-meta">생성 ID: {r.result.created_id}</div>}
          {r.result?.terraform && <div className="ac-req-meta">🔧 Terraform으로 적용됨</div>}
          {r.error_message && <div className="ac-req-error">{r.error_message}</div>}
          <div className="ac-req-meta">{d.toLocaleString('ko-KR')}</div>
        </div>
      )}
    </div>
  )
}

export default function InfraRequest({ mode = 'network' }) {
  const types = INFRA_TYPES[mode] || INFRA_TYPES.network
  const meta = PAGE_META[mode] || PAGE_META.network
  const [selected, setSelected] = useState(types[0].key)
  const [myRequests, setMyRequests] = useState([])
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [user, setUser] = useState(null)

  const typeKeys = types.map((t) => t.key)

  const fetchMyRequests = async () => {
    setLoading(true)
    const { data } = await supabase.from('aws_requests').select('*')
      .in('resource_type', typeKeys)
      .order('requested_at', { ascending: false }).limit(50)
    setMyRequests(data || [])
    setLoading(false)
  }

  useEffect(() => {
    setSelected(types[0].key)
    supabase.auth.getUser().then(({ data }) => setUser(data.user))
    fetchMyRequests()
  }, [mode])

  const submitRequest = async (req) => {
    setSubmitting(true)
    const { error } = await supabase.from('aws_requests').insert({
      ...req,
      requester_id: user?.id || null,
      requester_email: user?.email || null,
    })
    setSubmitting(false)
    if (error) { alert('신청 실패: ' + error.message); return false }
    await fetchMyRequests()
    alert('신청되었습니다. 승인 후 자동 적용됩니다.')
    return true
  }

  const FormComponent = FORM_MAP[selected]

  return (
    <div className="ac-page">
      <h2 className="ac-title">{meta.title}</h2>
      <p className="ac-sub">{meta.sub}</p>

      <div className="ac-grid">
        <div className="ac-card ac-card-wide">
          <div className="ac-card-title">신청서 작성</div>
          {types.length > 1 && (
            <div className="ac-filter-row">
              {types.map((t) => (
                <button key={t.key} className={`ac-filter-btn ${selected === t.key ? 'active' : ''}`} onClick={() => setSelected(t.key)}>
                  {t.label}
                </button>
              ))}
            </div>
          )}
          {FormComponent && <FormComponent onSubmit={submitRequest} submitting={submitting} />}
        </div>

        <div className="ac-card ac-card-wide ac-card-muted">
          <div className="ac-card-title">내 신청 현황</div>
          {loading && <div className="ac-empty">불러오는 중...</div>}
          {!loading && myRequests.length === 0 && <div className="ac-empty">아직 신청 내역이 없습니다.</div>}
          <div className="ac-snapshot-list">
            {myRequests.map((r) => <MyReqRow key={r.id} r={r} />)}
          </div>
        </div>
      </div>
    </div>
  )
}
