import { useState } from 'react'

const AZ_OPTIONS = [
  { value: 'ap-northeast-2a', label: '2a' },
  { value: 'ap-northeast-2b', label: '2b' },
  { value: 'ap-northeast-2c', label: '2c' },
  { value: 'ap-northeast-2d', label: '2d' },
]

const INSTANCE_TYPES = ['t3.micro', 't3.small', 't3.medium', 't2.micro', 't2.small']

export const INFRA_TYPES = {
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

export const PAGE_META = {
  network: { title: 'VPC / 서브넷 신청', sub: 'VPC, 서브넷, IGW, 라우팅 테이블을 신청합니다. 승인 후 자동 적용됩니다.' },
  compute: { title: 'EC2 인스턴스 신청', sub: 'EC2 인스턴스를 신청합니다. 승인 후 자동 적용됩니다.' },
}

function isValidCidr(cidr) {
  const m = cidr.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/)
  if (!m) return false
  const [, a, b, c, d, mask] = m.map(Number)
  if ([a, b, c, d].some((o) => o > 255)) return false
  if (mask < 0 || mask > 32) return false
  // 네트워크 경계 검사: 호스트 비트가 0이어야 함
  const ip = ((a << 24) | (b << 16) | (c << 8) | d) >>> 0
  const hostBits = 32 - mask
  if (hostBits < 32 && (ip & ((1 << hostBits) - 1)) !== 0) return false
  return true
}

export function VpcForm({ onSubmit, submitting }) {
  const [form, setForm] = useState({ name: '', cidr_block: '10.0.0.0/16', dns_hostnames: true, reason: '' })
  const reset = () => setForm({ name: '', cidr_block: '10.0.0.0/16', dns_hostnames: true, reason: '' })

  const submit = async () => {
    if (!form.name.trim()) return alert('VPC 이름은 필수입니다')
    if (!form.cidr_block.trim()) return alert('CIDR 블록은 필수입니다')
    if (!isValidCidr(form.cidr_block.trim())) return alert('유효하지 않은 CIDR입니다.\n마스크: /0~/32, 네트워크 경계가 맞아야 합니다.\n예: 10.0.0.0/16, 172.16.0.0/12')
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

export function SubnetForm({ onSubmit, submitting, vpcOptions }) {
  const [form, setForm] = useState({ name: '', vpc_id: '', cidr_block: '', availability_zone: 'ap-northeast-2a', public_ip: true, reason: '' })
  const reset = () => setForm({ name: '', vpc_id: '', cidr_block: '', availability_zone: 'ap-northeast-2a', public_ip: true, reason: '' })

  const submit = async () => {
    if (!form.vpc_id.trim()) return alert('VPC ID는 필수입니다')
    if (!form.cidr_block.trim()) return alert('CIDR 블록은 필수입니다')
    if (!isValidCidr(form.cidr_block.trim())) return alert('유효하지 않은 CIDR입니다.\n마스크: /0~/32, 네트워크 경계가 맞아야 합니다.\n예: 10.0.1.0/24, 10.0.0.0/20')
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
          <label className="ac-label">VPC</label>
          {vpcOptions.length > 0 ? (
            <select className="ac-input" value={form.vpc_id} onChange={(e) => setForm({ ...form, vpc_id: e.target.value })}>
              <option value="">VPC 선택...</option>
              {vpcOptions.map((v) => <option key={v.vpc_id} value={v.vpc_id}>{v.name} ({v.vpc_id})</option>)}
            </select>
          ) : (
            <input className="ac-input" placeholder="vpc-0123abcd" value={form.vpc_id} onChange={(e) => setForm({ ...form, vpc_id: e.target.value })} />
          )}
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

export function Ec2Form({ onSubmit, submitting }) {
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

export function IgwForm({ onSubmit, submitting, vpcOptions }) {
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
          <label className="ac-label">연결할 VPC</label>
          {vpcOptions.length > 0 ? (
            <select className="ac-input" value={form.vpc_id} onChange={(e) => setForm({ ...form, vpc_id: e.target.value })}>
              <option value="">VPC 선택...</option>
              {vpcOptions.map((v) => <option key={v.vpc_id} value={v.vpc_id}>{v.name} ({v.vpc_id})</option>)}
            </select>
          ) : (
            <input className="ac-input" placeholder="vpc-0123abcd" value={form.vpc_id} onChange={(e) => setForm({ ...form, vpc_id: e.target.value })} />
          )}
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

export function RouteTableForm({ onSubmit, submitting, vpcOptions, igwOptions, subnetOptions }) {
  const [form, setForm] = useState({ name: '', vpc_id: '', gateway_id: '', subnet_ids: [], reason: '' })
  const reset = () => setForm({ name: '', vpc_id: '', gateway_id: '', subnet_ids: [], reason: '' })

  const toggleSubnet = (sid) => setForm((prev) => ({
    ...prev,
    subnet_ids: prev.subnet_ids.includes(sid) ? prev.subnet_ids.filter((s) => s !== sid) : [...prev.subnet_ids, sid],
  }))

  const submit = async () => {
    if (!form.vpc_id.trim()) return alert('VPC ID는 필수입니다')
    const subnetIds = form.subnet_ids
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
          <label className="ac-label">VPC</label>
          {vpcOptions.length > 0 ? (
            <select className="ac-input" value={form.vpc_id} onChange={(e) => setForm({ ...form, vpc_id: e.target.value })}>
              <option value="">VPC 선택...</option>
              {vpcOptions.map((v) => <option key={v.vpc_id} value={v.vpc_id}>{v.name} ({v.vpc_id})</option>)}
            </select>
          ) : (
            <input className="ac-input" placeholder="vpc-0123abcd" value={form.vpc_id} onChange={(e) => setForm({ ...form, vpc_id: e.target.value })} />
          )}
        </div>
      </div>
      <div className="ac-form-row">
        <div className="ac-field">
          <label className="ac-label">IGW (0.0.0.0/0 → IGW 라우트 추가)</label>
          {(() => {
            const filtered = igwOptions.filter((g) => !form.vpc_id || g.vpc_id === form.vpc_id)
            return filtered.length > 0 ? (
              <select className="ac-input" value={form.gateway_id} onChange={(e) => setForm({ ...form, gateway_id: e.target.value })}>
                <option value="">선택 안함</option>
                {filtered.map((g) => <option key={g.igw_id} value={g.igw_id}>{g.name} ({g.igw_id})</option>)}
              </select>
            ) : (
              <input className="ac-input" placeholder="igw-0123abcd (선택)" value={form.gateway_id} onChange={(e) => setForm({ ...form, gateway_id: e.target.value })} />
            )
          })()}
        </div>
        <div className="ac-field">
          <label className="ac-label">연결할 서브넷</label>
          {(() => {
            const filtered = subnetOptions.filter((s) => !form.vpc_id || s.vpc_id === form.vpc_id)
            return filtered.length > 0 ? (
              <div className="ac-check-list">
                {filtered.map((s) => (
                  <label key={s.subnet_id} className={`ac-check ${form.subnet_ids.includes(s.subnet_id) ? 'active' : ''}`}>
                    <input type="checkbox" checked={form.subnet_ids.includes(s.subnet_id)} onChange={() => toggleSubnet(s.subnet_id)} />
                    <span>{s.name} ({s.subnet_id})</span>
                  </label>
                ))}
              </div>
            ) : (
              <input className="ac-input" placeholder="subnet-abc, subnet-def (쉼표 구분)" value={Array.isArray(form.subnet_ids) ? form.subnet_ids.join(', ') : form.subnet_ids} onChange={(e) => setForm({ ...form, subnet_ids: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })} />
            )
          })()}
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

export const FORM_MAP = {
  vpc: VpcForm,
  subnet: SubnetForm,
  ec2_instance: Ec2Form,
  internet_gateway: IgwForm,
  route_table: RouteTableForm,
}
