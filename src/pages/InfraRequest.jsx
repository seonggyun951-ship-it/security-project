import { useState, useEffect } from 'react'
import { supabase } from '../lib/supabase'
import { REQ_STATUS_META, ACTION_LABEL, ReqCard, reqTitle, reqDetailLines } from '../lib/aws'
import { notify, summarizePayload } from '../lib/discord'
import { requireUser } from '../lib/auth'
import { fetchRows, callFunction } from '../lib/db'
import ErrorBanner from '../components/ErrorBanner'
import { WEEKDAYS, dateKey, localDateKey, todayKey, monthCells } from '../lib/date'

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

function VpcForm({ onSubmit, submitting }) {
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

function SubnetForm({ onSubmit, submitting, vpcOptions }) {
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

function IgwForm({ onSubmit, submitting, vpcOptions }) {
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

function RouteTableForm({ onSubmit, submitting, vpcOptions, igwOptions, subnetOptions }) {
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

const FORM_MAP = {
  vpc: VpcForm,
  subnet: SubnetForm,
  ec2_instance: Ec2Form,
  internet_gateway: IgwForm,
  route_table: RouteTableForm,
}

const STATUS_GROUP_ORDER = ['pending', 'approved', 'failed', 'applied', 'rejected']

function MyReqRow({ r }) {
  const [open, setOpen] = useState(false)
  const detail = reqDetailLines(r)
  const d = new Date(r.requested_at)
  const shortDate = `${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`

  return (
    <div className={`ac-myreq ${r.status === 'rejected' ? 'ac-myreq-rejected' : ''}`}>
      <div className="ac-myreq-top" onClick={() => setOpen((v) => !v)}>
        <span className="ac-myreq-title">{reqTitle(r)}</span>
        <span className="ac-myreq-date">{shortDate}</span>
        <span className="ac-expand-icon">{open ? '▲' : '▼'}</span>
      </div>
      {open && (
        <div className="ac-myreq-body">
          {detail.map((line, i) => <div key={i} className="ac-req-reason">{line}</div>)}
          {r.reason && <div className="ac-req-reason">사유: {r.reason}</div>}
          {r.result?.created_id && <div className="ac-req-meta">생성 ID: {r.result.created_id}</div>}
          {r.result?.terraform && <div className="ac-req-meta">🔧 Terraform으로 적용됨</div>}
          {r.status === 'rejected' && r.error_message && (
            <div className="ac-reject-box">거부 사유: {r.error_message}</div>
          )}
          {r.status !== 'rejected' && r.error_message && <div className="ac-req-error">{r.error_message}</div>}
          <div className="ac-req-meta">{d.toLocaleString('ko-KR')}</div>
        </div>
      )}
    </div>
  )
}

function MyReqGrouped({ requests }) {
  const [openGroup, setOpenGroup] = useState('pending')

  const groups = STATUS_GROUP_ORDER.map((status) => {
    const meta = REQ_STATUS_META[status] || { label: status, color: '#94a3b8' }
    const items = requests.filter((r) => r.status === status)
    const byDate = {}
    for (const r of items) {
      const key = localDateKey(r.requested_at)
      if (!byDate[key]) byDate[key] = []
      byDate[key].push(r)
    }
    const dates = Object.entries(byDate).sort((a, b) => b[0].localeCompare(a[0]))
    return { status, meta, items, dates }
  }).filter((g) => g.items.length > 0)

  return (
    <div className="ac-status-groups">
      {groups.map((g) => (
        <div key={g.status} className="ac-sgroup">
          <div
            className={`ac-sgroup-head ${openGroup === g.status ? 'is-open' : ''}`}
            onClick={() => setOpenGroup(openGroup === g.status ? null : g.status)}
          >
            <i className="ac-sgroup-dot" style={{ background: g.meta.color }} />
            <span className="ac-sgroup-label">{g.meta.label}</span>
            <span className="ac-sgroup-count">{g.items.length}건</span>
            <span className="ac-expand-icon">{openGroup === g.status ? '▲' : '▼'}</span>
          </div>
          {openGroup === g.status && (
            <div className="ac-sgroup-body">
              {g.dates.map(([date, items]) => (
                <div key={date} className="ac-sgroup-date">
                  <div className="ac-sgroup-date-label">{date}</div>
                  {items.map((r) => <MyReqRow key={r.id} r={r} />)}
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

function MiniCal({ requests, selected, onSelect }) {
  const today = new Date()
  const base = selected ? new Date(selected + 'T00:00:00') : today
  const [viewDate, setViewDate] = useState(new Date(base.getFullYear(), base.getMonth(), 1))

  const year = viewDate.getFullYear()
  const month = viewDate.getMonth()
  const cells = monthCells(year, month)
  const tKey = todayKey()

  const hasData = new Set()
  for (const r of requests) hasData.add(localDateKey(r.requested_at))

  return (
    <div className="ac-minical">
      <div className="ac-minical-head">
        <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => setViewDate(new Date(year, month - 1, 1))}>‹</button>
        <span className="ac-minical-title">{year}년 {month + 1}월</span>
        <button className="ac-btn ac-btn-secondary ac-cal-nav" onClick={() => setViewDate(new Date(year, month + 1, 1))}>›</button>
      </div>
      <div className="ac-minical-grid">
        {WEEKDAYS.map((w) => <div key={w} className="ac-minical-wday">{w}</div>)}
        {cells.map((d, i) => {
          if (d === null) return <div key={i} className="ac-minical-cell ac-minical-empty" />
          const key = dateKey(year, month, d)
          const has = hasData.has(key)
          const isToday = key === tKey
          const isSel = key === selected
          return (
            <div
              key={i}
              className={`ac-minical-cell ${has ? 'has-data' : ''} ${isToday ? 'is-today' : ''} ${isSel ? 'is-selected' : ''}`}
              onClick={() => has && onSelect(key)}
            >
              {d}
            </div>
          )
        })}
      </div>
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
  const [vpcOptions, setVpcOptions] = useState([])
  const [igwOptions, setIgwOptions] = useState([])
  const [subnetOptions, setSubnetOptions] = useState([])
  const [dateFilter, setDateFilter] = useState('')
  const [calOpen, setCalOpen] = useState(false)
  const [detailReq, setDetailReq] = useState(null)
  const [listError, setListError] = useState(null)
  const [optionsError, setOptionsError] = useState(null)

  const filteredRequests = dateFilter
    ? myRequests.filter((r) => localDateKey(r.requested_at) === dateFilter)
    : myRequests

  const typeKeys = types.map((t) => t.key)

  // 적용 완료된 신청에서 { id, 이름, 소속 VPC } 형태의 선택 옵션을 만든다.
  const optionsFromApplied = (rows, idKey) => rows
    .filter((r) => r.result?.created_id)
    .map((r) => ({
      [idKey]: r.result.created_id,
      name: r.title || r.payload?.name || r.result.created_id,
      vpc_id: r.payload?.vpc_id || '',
    }))

  const fetchVpcOptions = async () => {
    const errors = []
    const vpcMap = new Map()

    // 1) DB: SG 스냅샷에서 VPC ID 추출.
    //    raw_data에 acl-, subnet- 같은 다른 ID도 들어있어서 vpc- 접두사로 걸러야 한다.
    const sg = await fetchRows(
      supabase.from('aws_resource_snapshots')
        .select('raw_data').eq('resource_type', 'security_group')
        .order('collected_at', { ascending: false }).limit(200),
      'VPC 목록(스냅샷)')
    if (sg.error) errors.push(sg.error)
    for (const row of sg.rows) {
      const id = row.raw_data?.VpcId
      if (id && id.startsWith('vpc-') && !vpcMap.has(id)) vpcMap.set(id, { vpc_id: id, name: id })
    }

    // 2) DB: 적용된 VPC 신청에서 이름 보강
    const vpcReqs = await fetchRows(
      supabase.from('aws_requests')
        .select('title, payload, result').eq('resource_type', 'vpc').eq('status', 'applied'),
      'VPC 목록(신청 이력)')
    if (vpcReqs.error) errors.push(vpcReqs.error)
    for (const req of vpcReqs.rows) {
      const id = req.result?.created_id
      if (id) vpcMap.set(id, { vpc_id: id, name: req.title || req.payload?.name || id })
    }

    // 3) AWS API 실시간 조회로 덮어쓰기. 실패해도 위 DB 목록으로 동작해야 하므로 치명적 에러로 보지 않는다.
    const live = await callFunction('aws-list-vpcs')
    if (live.ok) {
      for (const v of (live.vpcs || [])) {
        vpcMap.set(v.vpc_id, { vpc_id: v.vpc_id, name: v.name || v.vpc_id })
      }
    } else {
      console.warn('AWS 실시간 VPC 조회 실패, DB 목록만 사용:', live.error)
    }
    setVpcOptions([...vpcMap.values()])

    const igw = await fetchRows(
      supabase.from('aws_requests')
        .select('title, payload, result').eq('resource_type', 'internet_gateway').eq('status', 'applied'),
      'IGW 목록')
    if (igw.error) errors.push(igw.error)
    setIgwOptions(optionsFromApplied(igw.rows, 'igw_id'))

    const subnet = await fetchRows(
      supabase.from('aws_requests')
        .select('title, payload, result').eq('resource_type', 'subnet').eq('status', 'applied'),
      '서브넷 목록')
    if (subnet.error) errors.push(subnet.error)
    setSubnetOptions(optionsFromApplied(subnet.rows, 'subnet_id'))

    setOptionsError(errors.length ? errors.join(' / ') : null)
  }

  const fetchMyRequests = async () => {
    setLoading(true)
    const { rows, error } = await fetchRows(
      supabase.from('aws_requests').select('*')
        .in('resource_type', typeKeys)
        .order('requested_at', { ascending: false }).limit(50),
      '신청 현황')
    setMyRequests(rows)
    setListError(error)
    setLoading(false)
  }

  useEffect(() => {
    setSelected(types[0].key)
    fetchMyRequests()
    fetchVpcOptions()
  }, [mode])

  const submitRequest = async (req) => {
    setSubmitting(true)
    let me
    try {
      me = await requireUser()
    } catch (e) {
      setSubmitting(false); alert(e.message); return false
    }
    const { error } = await supabase.from('aws_requests').insert({
      ...req,
      status: 'pending',
      requester_id: me.id,
      requester_email: me.email,
    })
    setSubmitting(false)
    if (error) { alert('신청 실패: ' + error.message); return false }
    await fetchMyRequests()
    const actionLabel = ACTION_LABEL[req.action] || req.action
    const detail = summarizePayload(req.action, req.payload)
    notify(`📋 **새 인프라 신청**\n${actionLabel}: ${req.title || ''}\n신청자: ${me.email}${detail ? `\n내용: ${detail}` : ''}${req.reason ? `\n사유: ${req.reason}` : ''}`)
    alert('신청되었습니다. 승인 후 자동 적용됩니다.')
    return true
  }

  const FormComponent = FORM_MAP[selected]

  return (
    <div className="ac-page">
      <h2 className="ac-title">{meta.title}</h2>
      <p className="ac-sub">{meta.sub}</p>

      <ErrorBanner message={optionsError} onRetry={fetchVpcOptions} />
      <ErrorBanner message={listError} onRetry={fetchMyRequests} />

      {!loading && (() => {
        const seenKey = `seen_rejected_infra_${mode}`
        const getSeen = () => { try { return JSON.parse(localStorage.getItem(seenKey) || '[]') } catch { return [] } }
        const rejectedItems = myRequests.filter((r) => r.status === 'rejected' || r.status === 'failed')
        const unseenItems = rejectedItems.filter((r) => !getSeen().includes(r.id))
        if (unseenItems.length === 0) return null
        const dismissOne = (id) => { const s = getSeen(); s.push(id); localStorage.setItem(seenKey, JSON.stringify(s)); setMyRequests([...myRequests]) }
        const dismissAll = () => { localStorage.setItem(seenKey, JSON.stringify(rejectedItems.map((r) => r.id))); setMyRequests([...myRequests]) }
        return (
          <div className="ac-reject-banner">
            <div className="ac-reject-banner-head">
              <span>거부/실패된 신청 {unseenItems.length}건</span>
              {unseenItems.length > 1 && <button className="ac-btn ac-btn-secondary" style={{ padding: '2px 8px', fontSize: 11 }} onClick={dismissAll}>전체 확인</button>}
            </div>
            <div className="ac-reject-banner-list">
              {unseenItems.map((r) => (
                <div key={r.id} className="ac-reject-banner-item" onClick={() => setDetailReq(r)} style={{ cursor: 'pointer' }}>
                  <span className="ac-reject-banner-title">{reqTitle(r)}</span>
                  {r.error_message && <span className="ac-reject-banner-reason">{r.error_message.slice(0, 80)}</span>}
                  <button className="ac-btn ac-btn-secondary" style={{ padding: '2px 6px', fontSize: 10, flexShrink: 0 }} onClick={(e) => { e.stopPropagation(); dismissOne(r.id) }}>확인</button>
                </div>
              ))}
            </div>
          </div>
        )
      })()}

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
          {FormComponent && <FormComponent onSubmit={submitRequest} submitting={submitting} vpcOptions={vpcOptions} igwOptions={igwOptions} subnetOptions={subnetOptions} />}
        </div>

        <div className="ac-card ac-card-wide ac-card-muted">
          <div className="ac-card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ flex: 1 }}>내 신청 현황</span>
            <button className="ac-btn ac-btn-secondary" style={{ padding: '2px 8px', fontSize: 11 }} onClick={() => setCalOpen((v) => !v)}>
              {dateFilter || '날짜 선택'}
            </button>
            {dateFilter && <button className="ac-btn ac-btn-secondary" style={{ padding: '2px 8px', fontSize: 11 }} onClick={() => setDateFilter('')}>전체</button>}
          </div>
          {calOpen && <MiniCal requests={myRequests} selected={dateFilter} onSelect={(d) => { setDateFilter(d); setCalOpen(false) }} />}
          {loading && <div className="ac-empty">불러오는 중...</div>}
          {!loading && filteredRequests.length === 0 && <div className="ac-empty">{dateFilter ? '해당 날짜에 신청 내역이 없습니다.' : '아직 신청 내역이 없습니다.'}</div>}
          {!loading && filteredRequests.length > 0 && <MyReqGrouped requests={filteredRequests} />}
        </div>
      </div>

      {detailReq && (
        <div className="ac-datepop-backdrop" onClick={() => setDetailReq(null)}>
          <div className="ac-modal" onClick={(e) => e.stopPropagation()}>
            <div className="ac-modal-head">
              <span className="ac-modal-title">신청 상세</span>
              <button className="ac-btn ac-btn-secondary" onClick={() => setDetailReq(null)}>닫기</button>
            </div>
            <div className="ac-modal-body">
              <ReqCard r={detailReq} />
              {detailReq.error_message && (
                <div className="ac-reject-box" style={{ marginTop: 12 }}>{detailReq.status === 'rejected' ? '거부 사유' : '에러'}: {detailReq.error_message}</div>
              )}
              <button className="ac-btn" style={{ marginTop: 12, width: '100%' }} onClick={() => setDetailReq(null)}>닫기</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
