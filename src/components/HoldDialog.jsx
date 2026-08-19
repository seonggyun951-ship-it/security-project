import { useState } from 'react'

// 점검 결과를 잠시 목록에서 내린다.
//
//   보류  나중에 조치한다. 기한이 지나면 다시 조치 필요로 돌아온다.
//   예외  조치하지 않기로 한다. 바꿀 수 없거나 감수하는 항목.
//
// 예외에도 기한을 두는 이유는 영구 예외가 결국 잊히기 때문이다.
// 1년 뒤에는 상황이 달라져 있을 수 있어 그때 다시 판단하게 한다.

const OPTIONS = {
  defer: [
    { days: 7, label: '1주' },
    { days: 14, label: '2주' },
    { days: 30, label: '1개월' },
    { days: 92, label: '3개월' },
  ],
  exception: [
    { days: 30, label: '1개월' },
    { days: 92, label: '3개월' },
    { days: 183, label: '6개월' },
    { days: 365, label: '1년' },
  ],
}

const META = {
  defer: {
    title: '보류',
    desc: '지금은 조치하지 않고 미룹니다. 기한이 지나면 다시 조치 필요 목록에 올라옵니다.',
    placeholder: '예: 다음 배포 때 함께 정리 예정',
  },
  exception: {
    title: '예외 처리',
    desc: '조치하지 않기로 합니다. 바꿀 수 없거나 감수하는 항목에 씁니다. 기한이 지나면 다시 판단하도록 목록에 올라옵니다.',
    placeholder: '예: 기본 VPC의 NACL이라 삭제할 수 없음',
  },
}

export default function HoldDialog({ kind, target, onCancel, onConfirm }) {
  const meta = META[kind]
  const opts = OPTIONS[kind]
  const [days, setDays] = useState(opts[kind === 'defer' ? 0 : 1].days)
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async () => {
    if (!reason.trim()) return alert('사유는 필수입니다')
    setBusy(true)
    await onConfirm({ days, reason: reason.trim() })
    setBusy(false)
  }

  const until = new Date(Date.now() + days * 86400000)

  return (
    <div className="ac-datepop-backdrop" onClick={onCancel}>
      <div className="ac-datepop hd" onClick={(e) => e.stopPropagation()}>
        <div className="hd-title">{meta.title}</div>
        <p className="hd-desc">{meta.desc}</p>

        {target && (
          <div className="hd-target">
            <span className="hd-target-check">{target.label}</span>
            <span className="hd-target-res">{target.resource_id}</span>
          </div>
        )}

        <div className="ac-form-row">
          <div className="ac-field">
            <label className="ac-label">기간</label>
            <div className="hd-opts">
              {opts.map((o) => (
                <button key={o.days}
                  className={`hd-opt ${days === o.days ? 'on' : ''}`}
                  onClick={() => setDays(o.days)}>
                  {o.label}
                </button>
              ))}
            </div>
            <p className="ac-sub" style={{ marginTop: 6, marginBottom: 0 }}>
              {until.toLocaleDateString('ko-KR')}까지 — 이후 다시 목록에 올라옵니다
            </p>
          </div>
        </div>

        <div className="ac-form-row">
          <div className="ac-field">
            <label className="ac-label">사유</label>
            <input className="ac-input" autoFocus
              placeholder={meta.placeholder}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && submit()} />
          </div>
        </div>

        <div className="ac-datepop-actions">
          <button className="ac-btn" disabled={busy} onClick={submit}>
            {busy ? '처리 중...' : meta.title}
          </button>
          <button className="ac-btn ac-btn-secondary" disabled={busy} onClick={onCancel}>취소</button>
        </div>
      </div>
    </div>
  )
}
