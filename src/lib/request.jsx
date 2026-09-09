import { checkRequest } from './rules'

// 신청 화면이 같이 쓰는 것들.
//
// 폼이 아홉 개인데 하는 일은 같다 — 자주 쓰는 값을 눌러 넣고, 적는 동안 점검하고,
// 무엇을 신청하는지 한 줄로 확인한다. 폼마다 따로 만들면 한쪽만 고쳐져 갈라진다.

// ── 자주 쓰는 포트 ──
// 22가 SSH인지 3389가 RDP인지는 신청하는 사람이 알아서 알아야 할 일이 아니다.
export const SG_PRESETS = [
  { label: 'HTTPS', port: '443' },
  { label: 'HTTP', port: '80' },
  { label: 'SSH', port: '22' },
  { label: 'RDP', port: '3389' },
  { label: 'MySQL', port: '3306' },
  { label: 'PostgreSQL', port: '5432' },
]

/** 포트 번호 → 무슨 서비스인지. 직접 적었을 때도 뜻이 보이게 한다. */
export const PORT_NAME = {
  22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 3389: 'RDP',
  3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB',
  1433: 'MSSQL', 21: 'FTP', 23: 'Telnet', 25: 'SMTP',
}

/** 규칙 한 줄을 사람 말로. 요약과 알림에서 같은 문구를 쓴다. */
export function ruleLabel(r) {
  const proto = r.protocol === '-1' ? '전체' : String(r.protocol || '').toUpperCase()
  const port = r.from_port == null ? '전체'
    : r.from_port === r.to_port ? String(r.from_port) : `${r.from_port}-${r.to_port}`
  const arrow = r.direction === 'egress' ? '→' : '←'
  return `${proto} ${port} ${arrow} ${r.cidr}`
}

/**
 * 브라우저에서 보이는 내 공인 IP.
 * 실패하면 null — 못 알아냈다고 신청 자체를 막을 이유는 없다.
 */
export async function myIp() {
  try {
    const res = await fetch('https://api.ipify.org?format=json')
    if (!res.ok) return null
    const j = await res.json()
    return j.ip || null
  } catch {
    return null
  }
}

/**
 * 적는 동안 부르는 점검.
 *
 * 판정은 lib/rules.js가 한다 — 여기서 규칙을 한 벌 더 들면 한쪽만 고쳐져
 * 안내 문구와 실제 판정이 갈라진다(예전에 실제로 그랬다).
 * 달라지는 건 부르는 시점뿐이다. 지금까지는 제출을 누른 뒤에야 창이 떠서,
 * 막히면 되돌아가 고쳐야 했다.
 *
 * 아직 덜 적은 줄은 넘긴다. 입력 도중에 "CIDR이 없습니다"가 뜨면 방해만 된다.
 */
export function liveCheck(action, payload) {
  try {
    const r = checkRequest(action, payload)
    return r?.findings || []
  } catch {
    return []
  }
}

/** 점검 결과 표시. 등급별로 색과 문구가 다르다. */
export function LiveCheck({ findings }) {
  if (!findings || findings.length === 0) return null
  const rank = { critical: 0, high: 1, medium: 2, low: 3 }
  const sorted = [...findings].sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9))

  return (
    <div className="rq-live">
      {sorted.map((f, i) => {
        const hard = f.severity === 'high' || f.severity === 'critical'
        return (
          <div key={i} className={`rq-lv ${hard ? 'is-bad' : 'is-warn'}`}>
            <span className="i">{hard ? '✕' : '!'}</span>
            <span className="tx">
              <span className="h">{hard ? '이대로는 접수되지 않습니다' : '사유를 받고 넘어갑니다'}</span>
              <b>{f.title}</b>
              {f.why && <span className="why">{f.why}</span>}
            </span>
          </div>
        )
      })}
    </div>
  )
}
