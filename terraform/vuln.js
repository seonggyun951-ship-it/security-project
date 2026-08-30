// 웹 취약점 점검 (Nuclei) — 뼈대만 만들어 둔 상태. 아직 어디에서도 부르지 않는다.
//
// 목적은 AWS 안에서 돌아가는 서버를 밖에서 쏘아 보는 것이다. 공격자가 보는 것과
// 같은 자리에서 열린 포트·노출된 경로·알려진 취약점을 찾는다.
//
// 지금 대상이 없다. 계정에 EC2도 로드밸런서도 없어서 쏠 곳이 없고, 서버를 띄우면
// 크레딧이 깎인다(2025-07-15부터 프리티어가 크레딧 차감 방식으로 바뀌었다).
// 그래서 코드만 두고 실행은 나중으로 미뤘다 — 대상이 생기면 주소만 등록하면 된다.
//
// Prowler(scan.js)와 같은 구조를 따른다:
//   (템플릿, 대상) 하나당 한 행을 두고 갱신한다. 매번 새 행을 쌓으면
//   "어제부터 있던 건지 오늘 새로 생긴 건지"를 알 수 없다.
//   다음 점검에서 안 보이면 고쳐진 것으로 본다.
//
// 남은 일:
//   - vuln_targets / vuln_findings 테이블 만들기
//   - saveFindings 채우기 (scan.js의 upsert 방식 그대로)
//   - agent.js에서 호출 (대상이 없으면 건너뛰도록)
//   - VulnScan 화면을 붙여넣기에서 저장된 결과 읽기로 전환
//     (CVE → KEV 대조는 화면에 이미 붙어 있다)

import { execFileSync } from 'child_process'
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'fs'
import { tmpdir } from 'os'
import path from 'path'

// 설정은 모듈을 읽을 때가 아니라 쓸 때 읽는다.
// 최상단에서 읽으면 .env를 나중에 불러오는 호출자에서 값이 비어 있다.
const nucleiExe = () => process.env.NUCLEI_EXE

// 어느 심각도까지 볼 것인가. info는 양이 많고 대부분 조치할 게 없어 기본에서 뺀다.
const severities = () => process.env.VULN_SEVERITIES || 'critical,high,medium,low'

// 한 대상에 오래 매달리지 않게 상한을 둔다. 에이전트가 이것 때문에 멈추면 안 된다.
const timeoutMs = () => Number(process.env.VULN_TIMEOUT_MS) || 10 * 60 * 1000

/**
 * 점검 대상을 가져온다.
 *
 * 코드에 박아두지 않고 DB에서 읽는다 — 서버가 늘거나 주소가 바뀔 때마다
 * 에이전트를 고쳐 배포하게 되면 아무도 안 고친다.
 */
export async function loadTargets(supabase) {
  const { data, error } = await supabase
    .from('vuln_targets').select('id, url, label').eq('enabled', true)
  if (error) throw error
  return data ?? []
}

/**
 * Nuclei를 돌려 결과를 JSONL로 받는다.
 *
 * 결과를 표준출력으로 받지 않고 파일로 쓴다. 진행 표시줄과 로그가 같은 곳으로 나와
 * 섞이기 때문이다(Prowler에서 겪었던 문제와 같다).
 */
function runNuclei(targets) {
  const exe = nucleiExe()
  if (!exe) throw new Error('NUCLEI_EXE가 설정되지 않았습니다')

  const dir = mkdtempSync(path.join(tmpdir(), 'nuclei-'))
  const outFile = path.join(dir, 'result.jsonl')

  const args = [
    '-jsonl', '-output', outFile,
    '-severity', severities(),
    '-no-color',
    '-disable-update-check',   // 점검 중에 업데이트를 받으러 가지 않게
    ...targets.flatMap((t) => ['-target', t.url]),
  ]

  try {
    execFileSync(exe, args, {
      timeout: timeoutMs(),
      stdio: 'ignore',
      // 한국어 Windows(cp949)가 진행 표시 문자를 못 써서 깨진다. Prowler와 같은 처리.
      env: { ...process.env, PYTHONIOENCODING: 'utf-8' },
    })
  } catch (e) {
    // 취약점을 찾으면 0이 아닌 코드로 끝나는 경우가 있다. 결과 파일이 있으면 정상으로 본다.
    if (!existsSync(outFile)) { rmSync(dir, { recursive: true, force: true }); throw e }
  }

  const text = existsSync(outFile) ? readFileSync(outFile, 'utf8') : ''
  rmSync(dir, { recursive: true, force: true })
  return text
}

/**
 * JSONL 한 줄 = 발견 하나. 화면과 DB가 쓰는 형태로 줄인다.
 *
 * CVE는 template-id에 들어 있는 경우가 많다(CVE-2021-44228). 그 값으로
 * 지식 베이스의 KEV를 조회해 "실제 공격에 쓰이는 취약점"인지 표시한다.
 */
export function parseNuclei(text) {
  const out = []
  for (const line of String(text).split('\n')) {
    const s = line.trim()
    if (!s) continue
    let o
    try { o = JSON.parse(s) } catch { continue }
    const info = o.info || {}
    out.push({
      template_id: o['template-id'] || o.templateID || null,
      name: info.name || null,
      severity: (info.severity || 'unknown').toLowerCase(),
      host: o.host || null,
      matched_at: o['matched-at'] || o.matchedAt || null,
      description: info.description || null,
      tags: info.tags || [],
      // 같은 템플릿이 경로만 다르게 여러 번 나온다. 이 둘로 한 건을 구분한다.
      key: `${o['template-id'] || ''}|${o['matched-at'] || o.host || ''}`,
    })
  }
  return out
}

/**
 * 결과를 저장한다. (미구현)
 *
 * scan.js의 방식을 그대로 쓸 자리다 —
 *   있던 것은 last_seen_at 갱신, 없던 것은 새로 넣고,
 *   이번에 안 보인 것은 resolved_at을 찍어 고쳐진 것으로 본다.
 */
export async function saveFindings(/* supabase, targets, findings */) {
  throw new Error('아직 만들지 않았습니다 (vuln_findings 테이블부터 필요)')
}

/**
 * 점검 한 번. 에이전트가 부르는 입구.
 *
 * 대상이 없으면 아무것도 하지 않고 넘어간다. 서버가 생기기 전까지는 이 상태다.
 */
export async function runVulnScan(supabase, { notify } = {}) {
  const targets = await loadTargets(supabase)
  if (targets.length === 0) {
    return { skipped: true, reason: '등록된 점검 대상이 없습니다' }
  }

  const text = runNuclei(targets)
  const findings = parseNuclei(text)
  await saveFindings(supabase, targets, findings)

  if (notify && findings.length > 0) {
    await notify(`🔎 웹 취약점 점검 — 대상 ${targets.length}곳에서 ${findings.length}건`)
  }
  return { skipped: false, targets: targets.length, findings: findings.length }
}
