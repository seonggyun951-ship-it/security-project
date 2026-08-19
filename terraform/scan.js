// AWS 보안 점검 (Prowler)
//
// 하는 일은 목록을 쌓는 게 아니라 고리를 닫는 것이다.
//   점검 → 알림 → 조치 신청 → 승인·적용 → 재점검 → 닫힘 확인
//
// 같은 위반이 매일 새 행으로 쌓이면 "어제부터 있던 건지 오늘 새로 생긴 건지"를 알 수 없다.
// (체크, 리소스) 하나당 한 행만 두고 갱신하며, 다음 점검에서 사라지면 고쳐진 것으로 본다.
//
// 결과의 리소스는 ARN으로 오는데, 끝부분(sg-xxx, acl-xxx)이 우리가 신청 이력에
// 저장해 둔 값과 같은 형식이라 그것으로 주인을 찾는다. 콘솔에서 직접 만든 것은
// 신청 기록이 없어 주인을 알 수 없고, 그런 것은 관리자에게만 알린다.

import { execFileSync } from 'child_process'
import { readdirSync, readFileSync, rmSync, mkdirSync, existsSync } from 'fs'
import { tmpdir } from 'os'
import path from 'path'
import {
  EC2Client, DescribeVpcsCommand, DescribeNetworkAclsCommand,
  DescribeSecurityGroupsCommand, DescribeSubnetsCommand,
} from '@aws-sdk/client-ec2'

// 설정은 모듈을 읽을 때가 아니라 쓸 때 읽는다.
// 최상단에서 읽으면 .env를 나중에 불러오는 호출자에서 값이 비어 있다.
const prowlerExe = () => process.env.PROWLER_EXE
const scanRegion = () => process.env.AWS_REGION || 'ap-northeast-2'
// 점검할 서비스. 비우면 전체를 돌지만 시간이 오래 걸린다.
const scanServices = () => (process.env.SCAN_SERVICES || 'ec2,iam,s3,cloudtrail,vpc')
  .split(',').map((s) => s.trim()).filter(Boolean)

// ARN 끝부분만 남긴다.
//   arn:aws:ec2:ap-northeast-2:170420138507:security-group/sg-08fa... → sg-08fa...
function resourceIdOf(arn, fallback) {
  if (!arn) return fallback || null
  const tail = String(arn).split('/').pop()
  return tail && tail !== arn ? tail : (fallback || arn)
}

function runProwler(outDir) {
  const exe = prowlerExe()
  if (!exe) throw new Error('PROWLER_EXE가 설정되지 않았습니다')

  const args = [
    'aws',
    '--region', scanRegion(),
    '--output-formats', 'json-ocsf',
    '--output-directory', outDir,
    '--no-banner',
  ]
  const services = scanServices()
  if (services.length > 0) args.push('--service', ...services)

  try {
    execFileSync(exe, args, {
      encoding: 'utf8',
      timeout: 30 * 60 * 1000,
      stdio: 'pipe',
      env: {
        ...process.env,
        // Prowler가 진행 표시줄에 쓰는 문자(▉)를 한국어 Windows 기본 인코딩(cp949)이
        // 처리하지 못해 UnicodeEncodeError로 죽는다. 파이프로 받을 때만 나타나는 문제다.
        PYTHONIOENCODING: 'utf-8',
        PYTHONUTF8: '1',
      },
    })
  } catch (e) {
    // Prowler는 위반이 있으면 3으로 끝낸다. 오류가 아니다.
    if (e.status !== 3) {
      // Python 트레이스백은 마지막 줄에 진짜 원인이 있다. 앞을 자르면 그 줄이 사라진다.
      const err = String(e.stderr || e.message)
      const tail = err.split('\n').filter(Boolean).slice(-4).join(' | ')
      console.error('Prowler stderr 전문:\n' + err)
      throw new Error(`Prowler 실행 실패 (code ${e.status}): ${tail.slice(0, 400)}`)
    }
  }

  const file = readdirSync(outDir).find((f) => f.endsWith('.ocsf.json'))
  if (!file) throw new Error('Prowler 결과 파일을 찾지 못했습니다')
  return JSON.parse(readFileSync(path.join(outDir, file), 'utf8'))
}

// 리소스가 어느 VPC(환경)에 속하는지 찾는다.
//
// Prowler 결과에는 VPC 정보가 없다. acl-0b1d... 만 봐서는 dev인지 prod인지 알 수 없어
// 화면에서 "어느 환경 문제인지"를 판단할 수 없다. AWS를 한 번 더 조회해 붙인다.
//
// 조회가 실패해도 점검 자체는 계속한다 — 환경 이름은 있으면 좋은 정보지 필수는 아니다.
async function buildEnvMap() {
  const region = scanRegion()
  const ec2 = new EC2Client({ region })
  const map = new Map()

  try {
    const vpcs = await ec2.send(new DescribeVpcsCommand({}))
    const vpcName = {}
    for (const v of vpcs.Vpcs || []) {
      const tag = (v.Tags || []).find((t) => t.Key === 'Name')?.Value
      vpcName[v.VpcId] = tag || (v.IsDefault ? '기본 VPC' : v.VpcId)
      map.set(v.VpcId, vpcName[v.VpcId])
    }

    const [acls, sgs, subnets] = await Promise.all([
      ec2.send(new DescribeNetworkAclsCommand({})).catch(() => null),
      ec2.send(new DescribeSecurityGroupsCommand({})).catch(() => null),
      ec2.send(new DescribeSubnetsCommand({})).catch(() => null),
    ])
    for (const a of acls?.NetworkAcls || []) map.set(a.NetworkAclId, vpcName[a.VpcId] || a.VpcId)
    for (const s of sgs?.SecurityGroups || []) map.set(s.GroupId, vpcName[s.VpcId] || s.VpcId)
    for (const s of subnets?.Subnets || []) map.set(s.SubnetId, vpcName[s.VpcId] || s.VpcId)
  } catch (e) {
    console.error('환경 정보 조회 실패 (점검은 계속):', e.message)
  }
  return map
}

// 리소스 ID → 그것을 만든 신청. 앱을 거쳐 만들어진 것만 찾을 수 있다.
async function buildOwnerMap(supabase) {
  const { data, error } = await supabase
    .from('aws_requests')
    .select('id, requester_email, target_id, result')
    .eq('status', 'applied')
    .limit(500)
  if (error) throw error

  const map = new Map()
  for (const r of data || []) {
    // 신규 생성은 result.created_id에, 기존 리소스 변경은 target_id에 들어 있다.
    for (const key of [r.result?.created_id, r.result?.web_acl_id, r.target_id]) {
      if (key && !map.has(key)) map.set(key, { request_id: r.id, owner_email: r.requester_email })
    }
  }
  return map
}

export async function runScan(supabase, { notify } = {}) {
  // 임시 폴더에 쓴다. 프로젝트 안에 두면 점 폴더(.scan-out)에 파일을 만들지 못하고,
  // 에이전트 작업 디렉터리에 결과 파일이 섞이기도 한다.
  const outDir = path.join(tmpdir(), `prowler-${Date.now()}`)
  if (existsSync(outDir)) rmSync(outDir, { recursive: true, force: true })
  mkdirSync(outDir, { recursive: true })

  const { data: run, error: runErr } = await supabase
    .from('scan_runs')
    .insert({ provider: 'aws', services: scanServices() })
    .select().single()
  if (runErr) throw runErr

  try {
    const results = runProwler(outDir)
    const fails = results.filter((r) => r.status_code === 'FAIL')
    const passed = results.filter((r) => r.status_code === 'PASS').length

    const [owners, envs] = await Promise.all([
      buildOwnerMap(supabase),
      buildEnvMap(),
    ])
    const now = new Date().toISOString()

    // 이번에 본 (체크, 리소스) 목록. 여기 없는 기존 항목은 고쳐진 것이다.
    //
    // 같은 (체크, 리소스)가 결과에 두 번 나올 수 있다. 리전이 여러 개거나
    // 한 리소스를 여러 관점에서 보는 체크가 겹칠 때 그렇다.
    // upsert에 같은 키를 두 번 넘기면 Postgres가 거부하므로("cannot affect row a second time")
    // 맵에 모아 하나로 합친다. 나중에 온 것이 이긴다 — 어느 쪽이든 같은 위반이다.
    const byKey = new Map()

    for (const f of fails) {
      const res = (f.resources || [])[0] || {}
      const arn = res.uid || null
      const resourceId = resourceIdOf(arn, res.name)
      const checkId = f.metadata?.event_code || String(f.finding_info?.uid || '').split('-')[0]
      if (!checkId || !resourceId) continue

      const owner = owners.get(resourceId) || {}
      byKey.set(`${checkId}::${resourceId}`, {
        check_id: checkId,
        resource_id: resourceId,
        resource_arn: arn,
        region: res.region || scanRegion(),
        severity: String(f.severity || '').toLowerCase(),
        title: f.finding_info?.title || null,
        detail: f.status_detail || null,
        request_id: owner.request_id || null,
        owner_email: owner.owner_email || null,
        environment: envs.get(resourceId) || null,
        last_seen_at: now,
        resolved_at: null,   // 다시 나타났으면 닫힘을 취소한다
      })
    }

    // 이번 점검 전에 열려 있던 것
    const { data: before } = await supabase
      .from('scan_findings')
      .select('check_id, resource_id')
      .is('resolved_at', null)
    const beforeKeys = new Set((before || []).map((b) => `${b.check_id}::${b.resource_id}`))
    const seenKeys = new Set(byKey.keys())
    const rows = [...byKey.values()]

    const newOnes = [...seenKeys].filter((k) => !beforeKeys.has(k))

    // 한 번에 다 보내면 요청이 너무 커진다. 전체 서비스를 돌리면 수백 건이 나온다.
    const CHUNK = 200
    for (let i = 0; i < rows.length; i += CHUNK) {
      const { error } = await supabase
        .from('scan_findings')
        .upsert(rows.slice(i, i + CHUNK), { onConflict: 'check_id,resource_id' })
      if (error) throw error
    }

    // 이번에 안 보인 것 = 고쳐진 것. 조치가 실제로 먹혔는지 확인하는 부분이다.
    //
    // 체크마다 묶어서 한 번에 처리한다. 건별로 보내면 수백 번 왕복하게 된다.
    const goneKeys = [...beforeKeys].filter((k) => !seenKeys.has(k))
    const goneByCheck = new Map()
    for (const key of goneKeys) {
      const [checkId, resourceId] = key.split('::')
      if (!goneByCheck.has(checkId)) goneByCheck.set(checkId, [])
      goneByCheck.get(checkId).push(resourceId)
    }
    for (const [checkId, resourceIds] of goneByCheck) {
      const { error } = await supabase.from('scan_findings')
        .update({ resolved_at: now })
        .eq('check_id', checkId)
        .in('resource_id', resourceIds)
        .is('resolved_at', null)
      if (error) console.error(`해결 표시 실패 (${checkId}):`, error.message)
    }

    await supabase.from('scan_runs').update({
      finished_at: now,
      total: results.length,
      failed: fails.length,
      passed,
      new_findings: newOnes.length,
      resolved_findings: goneKeys.length,
    }).eq('id', run.id)

    if (notify) await sendSummary(notify, { fails, rows, newOnes, goneKeys, passed })

    return { total: results.length, failed: fails.length, passed, new: newOnes.length, resolved: goneKeys.length }
  } catch (e) {
    await supabase.from('scan_runs')
      .update({ finished_at: new Date().toISOString(), error: String(e).slice(0, 500) })
      .eq('id', run.id)
    throw e
  } finally {
    rmSync(outDir, { recursive: true, force: true })
  }
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }

async function sendSummary(notify, { fails, rows, newOnes, goneKeys, passed }) {
  const bySev = {}
  for (const r of rows) bySev[r.severity] = (bySev[r.severity] || 0) + 1
  const sevLine = Object.entries(bySev)
    .sort((a, b) => (SEV_ORDER[a[0]] ?? 9) - (SEV_ORDER[b[0]] ?? 9))
    .map(([k, v]) => `${k} ${v}`).join(' · ') || '없음'

  const lines = [
    `🔍 **AWS 보안 점검** — 위반 ${fails.length}건 / 통과 ${passed}건`,
    `심각도: ${sevLine}`,
  ]

  // 특이사항: 이번에 새로 생긴 것과 이번에 닫힌 것.
  // 어제와 같은 것을 매일 나열하면 아무도 읽지 않는다.
  if (newOnes.length > 0) {
    const newRows = rows
      .filter((r) => newOnes.includes(`${r.check_id}::${r.resource_id}`))
      .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9))
      .slice(0, 6)
    lines.push('', `🆕 **새로 발견 ${newOnes.length}건**`)
    for (const r of newRows) {
      lines.push(`· [${r.severity}] ${r.check_id} — ${r.resource_id}${r.owner_email ? ` (신청자: ${r.owner_email})` : ''}`)
    }
    if (newOnes.length > newRows.length) lines.push(`· 외 ${newOnes.length - newRows.length}건`)
  }

  if (goneKeys.length > 0) {
    lines.push('', `✅ **해결됨 ${goneKeys.length}건**`)
    for (const k of goneKeys.slice(0, 5)) {
      const [check, res] = k.split('::')
      lines.push(`· ${check} — ${res}`)
    }
  }

  if (newOnes.length === 0 && goneKeys.length === 0) {
    lines.push('', '변동 없음 — 어제와 같습니다.')
  }

  await notify(lines.join('\n'))
}
