/**
 * 로컬 에이전트
 * - Supabase에서 approved 상태의 인프라 신청을 폴링해 Terraform으로 적용
 * - AWS 보안 점검(Prowler)을 하루 한 번, 그리고 적용 직후에 실행
 *
 * 사용법: node agent.js
 * 환경변수: SUPABASE_URL, SUPABASE_SERVICE_KEY (또는 .env 파일)
 *          PROWLER_EXE — 없으면 보안 점검은 건너뛴다
 */

import { createClient } from '@supabase/supabase-js'
import { execSync } from 'child_process'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { runScan } from './scan.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

// .env 파일 간단 로드
function loadEnv() {
  const envPath = path.join(__dirname, '.env')
  if (fs.existsSync(envPath)) {
    for (const line of fs.readFileSync(envPath, 'utf-8').split('\n')) {
      const m = line.match(/^\s*([^#=]+?)\s*=\s*(.+?)\s*$/)
      if (m) process.env[m[1]] = m[2]
    }
  }
}
loadEnv()

// 웹훅 URL은 .env에만 둔다 (저장소가 공개라 소스에 하드코딩하면 그대로 노출된다).
const DISCORD_WEBHOOK = process.env.DISCORD_WEBHOOK
if (!DISCORD_WEBHOOK) {
  console.warn('⚠️ DISCORD_WEBHOOK 미설정 — Terraform 알림이 전송되지 않습니다 (.env 확인)')
}

async function notifyDiscord(message) {
  if (!DISCORD_WEBHOOK) return
  try {
    const res = await fetch(DISCORD_WEBHOOK, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: message }),
    })
    if (!res.ok) console.error('    Discord 알림 실패:', res.status, await res.text().catch(() => ''))
  } catch (e) {
    console.error('    Discord 알림 에러:', e.message)
  }
}

const SUPABASE_URL = process.env.SUPABASE_URL
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY
if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('SUPABASE_URL, SUPABASE_SERVICE_KEY 환경변수 필요 (.env 파일 또는 환경변수)')
  process.exit(1)
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY)
const TERRAFORM_EXE = process.env.TERRAFORM_EXE || 'terraform'
const POLL_INTERVAL = Number(process.env.POLL_INTERVAL) || 15000 // 15초

// ---- .tf 생성 함수들 ----

function genVpcTf(id, p) {
  const name = p.name || `vpc-${id.slice(0, 8)}`
  return `
resource "aws_vpc" "req_${id.replace(/-/g, '_')}" {
  cidr_block           = "${p.cidr_block || '10.0.0.0/16'}"
  enable_dns_support   = true
  enable_dns_hostnames = ${p.dns_hostnames !== false ? 'true' : 'false'}
  tags = { Name = "${name}" }
}
`
}

function genSubnetTf(id, p) {
  const name = p.name || `subnet-${id.slice(0, 8)}`
  return `
resource "aws_subnet" "req_${id.replace(/-/g, '_')}" {
  vpc_id                  = "${p.vpc_id}"
  cidr_block              = "${p.cidr_block}"
  availability_zone       = "${p.availability_zone || 'ap-northeast-2a'}"
  map_public_ip_on_launch = ${p.public_ip ? 'true' : 'false'}
  tags = { Name = "${name}" }
}
`
}

function genEc2Tf(id, p) {
  const name = p.name || `instance-${id.slice(0, 8)}`
  const userDataBlock = p.user_data
    ? `\n  user_data = <<-EOF\n${p.user_data}\n  EOF`
    : ''
  return `
data "aws_ami" "req_${id.replace(/-/g, '_')}" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "req_${id.replace(/-/g, '_')}" {
  ami                    = data.aws_ami.req_${id.replace(/-/g, '_')}.id
  instance_type          = "${p.instance_type || 't3.micro'}"
  subnet_id              = "${p.subnet_id}"
  vpc_security_group_ids = ${JSON.stringify(p.security_group_ids || [])}${userDataBlock}
  tags = { Name = "${name}" }
}
`
}

function genIgwTf(id, p) {
  const name = p.name || `igw-${id.slice(0, 8)}`
  return `
resource "aws_internet_gateway" "req_${id.replace(/-/g, '_')}" {
  vpc_id = "${p.vpc_id}"
  tags = { Name = "${name}" }
}
`
}

function genRouteTableTf(id, p) {
  const name = p.name || `rt-${id.slice(0, 8)}`
  const routes = (p.routes || []).map((r) => `
  route {
    cidr_block = "${r.cidr_block}"
    gateway_id = "${r.gateway_id}"
  }`).join('')
  const assocs = (p.subnet_ids || []).map((sid, i) => `
resource "aws_route_table_association" "req_${id.replace(/-/g, '_')}_${i}" {
  subnet_id      = "${sid}"
  route_table_id = aws_route_table.req_${id.replace(/-/g, '_')}.id
}
`).join('\n')
  return `
resource "aws_route_table" "req_${id.replace(/-/g, '_')}" {
  vpc_id = "${p.vpc_id}"${routes}
  tags = { Name = "${name}" }
}
${assocs}`
}

const GENERATORS = {
  vpc: genVpcTf,
  subnet: genSubnetTf,
  ec2_instance: genEc2Tf,
  internet_gateway: genIgwTf,
  route_table: genRouteTableTf,
}

// ---- Terraform 실행 ----

function runTerraform(cmd) {
  try {
    const result = execSync(`"${TERRAFORM_EXE}" ${cmd}`, {
      cwd: __dirname,
      encoding: 'utf-8',
      timeout: 120000,
    })
    return { ok: true, output: result }
  } catch (e) {
    return { ok: false, output: e.stderr || e.stdout || String(e) }
  }
}

// 신청 코드에 들어 있는 리소스 주소. plan·apply를 이것들로만 좁힌다(-target).
//
// 폴더 전체를 apply하면 폴더에 남아 있는 다른 코드까지 같이 적용된다. 2026-10-07에
// 8월에 지운 옛 기본 인프라 코드(security-vpc, SSH 전체 개방 SG, EC2 2대)가 남아 있어
// 서브넷 신청 하나에 그 전부를 다시 만들려 했다(VPC 한도에 막혀 EC2까지는 안 갔다).
// 라우팅 테이블 신청은 테이블 + 서브넷 연결 여러 개라 리소스를 전부 뽑는다.
// 데이터 소스(AMI 조회 등)는 Terraform이 의존 관계로 알아서 포함한다.
function targetsOf(tfContent) {
  return [...tfContent.matchAll(/^resource\s+"([^"]+)"\s+"([^"]+)"/gm)].map((m) => `${m[1]}.${m[2]}`)
}

// 그 주소들 중 이미 state에 들어간 것. apply가 실패해도 일부는 만들어졌을 수 있다.
function inState(addresses) {
  const list = runTerraform('state list -no-color')
  if (!list.ok) return []
  const have = new Set(list.output.split('\n').map((s) => s.trim()).filter(Boolean))
  return addresses.filter((a) => have.has(a))
}

// ---- 메인 폴링 루프 ----

async function processApproved() {
  const { data: requests, error } = await supabase
    .from('aws_requests')
    .select('*')
    .eq('status', 'approved')
    .in('resource_type', Object.keys(GENERATORS))
    .order('requested_at', { ascending: true })

  if (error) {
    console.error('폴링 에러:', error.message)
    return 0
  }
  if (!requests || requests.length === 0) return 0

  console.log(`\n[${new Date().toLocaleString('ko-KR')}] 처리 대기: ${requests.length}건`)

  for (const req of requests) {
    const gen = GENERATORS[req.resource_type]
    if (!gen) continue

    const tfFile = path.join(__dirname, `req_${req.id.replace(/-/g, '_')}.tf`)
    const tfContent = gen(req.id.replace(/-/g, '_'), req.payload || {})

    console.log(`  → ${req.resource_type}: ${req.title || req.id}`)

    // .tf 파일 생성
    fs.writeFileSync(tfFile, tfContent, 'utf-8')

    const addresses = targetsOf(tfContent)
    const targetArgs = addresses.map((a) => `-target=${a}`).join(' ')

    // terraform plan — 이 신청의 리소스만
    const plan = runTerraform(`plan -no-color -input=false ${targetArgs}`)
    if (!plan.ok) {
      console.log('    plan 실패:', plan.output.slice(0, 200))
      const { error: dbErr1 } = await supabase.from('aws_requests').update({
        status: 'failed',
        error_message: 'terraform plan 실패: ' + plan.output.slice(0, 500),
        applied_at: new Date().toISOString(),
      }).eq('id', req.id)
      if (dbErr1) console.error('    DB 상태 업데이트 실패:', dbErr1.message)
      await notifyDiscord(`❌ **Terraform plan 실패**\n${req.resource_type}: ${req.title || req.id}\n${plan.output.slice(0, 200)}`)
      fs.unlinkSync(tfFile) // 실패한 .tf 정리
      continue
    }

    // terraform apply — 이 신청의 리소스만
    const apply = runTerraform(`apply -auto-approve -no-color -input=false ${targetArgs}`)
    if (!apply.ok) {
      console.log('    apply 실패:', apply.output.slice(0, 200))
      // 실패해도 일부 리소스는 이미 만들어졌을 수 있다. 그때 코드 파일을 지우면 state에만 남아,
      // 다음 apply에서 '코드에 없는 리소스'로 지워진다(2026-10-07 dev-demo-a가 그럴 뻔했다).
      // 만들어진 게 있으면 파일을 남기고 사람이 보게 알린다.
      const made = inState(addresses)
      const partial = made.length > 0
      const { error: dbErr2 } = await supabase.from('aws_requests').update({
        status: 'failed',
        error_message: (partial
          ? `terraform apply 일부 적용 — 만들어진 리소스: ${made.join(', ')}. 코드 파일을 남겨 두었으니 AWS에서 확인 후 정리하세요.\n`
          : 'terraform apply 실패: ') + apply.output.slice(0, 500),
        applied_at: new Date().toISOString(),
      }).eq('id', req.id)
      if (dbErr2) console.error('    DB 상태 업데이트 실패:', dbErr2.message)
      await notifyDiscord(partial
        ? `⚠️ **Terraform 일부 적용**\n${req.resource_type}: ${req.title || req.id}\n만들어진 리소스: ${made.join(', ')}\n코드 파일을 남겨 두었습니다. AWS에서 확인해주세요.\n${apply.output.slice(0, 200)}`
        : `❌ **Terraform apply 실패**\n${req.resource_type}: ${req.title || req.id}\n${apply.output.slice(0, 200)}`)
      if (!partial) fs.unlinkSync(tfFile) // 아무것도 안 만들어졌을 때만 정리 (재시도 방지)
      else console.log(`    ⚠️ 일부 적용됨 — 코드 파일 유지: ${made.join(', ')}`)
      continue
    }

    // state에서 생성된 리소스 ID 추출.
    // 정규식이 느슨하면 availability_zone_id 같은 다른 '*_id' 필드가 먼저 잡힌다(실제로 서브넷 ID 자리에
    // apne2-az1이 저장돼서 라우팅 테이블 연결이 깨진 적 있음). 줄 시작의 id 필드만 매칭한다.
    let createdId = null
    const resName = `aws_${req.resource_type === 'ec2_instance' ? 'instance' : req.resource_type}.req_${req.id.replace(/-/g, '_')}`
    try {
      const state = runTerraform(`state show ${resName} -no-color`)
      if (!state.ok) {
        console.error('    state show 실패:', state.output.slice(0, 200))
      } else {
        const idMatch = state.output.match(/^\s+id\s+=\s+"([^"]+)"/m)
        if (idMatch) createdId = idMatch[1]
        else console.error('    state에서 id를 찾지 못함:', resName)
      }
    } catch (e) {
      console.error('    ID 추출 에러:', e.message)
    }
    if (!createdId) {
      // ID가 없으면 이후 서브넷/IGW 드롭다운에 이 리소스가 안 뜬다.
      console.error(`    ⚠️ 생성 ID를 확인하지 못했습니다 (${resName}) — 드롭다운 목록에 표시되지 않습니다`)
    }

    console.log('    ✅ 적용 완료', createdId ? `→ ${createdId}` : '')

    const { error: dbErr3 } = await supabase.from('aws_requests').update({
      status: 'applied',
      result: { created_id: createdId, terraform: true },
      applied_at: new Date().toISOString(),
    }).eq('id', req.id)
    if (dbErr3) console.error('    DB 상태 업데이트 실패:', dbErr3.message)

    // 적용 1건당 알림 1건. ID 확인 실패는 별도 알림이 아니라 이 안에 표시한다.
    const idLine = createdId
      ? `\n생성 ID: ${createdId}`
      : '\n⚠️ 생성 ID 확인 실패 — 드롭다운 목록에 안 뜰 수 있습니다'
    await notifyDiscord(`🔧 **Terraform 적용 완료**\n${req.resource_type}: ${req.title || req.id}${idLine}`)
  }

  // 적용이 있었으면 호출한 쪽이 점검을 한 번 돌린다 (조치가 먹혔는지 확인)
  return requests.length
}

// terraform plan+apply는 폴링 간격(기본 15초)보다 오래 걸린다.
// setInterval은 이전 실행을 기다리지 않으므로, 그대로 두면 첫 실행이 DB를 applied로 바꾸기 전에
// 다음 폴링이 같은 approved 건을 집어 두 번 적용하고 알림도 두 번 간다(실제로 발생함).
// 실행 중에는 새 폴링을 건너뛴다.
let running = false

// ---- 보안 점검 ----
//
// 하루 한 번 정기 점검하고, 신청이 적용된 직후에도 한 번 더 돈다.
// 적용 직후 점검이 있어야 조치가 실제로 먹혔는지 바로 확인된다 —
// 다음날까지 기다리면 고쳐졌는지 모른 채 하루를 보낸다.
const SCAN_INTERVAL = Number(process.env.SCAN_INTERVAL) || 24 * 60 * 60 * 1000

// 실패했을 때 얼마 뒤에 다시 볼 것인가.
//
// 전에는 실패해도 시각을 남기지 않아 다음 폴링(15초)에 곧바로 다시 돌았다.
// 안 풀리는 문제면 15초마다 실패 알림이 쌓인다. 절전에서 깨어난 직후가 그렇다 —
// 에이전트는 먼저 살아나는데 Wi-Fi는 몇 초 늦어서 그 틈에 시작하면 실패한다.
//
// 10분씩 세 번(30분) 보고 그래도 안 되면 다음 정기 점검까지 기다린다.
// 잠깐 네트워크가 없는 정도면 그 안에 회복되고, 고쳐야 풀리는 문제라면
// 30분을 더 두드려도 마찬가지라 하루 쉬었다 다시 본다.
const SCAN_RETRY_INTERVAL = 10 * 60 * 1000
const SCAN_MAX_RETRIES = 3

// 성공·실패 모두 '다음에 볼 시각'으로 남긴다. 마지막 성공 시각만 들고 있으면
// 실패가 아무 흔적을 남기지 않아 곧바로 다시 돌게 된다.
let nextScanAt = 0
let scanFailures = 0
let scanning = false
// 적용이 있었으면 다음 tick에서 점검을 한 번 돌린다. 여러 건이 연달아 적용돼도 한 번만 돈다.
let scanRequested = false

async function maybeScan(force = false) {
  if (scanning) return
  if (!process.env.PROWLER_EXE) return // 점검을 안 쓰는 환경이면 조용히 넘어간다
  if (!force && Date.now() < nextScanAt) return

  scanning = true
  try {
    console.log('🔍 보안 점검 시작...')
    const r = await runScan(supabase, { notify: notifyDiscord })
    nextScanAt = Date.now() + SCAN_INTERVAL
    scanFailures = 0
    console.log(`   위반 ${r.failed} / 통과 ${r.passed} · 새로 ${r.new} · 해결 ${r.resolved}`)
  } catch (e) {
    scanFailures++
    const giveUp = scanFailures >= SCAN_MAX_RETRIES
    nextScanAt = Date.now() + (giveUp ? SCAN_INTERVAL : SCAN_RETRY_INTERVAL)

    const when = giveUp
      ? `${SCAN_MAX_RETRIES}번 실패해 다음 정기 점검까지 기다립니다`
      : `${SCAN_RETRY_INTERVAL / 60000}분 뒤 다시 시도합니다 (${scanFailures}/${SCAN_MAX_RETRIES})`
    console.error(`보안 점검 실패: ${e.message} — ${when}`)
    await notifyDiscord(`❌ **보안 점검 실패**\n${String(e.message).slice(0, 300)}\n${when}`)

    // 포기했으면 실패 횟수를 되돌린다. 안 그러면 다음 정기 점검이 한 번 실패했을 때
    // 재시도 없이 곧바로 또 하루를 건너뛴다.
    if (giveUp) scanFailures = 0
  } finally {
    scanning = false
  }
}

async function tick() {
  if (running) return
  running = true
  try {
    const applied = await processApproved()
    if (applied > 0) scanRequested = true
  } catch (e) {
    console.error('폴링 처리 중 예외:', e.message)
  } finally {
    running = false
  }

  // 점검은 폴링 잠금 밖에서 돈다. 몇 분 걸릴 수 있어 그동안 신청 처리가 멈추면 안 된다.
  if (scanRequested) {
    scanRequested = false
    await maybeScan(true)
  } else {
    await maybeScan()
  }
}

// 시작
console.log('🚀 로컬 에이전트 시작')
console.log(`   Supabase: ${SUPABASE_URL}`)
console.log(`   Terraform: ${TERRAFORM_EXE}`)
console.log(`   폴링 간격: ${POLL_INTERVAL / 1000}초`)
console.log(`   작업 디렉토리: ${__dirname}`)
console.log(`   보안 점검: ${process.env.PROWLER_EXE
  ? `${SCAN_INTERVAL / 3600000}시간마다 + 적용 직후`
  : '꺼짐 (PROWLER_EXE 미설정)'}`)
console.log('   Ctrl+C로 종료\n')

// 즉시 1회 실행 후 인터벌 (tick이 중복 실행을 막는다)
await tick()
setInterval(tick, POLL_INTERVAL)
