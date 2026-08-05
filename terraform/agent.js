/**
 * Terraform 로컬 에이전트
 * - Supabase에서 approved 상태의 인프라 신청을 폴링
 * - .tf 파일 자동 생성 → terraform apply 실행 → 결과를 DB에 반영
 *
 * 사용법: node agent.js
 * 환경변수: SUPABASE_URL, SUPABASE_SERVICE_KEY (또는 .env 파일)
 */

import { createClient } from '@supabase/supabase-js'
import { execSync } from 'child_process'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

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
    return
  }
  if (!requests || requests.length === 0) return

  console.log(`\n[${new Date().toLocaleString('ko-KR')}] 처리 대기: ${requests.length}건`)

  for (const req of requests) {
    const gen = GENERATORS[req.resource_type]
    if (!gen) continue

    const tfFile = path.join(__dirname, `req_${req.id.replace(/-/g, '_')}.tf`)
    const tfContent = gen(req.id.replace(/-/g, '_'), req.payload || {})

    console.log(`  → ${req.resource_type}: ${req.title || req.id}`)

    // .tf 파일 생성
    fs.writeFileSync(tfFile, tfContent, 'utf-8')

    // terraform plan
    const plan = runTerraform('plan -no-color -input=false')
    if (!plan.ok) {
      console.log('    plan 실패:', plan.output.slice(0, 200))
      await supabase.from('aws_requests').update({
        status: 'failed',
        error_message: 'terraform plan 실패: ' + plan.output.slice(0, 500),
        applied_at: new Date().toISOString(),
      }).eq('id', req.id)
      fs.unlinkSync(tfFile) // 실패한 .tf 정리
      continue
    }

    // terraform apply
    const apply = runTerraform('apply -auto-approve -no-color -input=false')
    if (!apply.ok) {
      console.log('    apply 실패:', apply.output.slice(0, 200))
      await supabase.from('aws_requests').update({
        status: 'failed',
        error_message: 'terraform apply 실패: ' + apply.output.slice(0, 500),
        applied_at: new Date().toISOString(),
      }).eq('id', req.id)
      // 실패해도 .tf 파일은 남겨둠 (디버깅용)
      continue
    }

    // state에서 생성된 리소스 ID 추출
    let createdId = null
    try {
      const state = runTerraform(`state show aws_${req.resource_type === 'ec2_instance' ? 'instance' : req.resource_type}.req_${req.id.replace(/-/g, '_')} -no-color`)
      const idMatch = state.output.match(/id\s+=\s+"([^"]+)"/)
      if (idMatch) createdId = idMatch[1]
    } catch (_) {}

    console.log('    ✅ 적용 완료', createdId ? `→ ${createdId}` : '')

    await supabase.from('aws_requests').update({
      status: 'applied',
      result: { created_id: createdId, terraform: true },
      applied_at: new Date().toISOString(),
    }).eq('id', req.id)
  }
}

// 시작
console.log('🚀 Terraform 에이전트 시작')
console.log(`   Supabase: ${SUPABASE_URL}`)
console.log(`   Terraform: ${TERRAFORM_EXE}`)
console.log(`   폴링 간격: ${POLL_INTERVAL / 1000}초`)
console.log(`   작업 디렉토리: ${__dirname}`)
console.log('   Ctrl+C로 종료\n')

// 즉시 1회 실행 후 인터벌
await processApproved()
setInterval(processApproved, POLL_INTERVAL)
