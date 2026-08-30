# 환경 하나당 VPC 하나. dev/qa/prod/db가 모두 이 모듈을 쓴다.
#
# 주소 계획 (RFC1918 세 블록을 환경 성격에 따라 나눠 쓴다):
#   vpc-dev   10.10.0.0/16     퍼블릭 10.10.1.0/24, 10.10.2.0/24
#   vpc-qa    10.20.0.0/16     퍼블릭 10.20.1.0/24, 10.20.2.0/24
#   vpc-prod  172.16.0.0/16    퍼블릭 172.16.1.0/24, .2.0/24 · 프라이빗 172.16.11.0/24, .12.0/24
#   vpc-db    192.168.0.0/16   프라이빗 192.168.1.0/24, .2.0/24
#
# 서브넷 셋째 옥텟은 1·2가 퍼블릭, 11·12가 프라이빗이다. 번호만 봐도 성격을 안다.
# 계정 기본 VPC가 172.31.0.0/16을 쓰므로 prod의 172.16.0.0/16과 겹치지 않는다.
#
# 이 대역을 바꾸면 앱의 사내망 판정(src/lib/rules.js의 INTERNAL_CIDRS)도 함께 바꿔야 한다.
#
# 함정 — CIDR을 바꿀 때는 IGW도 같이 교체해야 한다:
#   terraform apply -replace=module.vpc.aws_internet_gateway.this[0]
# CIDR 변경은 VPC 교체(삭제 후 생성)를 부른다. 그런데 IGW는 vpc_id만 바뀌면
# 제자리 수정으로 처리되어 삭제 대상이 아니다. 결과적으로 옛 VPC는 IGW가 붙어 있어
# 못 지우고, IGW는 새 VPC가 생겨야 옮겨갈 수 있어 서로 기다린다.
# 겉으로는 "Still destroying..."만 몇 분씩 찍히다 멈춘 것처럼 보인다.
# IGW를 교체 대상으로 지정하면 IGW → VPC 순으로 지워져 풀린다.
#
# 퍼블릭 서브넷 유무로 성격이 갈린다:
#   public_subnets가 비어 있으면 인터넷 게이트웨이도, 외부로 나가는 경로도 만들지 않는다.
#   vpc-db가 그 경우 — 설정으로 막는 게 아니라 구조적으로 나갈 길이 없게 한다.
#
# NAT 게이트웨이는 두지 않는다. 프리티어에 포함되지 않아 월 $43씩 나가고,
# 권한 분리 실습에는 필요하지 않다. 프라이빗 서브넷은 외부 통신이 없는 상태로 둔다.

locals {
  tags = {
    Environment = var.environment
    ManagedBy   = "terraform"
    Project     = "security-console"
  }
  az_suffix = { for az, cidr in merge(var.public_subnets, var.private_subnets) : az => substr(az, -1, 1) }
}

resource "aws_vpc" "this" {
  cidr_block           = var.cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.tags, { Name = var.name })
}

/* ─── 퍼블릭 ─────────────────────────────────────── */

resource "aws_subnet" "public" {
  for_each = var.public_subnets

  vpc_id                  = aws_vpc.this.id
  cidr_block              = each.value
  availability_zone       = each.key
  map_public_ip_on_launch = true

  tags = merge(local.tags, {
    Name = "${var.name}-public-${local.az_suffix[each.key]}"
    Tier = "public"
  })
}

# 퍼블릭 서브넷이 하나도 없으면 게이트웨이를 만들지 않는다.
resource "aws_internet_gateway" "this" {
  count = length(var.public_subnets) > 0 ? 1 : 0

  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${var.name}-igw" })
}

resource "aws_route_table" "public" {
  count = length(var.public_subnets) > 0 ? 1 : 0

  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this[0].id
  }

  tags = merge(local.tags, { Name = "${var.name}-public-rt" })
}

resource "aws_route_table_association" "public" {
  for_each = var.public_subnets

  subnet_id      = aws_subnet.public[each.key].id
  route_table_id = aws_route_table.public[0].id
}

/* ─── 프라이빗 ───────────────────────────────────── */

resource "aws_subnet" "private" {
  for_each = var.private_subnets

  vpc_id                  = aws_vpc.this.id
  cidr_block              = each.value
  availability_zone       = each.key
  map_public_ip_on_launch = false

  tags = merge(local.tags, {
    Name = "${var.name}-private-${local.az_suffix[each.key]}"
    Tier = "private"
  })
}

# 기본 경로(0.0.0.0/0)를 넣지 않는다. NAT가 없으므로 나갈 곳이 없고,
# VPC 내부 통신만 되는 상태가 된다.
resource "aws_route_table" "private" {
  count = length(var.private_subnets) > 0 ? 1 : 0

  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${var.name}-private-rt" })
}

resource "aws_route_table_association" "private" {
  for_each = var.private_subnets

  subnet_id      = aws_subnet.private[each.key].id
  route_table_id = aws_route_table.private[0].id
}
