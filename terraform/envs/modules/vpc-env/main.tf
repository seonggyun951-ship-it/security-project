# 환경 하나당 VPC 하나. dev/qa/prod/db가 모두 이 모듈을 쓴다.
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
