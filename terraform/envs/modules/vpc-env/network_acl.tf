# 기본 네트워크 ACL.
#
# AWS가 VPC마다 자동으로 만드는 기본 NACL은 **인바운드·아웃바운드 모두 전체 허용**이다.
# 그래서 아무것도 안 해도 Prowler의 다음 세 체크가 전부 걸린다:
#   ec2_networkacl_allow_ingress_any_port / _tcp_port_22 / _tcp_port_3389
#
# NACL은 SG와 달리 **스테이트리스**다. 나간 요청의 응답이 자동으로 돌아오지 않으므로
# 응답이 도착하는 임시 포트(1024-65535)를 인바운드로 열어줘야 한다. 이걸 빼면
# 인스턴스에서 밖으로 나가는 통신이 전부 먹통이 된다.
#
# 그런데 임시 포트 범위에 **3389(RDP)가 들어간다.** 그래서 더 낮은 번호에 3389 거부를
# 먼저 둔다 — NACL은 규칙 번호 순으로 먼저 맞는 것 하나만 적용한다.
# 22(SSH)는 1024 미만이라 범위 밖이고, 필요하면 admin_cidr로만 연다.
#
# 주의: subnet_ids를 비워 두면 Terraform이 기본 NACL에서 서브넷을 떼어내려 하는데
# AWS는 그걸 허용하지 않는다(어느 NACL에도 안 붙은 서브넷은 존재할 수 없다).
# 이 VPC의 서브넷을 전부 명시한다.

locals {
  # 퍼블릭 서브넷이 없는 VPC(vpc-db)는 인터넷과 주고받을 일이 없다.
  # 웹 인바운드도, 외부로 나가는 아웃바운드도 열지 않는다.
  has_public = length(var.public_subnets) > 0

  # 임시 포트 범위(1024-65535)에 딸려 들어오는 민감 포트.
  # 앱의 판정 엔진(src/lib/rules.js의 SENSITIVE_PORTS)과 같은 목록이어야 한다.
  # 22는 여기 없다 — 1024 미만이라 임시 포트 범위 밖이고, admin_cidr 규칙으로 따로 다룬다.
  sensitive_ports = [3389, 3306, 5432, 1433, 6379, 27017]

  all_subnet_ids = concat(
    [for s in aws_subnet.public : s.id],
    [for s in aws_subnet.private : s.id],
  )
}

resource "aws_default_network_acl" "this" {
  default_network_acl_id = aws_vpc.this.default_network_acl_id
  subnet_ids             = local.all_subnet_ids

  /* ─── 인바운드 ─────────────────────────────────── */
  #
  # 번호 순서가 곧 정책이다. 낮은 번호부터 먼저 맞는 하나만 적용된다.
  #   10   관리자 SSH        ← 거부보다 앞에 둬야 아래 22 차단에 걸리지 않는다
  #   20   VPC 내부 전체     ← 거부보다 앞에 둬야 내부 DB 통신이 살아 있다
  #   80~  민감 포트 거부    ← 출발지가 0.0.0.0/0이라 내부 주소도 함께 걸린다
  #   100~ 웹 + 임시 포트

  # SSH는 지정한 주소에서만. admin_cidr가 비어 있으면 규칙 자체가 없다(= 차단).
  dynamic "ingress" {
    for_each = var.admin_cidr == null ? [] : [var.admin_cidr]
    content {
      rule_no    = 10
      action     = "allow"
      protocol   = "tcp"
      from_port  = 22
      to_port    = 22
      cidr_block = ingress.value
    }
  }

  # VPC 내부 통신은 전부 허용. 아래 거부 규칙보다 반드시 앞에 있어야 한다 —
  # 거부는 0.0.0.0/0을 대상으로 하므로 내부 주소도 매칭된다.
  ingress {
    rule_no    = 20
    action     = "allow"
    protocol   = "-1"
    from_port  = 0
    to_port    = 0
    cidr_block = var.cidr
  }

  # 임시 포트 범위에 딸려 들어오는 민감 포트를 앞에서 잘라낸다.
  # 이 규칙이 없으면 아래 1024-65535 허용이 RDP·DB 포트까지 열어버린다.
  dynamic "ingress" {
    for_each = local.has_public ? { for i, p in local.sensitive_ports : p => 80 + i } : {}
    content {
      rule_no    = ingress.value
      action     = "deny"
      protocol   = "tcp"
      from_port  = ingress.key
      to_port    = ingress.key
      cidr_block = "0.0.0.0/0"
    }
  }

  dynamic "ingress" {
    for_each = local.has_public ? [80, 443] : []
    content {
      rule_no    = 100 + index([80, 443], ingress.value) * 10
      action     = "allow"
      protocol   = "tcp"
      from_port  = ingress.value
      to_port    = ingress.value
      cidr_block = "0.0.0.0/0"
    }
  }

  # 나간 요청의 응답이 돌아오는 자리. 스테이트리스라서 필요하다.
  dynamic "ingress" {
    for_each = local.has_public ? [1] : []
    content {
      rule_no    = 120
      action     = "allow"
      protocol   = "tcp"
      from_port  = 1024
      to_port    = 65535
      cidr_block = "0.0.0.0/0"
    }
  }

  /* ─── 아웃바운드 ───────────────────────────────── */

  # 퍼블릭이 있는 VPC만 밖으로 내보낸다. vpc-db는 VPC 안에서만 오간다
  # (라우팅에도 0.0.0.0/0 경로가 없지만, 여기서도 같은 뜻을 한 번 더 적어 둔다).
  egress {
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    from_port  = 0
    to_port    = 0
    cidr_block = local.has_public ? "0.0.0.0/0" : var.cidr
  }

  tags = merge(local.tags, { Name = "${var.name}-default-nacl" })
}
