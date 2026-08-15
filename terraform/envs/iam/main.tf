# 환경별 IAM 정책 — dev / qa / prod / db
#
# VPC ID는 각 환경의 state에 있지만 여기서 참조하지 않는다. 태그로 찾아오면
# state끼리 엮이지 않아서, 환경 하나를 다시 만들어도 이쪽은 손댈 필요가 없다.

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  default = "ap-northeast-2"
}

data "aws_caller_identity" "current" {}

data "aws_vpc" "env" {
  for_each = toset(["vpc-dev", "vpc-qa", "vpc-prod", "vpc-db"])

  filter {
    name   = "tag:Name"
    values = [each.value]
  }
}

locals {
  account = data.aws_caller_identity.current.account_id
  vpc_arn = {
    for name, v in data.aws_vpc.env :
    name => "arn:aws:ec2:${var.region}:${local.account}:vpc/${v.id}"
  }

  # 조회 계열. ec2:Describe*는 리소스 단위 제한이 불가능해 "*"로만 줄 수 있다.
  # 즉 어느 정책을 붙이든 다른 환경의 목록까지 보인다 — IAM의 한계다.
  read_actions = [
    "ec2:Describe*",
    "ec2:GetConsoleOutput",
    "ec2:GetConsoleScreenshot",
  ]

  # RunInstances는 아직 존재하지 않는 리소스(인스턴스·볼륨)를 만들기 때문에
  # ec2:Vpc 조건을 걸 수 없다. 대신 서브넷·보안그룹 쪽에 조건이 걸려 있어
  # 결과적으로 해당 VPC 안에서만 인스턴스를 띄울 수 있다.
  run_instance_resources = [
    "arn:aws:ec2:${var.region}::image/*",
    "arn:aws:ec2:${var.region}::snapshot/*",
    "arn:aws:ec2:${var.region}:${local.account}:instance/*",
    "arn:aws:ec2:${var.region}:${local.account}:volume/*",
    "arn:aws:ec2:${var.region}:${local.account}:network-interface/*",
    "arn:aws:ec2:${var.region}:${local.account}:key-pair/*",
  ]
}

/* ─── dev — vpc-dev 안에서는 자유롭게 ─────────────── */

resource "aws_iam_policy" "dev" {
  name        = "env-dev-policy"
  description = "vpc-dev 범위 안에서만 생성/수정/삭제"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadEverything"
        Effect   = "Allow"
        Action   = local.read_actions
        Resource = "*"
      },
      {
        # ec2:Vpc를 지원하는 리소스(서브넷, 보안그룹, 라우팅테이블,
        # 네트워크 인터페이스, ACL 등)에만 조건이 걸린다.
        Sid      = "ManageInsideDevVpc"
        Effect   = "Allow"
        Action   = ["ec2:*"]
        Resource = "*"
        Condition = {
          StringEquals = { "ec2:Vpc" = local.vpc_arn["vpc-dev"] }
        }
      },
      {
        # VPC 자체를 대상으로 하는 작업 (서브넷 생성, SG 생성, IGW 연결 등)
        Sid      = "ActOnDevVpcItself"
        Effect   = "Allow"
        Action   = ["ec2:*"]
        Resource = local.vpc_arn["vpc-dev"]
      },
      {
        Sid      = "LaunchInstances"
        Effect   = "Allow"
        Action   = ["ec2:RunInstances"]
        Resource = local.run_instance_resources
      },
      {
        Sid      = "TagOnCreate"
        Effect   = "Allow"
        Action   = ["ec2:CreateTags", "ec2:DeleteTags"]
        Resource = "*"
        Condition = {
          StringEquals = { "ec2:Vpc" = local.vpc_arn["vpc-dev"] }
        }
      },
      {
        # VPC는 Terraform이 관리한다. 사람이 지우면 코드와 실제가 어긋난다.
        Sid      = "ProtectManagedVpc"
        Effect   = "Deny"
        Action   = ["ec2:DeleteVpc"]
        Resource = "*"
      },
    ]
  })
}

/* ─── qa — 만들고 고치되 지우지는 못한다 ──────────── */

resource "aws_iam_policy" "qa" {
  name        = "env-qa-policy"
  description = "vpc-qa 범위 안에서 생성/수정 가능, 삭제 불가"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadEverything"
        Effect   = "Allow"
        Action   = local.read_actions
        Resource = "*"
      },
      {
        Sid      = "ManageInsideQaVpc"
        Effect   = "Allow"
        Action   = ["ec2:*"]
        Resource = "*"
        Condition = {
          StringEquals = { "ec2:Vpc" = local.vpc_arn["vpc-qa"] }
        }
      },
      {
        Sid      = "ActOnQaVpcItself"
        Effect   = "Allow"
        Action   = ["ec2:*"]
        Resource = local.vpc_arn["vpc-qa"]
      },
      {
        Sid      = "LaunchInstances"
        Effect   = "Allow"
        Action   = ["ec2:RunInstances"]
        Resource = local.run_instance_resources
      },
      {
        Sid      = "TagOnCreate"
        Effect   = "Allow"
        Action   = ["ec2:CreateTags"]
        Resource = "*"
        Condition = {
          StringEquals = { "ec2:Vpc" = local.vpc_arn["vpc-qa"] }
        }
      },
      {
        # 삭제 금지. Deny는 위의 Allow보다 항상 우선한다.
        # Revoke(규칙 회수)와 Detach(연결 해제)도 사실상 삭제라 같이 막는다.
        Sid    = "DenyAllDeletion"
        Effect = "Deny"
        Action = [
          "ec2:Delete*",
          "ec2:TerminateInstances",
          "ec2:Revoke*",
          "ec2:Detach*",
          "ec2:Disassociate*",
          "ec2:ReleaseAddress",
        ]
        Resource = "*"
      },
    ]
  })
}

/* ─── prod — 조회만. 변경은 신청·승인 자동화로 ────── */

resource "aws_iam_policy" "prod" {
  name        = "env-prod-policy"
  description = "vpc-prod 조회 전용. 변경은 신청-승인 자동화를 통해서만"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadEverything"
        Effect   = "Allow"
        Action   = local.read_actions
        Resource = "*"
      },
      {
        # 다른 정책이 함께 붙어도 prod만은 못 건드리게 하는 잠금장치.
        # ec2:Vpc를 지원하지 않는 조회 계열은 이 조건에 걸리지 않아 그대로 허용된다.
        Sid      = "DenyAnyChangeInProdVpc"
        Effect   = "Deny"
        Action   = ["ec2:*"]
        Resource = "*"
        Condition = {
          StringEquals = { "ec2:Vpc" = local.vpc_arn["vpc-prod"] }
        }
      },
      {
        Sid      = "DenyChangeOnProdVpcItself"
        Effect   = "Deny"
        Action   = ["ec2:*"]
        Resource = local.vpc_arn["vpc-prod"]
      },
    ]
  })
}

/* ─── db — 조회만. 소수에게만 부여 ────────────────── */

resource "aws_iam_policy" "db" {
  name        = "env-db-policy"
  description = "vpc-db 조회 전용. 개인정보 환경이라 부여 대상을 최소화한다"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadEverything"
        Effect   = "Allow"
        Action   = local.read_actions
        Resource = "*"
      },
      {
        Sid      = "DenyAnyChangeInDbVpc"
        Effect   = "Deny"
        Action   = ["ec2:*"]
        Resource = "*"
        Condition = {
          StringEquals = { "ec2:Vpc" = local.vpc_arn["vpc-db"] }
        }
      },
      {
        Sid      = "DenyChangeOnDbVpcItself"
        Effect   = "Deny"
        Action   = ["ec2:*"]
        Resource = local.vpc_arn["vpc-db"]
      },
    ]
  })
}

output "policy_arns" {
  value = {
    dev  = aws_iam_policy.dev.arn
    qa   = aws_iam_policy.qa.arn
    prod = aws_iam_policy.prod.arn
    db   = aws_iam_policy.db.arn
  }
}

output "scoped_vpcs" {
  description = "각 정책이 제한하는 VPC"
  value       = { for name, v in data.aws_vpc.env : name => v.id }
}
