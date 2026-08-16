# 환경별 역할 — 맡으면(AssumeRole) 임시 자격증명을 받는다.
#
# 영구 키를 사람마다 쥐어주는 대신, 필요할 때 역할을 맡아 몇 시간짜리 키를 받게 한다.
# 역할을 맡는 순간 원래 권한은 버려지고 그 역할의 정책만 적용된다. 합쳐지지 않는다.
# 그래서 dev 역할로 일하는 동안에는 prod 권한이 아예 없다.
#
# 누구에게 줄지는 그룹으로 정한다. 그룹에 넣으면 부여, 빼면 회수다.

variable "require_mfa" {
  description = <<-EOT
    역할을 맡을 때 MFA를 요구할지 여부.

    지금은 계정에 MFA 기기가 없어 false로 둔다. true로 켜면 MFA 없이는
    역할을 맡을 수 없게 되므로, 기기를 등록하기 전에 켜면 스스로 잠긴다.

    등록한 뒤 켜는 방법:
      terraform apply -var require_mfa=true
    또는 이 default를 true로 바꾸면 된다. 신뢰 정책만 갱신되고
    역할·정책·그룹은 그대로 유지된다.
  EOT
  type        = bool
  default     = false
}

locals {
  # 정책과 역할을 짝지어 둔다. 정책은 main.tf에서 이미 만들었다.
  role_policy = {
    dev  = aws_iam_policy.dev.arn
    qa   = aws_iam_policy.qa.arn
    prod = aws_iam_policy.prod.arn
    db   = aws_iam_policy.db.arn
  }
}

# 신뢰 정책 — "이 계정 안의 주체"까지만 열어두고, 실제로 누가 맡을 수 있는지는
# 아래 그룹의 sts:AssumeRole 권한으로 정한다. 사람을 여기 하나씩 적지 않아도 된다.
data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account}:root"]
    }

    dynamic "condition" {
      for_each = var.require_mfa ? [1] : []
      content {
        test     = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values   = ["true"]
      }
    }
  }
}

resource "aws_iam_role" "env" {
  for_each = local.role_policy

  name = "env-${each.key}-role"
  # description은 두지 않는다 — IAM이 ASCII/Latin-1만 받아 한글을 거부한다.
  assume_role_policy = data.aws_iam_policy_document.assume.json

  # 임시 키가 살아 있는 시간. 만료되면 다시 맡아야 한다.
  # CLI는 프로필에 role_arn을 적어두면 알아서 갱신한다.
  max_session_duration = 3600 # 1시간

  tags = {
    Environment = each.key
    ManagedBy   = "terraform"
  }
}

resource "aws_iam_role_policy_attachment" "env" {
  for_each = local.role_policy

  role       = aws_iam_role.env[each.key].name
  policy_arn = each.value
}

/* ─── 부여용 그룹 ────────────────────────────────── */
#
# 그룹에 사용자를 넣으면 그 환경의 역할을 맡을 수 있게 된다.
# 그룹이 주는 권한은 "역할을 맡을 수 있다"뿐이고, 실제로 무엇을 할 수 있는지는
# 역할에 붙은 정책이 정한다.

resource "aws_iam_group" "env" {
  for_each = local.role_policy

  name = "env-${each.key}"
}

data "aws_iam_policy_document" "group_assume" {
  for_each = local.role_policy

  statement {
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.env[each.key].arn]
  }
}

resource "aws_iam_group_policy" "env" {
  for_each = local.role_policy

  name   = "assume-env-${each.key}-role"
  group  = aws_iam_group.env[each.key].name
  policy = data.aws_iam_policy_document.group_assume[each.key].json
}

output "role_arns" {
  description = "CLI 프로필의 role_arn에 넣을 값"
  value       = { for k, r in aws_iam_role.env : k => r.arn }
}

output "grant_groups" {
  description = "사용자를 여기 넣으면 해당 환경 권한이 부여된다"
  value       = { for k, g in aws_iam_group.env : k => g.name }
}
