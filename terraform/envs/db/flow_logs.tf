# vpc-db 접근 로그 (VPC Flow Logs)
#
# 개인정보 환경이라 "누가 무엇에 접근했는가"가 남아야 한다.
# 이 VPC는 인터넷 게이트웨이가 없어 외부 통신 자체가 없으므로, 여기 찍히는 것은
# 대부분 내부 접근이다. 거절된 접근(REJECT)이 특히 볼 값어치가 있다.
#
# Flow Logs는 CloudWatch에 쓸 권한을 역할로 넘겨받는다. 그래서 IAM 역할이 함께 필요하다.

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/aws/vpc-flow-logs/vpc-db"
  retention_in_days = 30 # 보관 기간을 두지 않으면 계속 쌓여 요금이 는다

  tags = {
    Environment = "db"
    ManagedBy   = "terraform"
  }
}

# Flow Logs 서비스가 이 역할을 맡아 로그를 쓴다.
data "aws_iam_policy_document" "flow_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "flow" {
  name = "vpc-db-flow-logs-role"
  # description은 두지 않는다 — IAM이 ASCII/Latin-1만 받아 한글을 거부한다.
  # 역할의 목적은 이 파일 상단 주석에 적어두었다.
  assume_role_policy = data.aws_iam_policy_document.flow_assume.json

  tags = {
    Environment = "db"
    ManagedBy   = "terraform"
  }
}

# 이 로그 그룹에만 쓸 수 있게 좁힌다. 다른 로그 그룹은 건드리지 못한다.
data "aws_iam_policy_document" "flow_write" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = ["${aws_cloudwatch_log_group.flow.arn}:*"]
  }
}

resource "aws_iam_role_policy" "flow" {
  name   = "vpc-db-flow-logs-write"
  role   = aws_iam_role.flow.id
  policy = data.aws_iam_policy_document.flow_write.json
}

resource "aws_flow_log" "db" {
  vpc_id          = module.vpc.vpc_id
  traffic_type    = "ALL" # 허용된 것과 거절된 것 모두
  log_destination = aws_cloudwatch_log_group.flow.arn
  iam_role_arn    = aws_iam_role.flow.arn

  tags = {
    Name        = "vpc-db-flow-log"
    Environment = "db"
  }
}

output "flow_log_group" {
  description = "접근 로그가 쌓이는 CloudWatch 로그 그룹"
  value       = aws_cloudwatch_log_group.flow.name
}
