# 개인정보 DB 환경 — 프라이빗 서브넷만. vpc-db와 같은 격리 방식이되 별도 VPC다.
#
# 왜 vpc-db와 나누는가:
#   일반 DB와 개인정보 DB를 같은 대역에 두면 접근 통제·감사 로그가 섞인다.
#   개인정보처리시스템은 별도 경계로 격리해야 한다(ISMS-P 접근통제·망분리).
#   계정을 못 나누므로 VPC로 나눈다 — 별도 SG/NACL.
#
# public_subnets를 넘기지 않으므로 인터넷 게이트웨이가 아예 만들어지지 않는다.
# 나갈 길 자체가 없어, 실수로 퍼블릭 IP를 켜도 외부와 통신할 수 없다.
#
# 골격만 둔다. 돈 나가는 것은 지금 만들지 않는다:
#   - 앱(prod)에서 이 DB에 닿는 경로(PrivateLink + DB 접근제어)
#   - 접속기록(VPC Flow Logs → CloudWatch, 트래픽만큼 과금)
# 마지막 달 데모 때 함께 켠다.
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

module "vpc" {
  source = "../modules/vpc-env"

  name        = "vpc-pii"
  environment = "pii"
  cidr        = "10.99.0.0/16"

  private_subnets = {
    "ap-northeast-2a" = "10.99.1.0/24"
    "ap-northeast-2c" = "10.99.2.0/24"
  }
}

output "vpc_id" { value = module.vpc.vpc_id }
output "private_subnet_ids" { value = module.vpc.private_subnet_ids }
output "has_internet_access" { value = module.vpc.has_internet_access }
