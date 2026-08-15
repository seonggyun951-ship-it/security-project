# 개인정보 보호 환경 — 프라이빗 서브넷만.
#
# public_subnets를 넘기지 않으므로 인터넷 게이트웨이가 아예 만들어지지 않는다.
# 설정으로 막는 게 아니라 나갈 길 자체를 두지 않는 방식이다. 실수로 퍼블릭 IP를
# 켜더라도 경로가 없어 외부와 통신할 수 없다.
#
# 접근 로그(VPC Flow Logs)는 CloudWatch에 쓸 IAM 역할이 필요해 여기서는 만들지 않았다.
# IAM은 2단계에서 함께 다룬다.
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

  name        = "vpc-db"
  environment = "db"
  cidr        = "10.4.0.0/16"

  private_subnets = {
    "ap-northeast-2a" = "10.4.1.0/24"
    "ap-northeast-2c" = "10.4.2.0/24"
  }
}

output "vpc_id" { value = module.vpc.vpc_id }
output "private_subnet_ids" { value = module.vpc.private_subnet_ids }
output "has_internet_access" { value = module.vpc.has_internet_access }
