# 운영 환경 — 퍼블릭과 프라이빗을 나눈다.
# 프라이빗 서브넷은 NAT가 없어 외부로 나가지 못한다. 내부 통신 전용이다.
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

  name        = "vpc-prod"
  environment = "prod"
  cidr        = "172.16.0.0/16"

  public_subnets = {
    "ap-northeast-2a" = "172.16.1.0/24"
    "ap-northeast-2c" = "172.16.2.0/24"
  }

  private_subnets = {
    "ap-northeast-2a" = "172.16.11.0/24"
    "ap-northeast-2c" = "172.16.12.0/24"
  }
}

output "vpc_id" { value = module.vpc.vpc_id }
output "public_subnet_ids" { value = module.vpc.public_subnet_ids }
output "private_subnet_ids" { value = module.vpc.private_subnet_ids }
