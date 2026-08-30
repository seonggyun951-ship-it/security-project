# QA 환경 — 퍼블릭 서브넷만. 구조는 dev와 같고 권한 정책에서 갈린다(2단계).
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

  name        = "vpc-qa"
  environment = "qa"
  cidr        = "10.20.0.0/16"

  public_subnets = {
    "ap-northeast-2a" = "10.20.1.0/24"
    "ap-northeast-2c" = "10.20.2.0/24"
  }
}

output "vpc_id" { value = module.vpc.vpc_id }
output "public_subnet_ids" { value = module.vpc.public_subnet_ids }
