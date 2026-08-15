# 개발 환경 — 퍼블릭 서브넷만. 자유롭게 만들고 지우는 곳.
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

  name        = "vpc-dev"
  environment = "dev"
  cidr        = "10.1.0.0/16"

  public_subnets = {
    "ap-northeast-2a" = "10.1.1.0/24"
    "ap-northeast-2c" = "10.1.2.0/24"
  }
}

output "vpc_id" { value = module.vpc.vpc_id }
output "public_subnet_ids" { value = module.vpc.public_subnet_ids }
