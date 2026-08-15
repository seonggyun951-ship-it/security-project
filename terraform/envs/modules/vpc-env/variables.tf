variable "name" {
  description = "VPC 이름 (태그와 하위 리소스 이름의 접두사)"
  type        = string
}

variable "environment" {
  description = "환경 구분 태그 — dev / qa / prod / db"
  type        = string
}

variable "cidr" {
  description = "VPC CIDR 대역"
  type        = string
}

# AZ를 키로 쓴다. { "ap-northeast-2a" = "10.1.1.0/24", ... }
# 비워두면 퍼블릭 서브넷과 인터넷 게이트웨이가 아예 생기지 않는다 (vpc-db가 이 경우).
variable "public_subnets" {
  description = "퍼블릭 서브넷 — AZ를 키로 한 CIDR 맵"
  type        = map(string)
  default     = {}
}

variable "private_subnets" {
  description = "프라이빗 서브넷 — AZ를 키로 한 CIDR 맵"
  type        = map(string)
  default     = {}
}
