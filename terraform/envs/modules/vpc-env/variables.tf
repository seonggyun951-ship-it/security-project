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

# 기본 NACL에서 SSH(22)를 열어줄 출발지. 비워 두면 22가 아예 안 열린다.
# 0.0.0.0/0을 넣으면 점검(ec2_networkacl_allow_ingress_tcp_port_22)에 걸리므로
# 접속할 곳의 주소를 /32로 적는다.
variable "admin_cidr" {
  description = "SSH를 허용할 관리자 CIDR (예: 1.2.3.4/32). null이면 열지 않음"
  type        = string
  default     = null
}
