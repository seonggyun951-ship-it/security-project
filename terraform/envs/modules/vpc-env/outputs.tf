output "vpc_id" {
  description = "생성된 VPC ID"
  value       = aws_vpc.this.id
}

output "vpc_cidr" {
  value = aws_vpc.this.cidr_block
}

output "public_subnet_ids" {
  description = "퍼블릭 서브넷 ID — 없으면 빈 맵"
  value       = { for az, s in aws_subnet.public : az => s.id }
}

output "private_subnet_ids" {
  description = "프라이빗 서브넷 ID — 없으면 빈 맵"
  value       = { for az, s in aws_subnet.private : az => s.id }
}

output "has_internet_access" {
  description = "인터넷 게이트웨이 유무. db 환경은 false여야 한다."
  value       = length(aws_internet_gateway.this) > 0
}
