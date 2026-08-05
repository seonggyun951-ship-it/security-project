output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_ids" {
  value = [aws_subnet.public_a.id, aws_subnet.public_b.id]
}

output "security_group_id" {
  value = aws_security_group.web.id
}

output "instance_a_public_ip" {
  value = aws_instance.web_a.public_ip
}

output "instance_b_public_ip" {
  value = aws_instance.web_b.public_ip
}
