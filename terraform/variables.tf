variable "region" {
  default = "ap-northeast-2"
}

variable "vpc_cidr" {
  default = "10.0.0.0/16"
}

variable "subnet_a_cidr" {
  default = "10.0.1.0/24"
}

variable "subnet_b_cidr" {
  default = "10.0.2.0/24"
}

variable "az_a" {
  default = "ap-northeast-2a"
}

variable "az_b" {
  default = "ap-northeast-2c"
}

variable "instance_type" {
  default = "t3.micro"
}
