variable "project_name" {
  description = "Project name used to identify network resources."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR range for the test VPC."
  type        = string
}

variable "subnet_cidr" {
  description = "CIDR range for the test subnet."
  type        = string
}

variable "aws_region" {
  description = "AWS region for the test network."
  type        = string
}
