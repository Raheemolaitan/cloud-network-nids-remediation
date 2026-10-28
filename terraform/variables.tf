variable "aws_region" {
  description = "AWS region used by the LocalStack test environment."
  type        = string
  default     = "us-east-1"
}

variable "localstack_endpoint" {
  description = "LocalStack edge endpoint."
  type        = string
  default     = "http://localhost:4566"
}

variable "project_name" {
  description = "Project name used to identify test resources."
  type        = string
  default     = "cloud-network-nids"
}

variable "vpc_cidr" {
  description = "CIDR range for the isolated test VPC."
  type        = string
  default     = "10.250.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR range for the isolated test subnet."
  type        = string
  default     = "10.250.1.0/24"
}
