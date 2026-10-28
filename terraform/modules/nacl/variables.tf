variable "vpc_id" {
  description = "VPC protected by this Network ACL."
  type        = string
}

variable "subnet_id" {
  description = "Subnet associated with this Network ACL."
  type        = string
}

variable "project_name" {
  description = "Project name used to identify resources."
  type        = string
}
