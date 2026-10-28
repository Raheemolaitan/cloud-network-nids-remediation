resource "aws_vpc" "test" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = "${var.project_name}-test-vpc"
    Environment = "local-test"
    ManagedBy   = "Terraform"
  }
}

resource "aws_subnet" "test" {
  vpc_id                  = aws_vpc.test.id
  cidr_block              = var.subnet_cidr
  map_public_ip_on_launch = false

  tags = {
    Name        = "${var.project_name}-test-subnet"
    Environment = "local-test"
    ManagedBy   = "Terraform"
  }
}
