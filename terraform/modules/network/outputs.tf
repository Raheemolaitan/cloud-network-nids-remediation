output "vpc_id" {
  description = "ID of the isolated test VPC."
  value       = aws_vpc.test.id
}

output "subnet_id" {
  description = "ID of the isolated test subnet."
  value       = aws_subnet.test.id
}

output "vpc_cidr" {
  description = "CIDR range of the test VPC."
  value       = aws_vpc.test.cidr_block
}

output "subnet_cidr" {
  description = "CIDR range of the test subnet."
  value       = aws_subnet.test.cidr_block
}
