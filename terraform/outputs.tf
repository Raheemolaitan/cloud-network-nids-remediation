output "test_vpc_id" {
  description = "ID of the isolated test VPC."
  value       = module.network.vpc_id
}

output "test_subnet_id" {
  description = "ID of the isolated test subnet."
  value       = module.network.subnet_id
}

output "test_network_acl_id" {
  description = "ID of the dedicated test Network ACL."
  value       = module.nacl.network_acl_id
}

output "test_vpc_cidr" {
  value = module.network.vpc_cidr
}

output "test_subnet_cidr" {
  value = module.network.subnet_cidr
}
