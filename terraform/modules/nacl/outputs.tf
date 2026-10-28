output "network_acl_id" {
  description = "ID of the dedicated test Network ACL."
  value       = aws_network_acl.test.id
}
