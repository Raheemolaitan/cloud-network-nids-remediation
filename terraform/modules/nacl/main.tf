resource "aws_network_acl" "test" {
  vpc_id = var.vpc_id

  tags = {
    Name        = "${var.project_name}-test-nacl"
    Environment = "local-test"
    ManagedBy   = "Terraform"
  }
}

resource "aws_network_acl_association" "test" {
  network_acl_id = aws_network_acl.test.id
  subnet_id      = var.subnet_id
}

resource "aws_network_acl_rule" "allow_all_ingress" {
  network_acl_id = aws_network_acl.test.id
  rule_number    = 200
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  egress         = false
}

resource "aws_network_acl_rule" "allow_all_egress" {
  network_acl_id = aws_network_acl.test.id
  rule_number    = 200
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  egress         = true
}
