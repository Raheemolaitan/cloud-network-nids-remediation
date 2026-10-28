module "network" {
  source = "./modules/network"

  project_name = var.project_name
  vpc_cidr     = var.vpc_cidr
  subnet_cidr  = var.subnet_cidr
  aws_region   = var.aws_region
}

module "nacl" {
  source = "./modules/nacl"

  vpc_id       = module.network.vpc_id
  subnet_id    = module.network.subnet_id
  project_name = var.project_name
}
