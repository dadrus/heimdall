module "kind" {
  source = "../modules/kind"
  count  = var.cluster_provider == "kind" ? 1 : 0
}