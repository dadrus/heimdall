module "cluster" {
  source = "./modules/cluster"

  cluster_provider = var.cluster_provider
}

module "cert_manager" {
  source = "./modules/cert-manager"

  depends_on = [module.cluster]
}

module "minio_operator" {
  source = "./modules/minio"
  count  = var.cluster_provider == "kind" ? 1 : 0

  depends_on = [module.cert_manager]
}

resource "null_resource" "storage_deps" {
  triggers = {
    cluster        = module.cluster.kubeconfig_path
    minio_operator = try(module.minio_operator[0].dummy, "null")
  }
}

module "storage" {
  source = "./modules/storage"

  depends_on = [null_resource.storage_deps]

  storage_provider = var.storage_provider
}

module "observability" {
  source = "./modules/observability"
  count  = var.observability_stack_enabled ? 1 : 0

  depends_on = [module.storage, module.cert_manager]

  s3_endpoint = module.storage.s3_endpoint
  access_key  = module.storage.access_key
  secret_key  = module.storage.secret_key
}

module "ingress_controller" {
  source = "./modules/ingress"

  depends_on = [module.cert_manager]
}
