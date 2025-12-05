module "minio_tenant" {
  source = "./minio-tenant"

  count = var.storage_provider == "minio" ? 1 : 0

  namespace       = "monitoring"
  kubeconfig_path = var.kubeconfig_path
}
