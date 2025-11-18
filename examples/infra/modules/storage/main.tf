module "minio_tenant" {
  source = "./minio-tenant"

  count  = var.storage_provider == "minio" ? 1 : 0

  namespace = "monitoring"
}