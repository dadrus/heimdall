output "s3_endpoint" {
  value = var.storage_provider == "minio" ? module.minio_tenant[0].minio_url : null
}

output "access_key" {
  value     = var.storage_provider == "minio" ? module.minio_tenant[0].minio_user : null
  sensitive = true
}

output "secret_key" {
  value     = var.storage_provider == "minio" ? module.minio_tenant[0].minio_password : null
  sensitive = true
}