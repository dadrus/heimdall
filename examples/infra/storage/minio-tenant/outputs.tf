output "minio_console_url" {
  description = "MinIO Console URL (Browser)"
  value       = "https://console.minio.${var.namespace}.svc.cluster.local:9001"
}

output "minio_url" {
  description = "S3 compatible API URL"
  value       = "https://minio-hl.${var.namespace}.svc.cluster.local:9000"
}

output "minio_user" {
  description = "MinIO Tenant User"
  value       = "minio"
  sensitive   = false
}

output "minio_password" {
  description = "MinIO Tenant Password"
  value       = "minio123"  # später natürlich aus Secret!
  sensitive   = true
}

output "minio_tenant_name" {
  value = "minio"
}

output "minio_namespace" {
  value = var.namespace
}