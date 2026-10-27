output "kubeconfig_path" {
  description = "Local kubeconfig path for deployment/local and just."
  value       = module.kind.kubeconfig_path
}

output "s3_endpoint" {
  description = "In-cluster S3-compatible endpoint; not reachable directly from the host."
  value       = module.rustfs.s3_endpoint
}

output "storage_namespace" {
  value = module.rustfs.namespace
}

output "rustfs_service_name" {
  value = module.rustfs.service_name
}

output "rustfs_console_port" {
  value = module.rustfs.console_port
}

output "headlamp_namespace" {
  value = module.headlamp.namespace
}

output "headlamp_service_name" {
  value = module.headlamp.service_name
}

output "headlamp_service_port" {
  value = module.headlamp.service_port
}
