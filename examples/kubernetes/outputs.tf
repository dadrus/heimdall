output "kubeconfig" {
  value       = module.cluster.kubeconfig
  description = "Kubeconfig of the cluster"
}

output "kubeconfig_path" {
  value       = module.cluster.kubeconfig_path
  description = "Path to the Kubeconfig of the cluster"
}

output "endpoint" {
  value       = module.cluster.endpoint
  description = "API server endpoint"
}