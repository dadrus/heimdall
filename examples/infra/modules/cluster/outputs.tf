output "kubeconfig" {
  value = var.cluster_provider == "kind" ? module.kind[0].kubeconfig :  null
}

output "kubeconfig_path" {
  value = var.cluster_provider == "kind" ? module.kind[0].kubeconfig_path :  null
}

output "endpoint" {
  value = var.cluster_provider == "kind" ? module.kind[0].endpoint :  null
}

output "client_certificate" {
  value = var.cluster_provider == "kind" ? module.kind[0].client_certificate : null
}

output "client_key" {
  value = var.cluster_provider == "kind" ? module.kind[0].client_key : null
}

output "cluster_ca_certificate" {
  value = var.cluster_provider == "kind" ? module.kind[0].cluster_ca_certificate :  null
}