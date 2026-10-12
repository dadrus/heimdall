output "namespace" {
  value = kubernetes_namespace_v1.headlamp.metadata[0].name
}

output "service_name" {
  value = helm_release.headlamp.name
}

output "service_port" {
  value = var.service_port
}
