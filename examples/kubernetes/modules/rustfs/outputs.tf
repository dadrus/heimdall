# The RustFS 1.0.1 chart uses <release-name>-svc for its Service.
locals {
  service_name = "${helm_release.rustfs.name}-svc"
}

output "s3_endpoint" {
  value = "https://${local.service_name}.${kubernetes_namespace_v1.rustfs.metadata[0].name}.svc.cluster.local:${var.s3_port}"
}

output "namespace" {
  value = kubernetes_namespace_v1.rustfs.metadata[0].name
}

output "service_name" {
  value = local.service_name
}

output "console_port" {
  value = var.console_port
}
