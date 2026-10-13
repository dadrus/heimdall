output "namespace" {
  value = kubernetes_namespace_v1.rules_server.metadata[0].name
}

output "rules_configmap_name" {
  value = var.rules_configmap_name
}

output "endpoint_url" {
  value = "https://${kubectl_manifest.service.name}.${var.namespace}.svc.${var.cluster_domain}/rules/echo-app.yaml"
}
