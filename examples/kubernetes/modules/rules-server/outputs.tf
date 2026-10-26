output "endpoint_url" {
  value = "https://${kubectl_manifest.service.name}.${var.namespace}.svc.${var.cluster_domain}/rules/echo-app.yaml"
}
