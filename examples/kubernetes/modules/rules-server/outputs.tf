output "endpoint_url" {
  value = "https://${kubectl_manifest.service.name}.${var.namespace}.svc.cluster.local/rules/echo-app.yaml"
}
