output "prometheus_url" {
  description = "Prometheus Server URL (for Remote Write, Alertmanager, etc.)"
  value       = "http://prometheus-server.${var.namespace}.svc.cluster.local:9090"
}
