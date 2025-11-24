output "pyroscope_url" {
  description = "Prometheus Server URL (for Remote Write, Alertmanager, etc.)"
  value       = "http://pyroscope.${var.namespace}.svc.cluster.local:4040"
}