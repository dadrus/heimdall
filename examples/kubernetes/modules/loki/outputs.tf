output "loki_gateway_url" {
  description = "Loki gateway URL for ingestion and queries."
  value       = "http://loki-gateway.${var.namespace}.svc.cluster.local"
}
