output "loki_write_url" {
  description = "Loki Write URL"
  value       = "http://loki-write.${var.namespace}.svc.cluster.local:3100"
}

output "loki_read_url" {
  description = "Loki Read URL"
  value       = "http://loki-read.${var.namespace}.svc.cluster.local:3100"
}