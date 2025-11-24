output "tempo_url" {
  description = "Tempo URL"
  value       = "tempo.${var.namespace}.svc.cluster.local:4317"
}