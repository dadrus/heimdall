output "server_endpoint" {
  value = "http://tempo.${var.namespace}.svc.cluster.local:3200"
}

output "otlp_grpc_receiver_endpoint" {
  value = "tempo.${var.namespace}.svc.cluster.local:4317"
}
