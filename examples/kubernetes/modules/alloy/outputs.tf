output "otlp_traces_endpoint" {
  description = "Endpoint where to sent traces via OTLP to"
  value       = "http://alloy.${var.namespace}:4317"
}

output "otlp_traces_protocol" {
  description = "Protocol to use for sending traces"
  value       = "grpc"
}

output "otlp_metrics_endpoint" {
  description = "Endpoint where to sent metrics via OTLP to"
  value       = "http://alloy.${var.namespace}:4317"
}

output "otlp_metrics_protocol" {
  description = "Protocol to use for sending metrics"
  value       = "grpc"
}

output "otlp_logs_endpoint" {
  description = "Endpoint where to sent logs via OTLP to"
  value       = "http://alloy.${var.namespace}:4317"
}

output "otlp_logs_protocol" {
  description = "Protocol to use for sending logs"
  value       = "grpc"
}