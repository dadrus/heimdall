output "otlp_traces_endpoint" {
  description = "Endpoint where to sent traces via OTLP to"
  value       = module.alloy.otlp_traces_endpoint
}

output "otlp_traces_protocol" {
  description = "Protocol to use for sending traces"
  value       = module.alloy.otlp_traces_protocol
}

output "otlp_metrics_endpoint" {
  description = "Endpoint where to sent metrics via OTLP to"
  value       = module.alloy.otlp_metrics_endpoint
}

output "otlp_metrics_protocol" {
  description = "Protocol to use for sending metrics"
  value       = module.alloy.otlp_metrics_protocol
}

output "otlp_logs_endpoint" {
  description = "Endpoint where to sent logs via OTLP to"
  value       = module.alloy.otlp_logs_endpoint
}

output "otlp_logs_protocol" {
  description = "Protocol to use for sending logs"
  value       = module.alloy.otlp_logs_protocol
}