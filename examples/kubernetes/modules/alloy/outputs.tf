output "otlp_traces_endpoint" {
  description = "Endpoint where to sent traces via OTLP to"
  value       = "http://alloy.${var.namespace}:4317"
}
