output "otlp_traces_endpoint" {
  description = "OTLP/gRPC endpoint for Heimdall traces."
  value       = module.alloy.otlp_traces_endpoint
}
