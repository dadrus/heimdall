output "otlp_traces_endpoint" {
  description = "OTLP/gRPC endpoint for Heimdall traces."
  value       = module.alloy.otlp_traces_endpoint
}

output "scraper_peer" {
  description = "The actual Alloy Pod selector for metrics/profile scraping."
  value       = module.alloy.scraper_peer
}
