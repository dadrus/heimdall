output "otlp_traces_endpoint" {
  description = "Endpoint where to sent traces via OTLP to"
  value       = "http://alloy.${var.namespace}:4317"
}

output "scraper_peer" {
  description = "Alloy Pod selector for Heimdall metrics and profiles scraping."
  value = {
    namespace = var.namespace
    labels = tomap({
      "app.kubernetes.io/instance" = "alloy"
      "app.kubernetes.io/name"     = "alloy"
    })
  }
}
