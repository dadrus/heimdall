locals {
  echo_app_rules_prefix = "echo-app/"
}

module "ingress_controller" {
  source = "../ingress"

  namespace                  = "ingress"
  ingress_controller         = var.ingress_controller
  kubeconfig_path            = var.kubeconfig_path
  global_integration_enabled = var.global_integration_enabled
  gateway_api_enabled        = var.gateway_api_enabled
  observability = {
    log_level        = "info"
    metrics_enabled  = var.observability_enabled
    metrics_exporter = "prometheus"
    metrics_endpoint = ""
    metrics_protocol = ""
    tracing_enabled  = var.observability_enabled
    tracing_endpoint = var.observability_enabled ? module.observability[0].otlp_traces_endpoint : ""
    tracing_protocol = "grpc"
  }
}

module "observability" {
  count  = var.observability_enabled ? 1 : 0
  source = "../observability"

  namespace             = "monitoring"
  s3_endpoint           = var.s3_endpoint
  s3_ca_config_map_name = var.s3_ca_config_map_name
  loki_bucket_name      = var.loki_bucket_name
  tempo_bucket_name     = var.tempo_bucket_name
  loki_s3_secret_name   = var.loki_s3_secret_name
  tempo_s3_secret_name  = var.tempo_s3_secret_name
}

module "rules_server" {
  count  = var.rule_provider == "http_endpoint" ? 1 : 0
  source = "../modules/rules-server"

  namespace = "rules-server"
}

module "heimdall" {
  source = "../modules/heimdall"

  depends_on = [module.ingress_controller, module.observability, module.rules_server]

  namespace           = "heimdall"
  ingress_controller  = var.ingress_controller
  rule_provider       = var.rule_provider
  http_rules_endpoint = var.rule_provider == "http_endpoint" ? module.rules_server[0].endpoint_url : ""
  blob_rules_url               = var.blob_rules_url
  blob_rules_prefix            = local.echo_app_rules_prefix
  blob_secret_name             = var.blob_secret_name
  s3_ca_config_map_name        = var.s3_ca_config_map_name
  observability = {
    log_level         = "info"
    log_format        = var.observability_enabled ? "gelf" : "text"
    metrics_enabled   = var.observability_enabled
    metrics_exporter  = "prometheus"
    metrics_endpoint  = "" # Prometheus is scraped via the chart PodMonitor.
    metrics_protocol  = "" # Only used with the OTLP metrics exporter.
    tracing_enabled   = var.observability_enabled
    tracing_exporter  = "otlp"
    tracing_endpoint  = var.observability_enabled ? module.observability[0].otlp_traces_endpoint : ""
    tracing_protocol  = "grpc"
    profiling_enabled = var.observability_enabled
  }
}

module "demo_app" {
  source = "../modules/echo-app"

  depends_on = [module.heimdall]

  namespace                  = "demo"
  ingress_controller         = var.ingress_controller
  global_integration_enabled = var.global_integration_enabled
  gateway_api_enabled        = var.gateway_api_enabled
  rule_provider              = var.rule_provider
  http_rules_namespace       = "rules-server"
  blob_rules_bucket_name     = var.rules_bucket_name
  blob_rules_prefix          = local.echo_app_rules_prefix
  blob_rules_s3_endpoint         = var.s3_endpoint
  blob_rules_s3_ca_config_map_name = var.s3_ca_config_map_name
  blob_rules_s3_region       = var.s3_region
  blob_rules_namespace       = var.blob_rules_namespace
  blob_rules_secret_name     = var.blob_rules_secret_name
}
