# Shared application layer. The cluster and permanent services live in
# cluster/local and are intentionally not managed by this state.
module "cert_manager" {
  source = "../modules/cert-manager"

  namespace       = "cert-manager"
  metrics_enabled = false
}

module "ingress_controller" {
  source = "../ingress"

  depends_on = [module.cert_manager]

  namespace                  = var.ingress_namespace
  ingress_controller         = var.ingress_controller
  kubeconfig_path            = var.kubeconfig_path
  global_integration_enabled = var.global_integration_enabled
  gateway_api_enabled        = var.gateway_api_enabled
  # Preserve Traefik's existing Prometheus/OTLP integration when OBS is on.
  # The endpoint also orders Traefik's PodMonitor after the monitoring CRDs.
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

# AP 5: an opt-in stack in the same deployment state. The monitoring
# namespace and its S3 credentials are created only when requested.
module "observability" {
  count  = var.observability_enabled ? 1 : 0
  source = "../observability"

  namespace          = "monitoring"
  s3_endpoint        = var.rustfs_s3_endpoint
  rustfs_namespace   = var.rustfs_namespace
  rustfs_secret_name = var.rustfs_secret_name
  loki_bucket_name   = var.loki_bucket_name
  tempo_bucket_name  = var.tempo_bucket_name
}

module "heimdall" {
  source = "../modules/heimdall"

  # The Heimdall chart renders its PodMonitor only after the monitoring CRD exists.
  depends_on = [module.ingress_controller, module.observability]

  namespace          = var.heimdall_namespace
  ingress_controller = var.ingress_controller
  image_repository   = var.heimdall_image_repository
  image_tag          = var.heimdall_image_tag
  image_pull_policy  = var.heimdall_image_pull_policy
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

  namespace                   = var.demo_namespace
  cluster_domain              = var.cluster_domain
  ingress_controller          = var.ingress_controller
  global_integration_enabled  = var.global_integration_enabled
  gateway_api_enabled         = var.gateway_api_enabled
}
