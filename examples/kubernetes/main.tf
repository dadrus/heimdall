module "cluster" {
  source = "./cluster"

  cluster_provider = var.cluster_provider
}

module "cert_manager" {
  source = "./modules/cert-manager"

  depends_on = [module.cluster]
}

module "minio_operator" {
  source = "./modules/minio"
  count  = var.cluster_provider == "kind" ? 1 : 0

  depends_on = [module.cert_manager]
}

resource "null_resource" "storage_deps" {
  triggers = {
    cluster        = module.cluster.kubeconfig_path
    minio_operator = try(module.minio_operator[0].dummy, "null")
  }
}

module "storage" {
  source = "./storage"

  depends_on = [module.cluster, null_resource.storage_deps]

  kubeconfig_path  = module.cluster.kubeconfig_path
  storage_provider = var.storage_provider
}

module "observability" {
  source = "./observability"
  count  = var.observability_stack_enabled ? 1 : 0

  depends_on = [module.storage, module.cert_manager]

  s3_endpoint = module.storage.s3_endpoint
  access_key  = module.storage.access_key
  secret_key  = module.storage.secret_key
}

module "ingress_controller" {
  source = "./ingress"

  depends_on = [module.cert_manager]

  namespace                  = "ingress"
  ingress_controller         = var.ingress_controller
  kubeconfig_path            = module.cluster.kubeconfig_path
  global_integration_enabled = var.global_integration_enabled
  gateway_api_enabled        = var.gateway_api_enabled
  observability = {
    metrics_enabled  = var.observability_stack_enabled
    metrics_exporter = "prometheus" # "otlp"
    metrics_endpoint = var.observability_stack_enabled ? module.observability[0].otlp_metrics_endpoint : ""
    metrics_protocol = var.observability_stack_enabled ? module.observability[0].otlp_metrics_protocol : ""
    tracing_enabled  = var.observability_stack_enabled
    tracing_endpoint = var.observability_stack_enabled ? module.observability[0].otlp_traces_endpoint : ""
    tracing_protocol = var.observability_stack_enabled ? module.observability[0].otlp_traces_protocol : ""
    log_level        = "debug" # "debug", "info", "warn", "info", "error"
  }
}

module "heimdall" {
  source = "./modules/heimdall"

  depends_on = [
    module.cluster,
    module.cert_manager,
    module.ingress_controller,
  ]

  namespace          = "heimdall"
  ingress_controller = var.ingress_controller
  observability = {
    metrics_enabled   = var.observability_stack_enabled
    metrics_exporter  = "prometheus" # "otlp"
    metrics_endpoint  = var.observability_stack_enabled ? module.observability[0].otlp_metrics_endpoint : ""
    metrics_protocol  = var.observability_stack_enabled ? module.observability[0].otlp_metrics_protocol : ""
    tracing_enabled   = var.observability_stack_enabled
    tracing_exporter  = "otlp"
    tracing_endpoint  = var.observability_stack_enabled ? module.observability[0].otlp_traces_endpoint : ""
    tracing_protocol  = var.observability_stack_enabled ? module.observability[0].otlp_traces_protocol : ""
    profiling_enabled = false
    log_format        = "gelf"  # "text"
    log_level         = "trace" # "debug", "info", "warn", "info", "error"
  }
}

module "demo_app" {
  source = "./modules/echo-app"

  depends_on = [
    module.cluster,
    module.cert_manager,
    module.ingress_controller,
    module.heimdall,
  ]

  namespace                   = "demo"
  ingress_controller          = var.ingress_controller
  observability_stack_enabled = var.observability_stack_enabled
  global_integration_enabled  = var.global_integration_enabled
  gateway_api_enabled         = var.gateway_api_enabled
}
