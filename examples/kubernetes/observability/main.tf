module "prometheus_operator_crds" {
  source = "../modules/prometheus-operator-crds"
  namespace = var.namespace
}

module "prometheus" {
  source = "../modules/prometheus"
  namespace = var.namespace
}

module "loki" {
  source = "../modules/loki"
  namespace      = var.namespace
  s3_endpoint    = var.s3_endpoint
  bucket_name    = var.loki_bucket_name
  s3_secret_name = var.loki_s3_secret_name
  s3_ca_config_map_name = var.s3_ca_config_map_name
}

module "tempo" {
  source = "../modules/tempo"
  depends_on = [module.prometheus]
  namespace      = var.namespace
  prometheus_url = module.prometheus.prometheus_url
  s3_endpoint    = var.s3_endpoint
  bucket_name    = var.tempo_bucket_name
  s3_secret_name = var.tempo_s3_secret_name
  s3_ca_config_map_name = var.s3_ca_config_map_name
}

module "pyroscope" {
  source = "../modules/pyroscope"
  depends_on = [module.prometheus_operator_crds]
  namespace = var.namespace
}

module "alloy" {
  source = "../modules/alloy"
  depends_on = [module.tempo, module.loki, module.prometheus, module.pyroscope, module.prometheus_operator_crds]
  namespace            = var.namespace
  cluster_name         = "demo"
  loki_endpoint        = module.loki.loki_gateway_url
  prometheus_endpoint  = module.prometheus.prometheus_url
  otel_traces_endpoint = module.tempo.otlp_grpc_receiver_endpoint
  pyroscope_endpoint   = module.pyroscope.pyroscope_url
}

module "grafana" {
  source = "../modules/grafana"
  depends_on = [module.alloy, module.prometheus_operator_crds]
  namespace      = var.namespace
  admin_user     = "admin"
  admin_password = "admin" # local demo only; ClusterIP, localhost port-forward
}

resource "kubectl_manifest" "grafana_datasources" {
  depends_on = [module.grafana]

  for_each = fileset(path.module, "manifests/data-sources/*.yaml")

  yaml_body = templatefile("${path.module}/${each.value}", {
    namespace      = var.namespace
    loki_url       = module.loki.loki_gateway_url
    prometheus_url = module.prometheus.prometheus_url
    tempo_url      = module.tempo.server_endpoint
    pyroscope_url  = module.pyroscope.pyroscope_url
  })
}

resource "kubectl_manifest" "heimdall_dashboard" {
  depends_on = [module.grafana, kubectl_manifest.grafana_datasources]

  yaml_body = templatefile("${path.module}/manifests/dashboards/heimdall.yaml", {
    namespace = var.namespace
  })
}
