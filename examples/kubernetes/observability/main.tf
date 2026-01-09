module "prometheus" {
  source = "../modules/prometheus"

  namespace = var.namespace
}

module "loki" {
  source = "../modules/loki"

  depends_on = [module.prometheus]

  namespace     = var.namespace
  s3_endpoint   = var.s3_endpoint
  s3_access_key = var.access_key
  s3_secret_key = var.secret_key
  bucket_name   = "loki"
}

module "tempo" {
  source = "../modules/tempo"

  depends_on = [module.prometheus]

  namespace      = var.namespace
  prometheus_url = module.prometheus.prometheus_url
  s3_endpoint    = var.s3_endpoint
  s3_access_key  = var.access_key
  s3_secret_key  = var.secret_key
  bucket_name    = "tempo"
}

module "pyroscope" {
  source = "../modules/pyroscope"

  depends_on = [module.prometheus]

  namespace = var.namespace
}

module "alloy" {
  source = "../modules/alloy"

  depends_on = [
    module.tempo,
    module.loki,
    module.prometheus,
  ]

  namespace            = var.namespace
  cluster_name         = "demo"
  loki_endpoint        = module.loki.loki_write_url
  prometheus_endpoint  = module.prometheus.prometheus_url
  otel_traces_endpoint = module.tempo.otlp_grpc_receiver_endpoint
  pyroscope_endpoint   = module.pyroscope.pyroscope_url
}

module "grafana" {
  source = "../modules/grafana"

  depends_on = [
    module.tempo,
    module.loki,
    module.prometheus,
    module.pyroscope
  ]

  namespace      = var.namespace
  admin_user     = "admin"
  admin_password = "admin"
  prometheus_url = module.prometheus.prometheus_url
  loki_url       = module.loki.loki_read_url
  tempo_url      = module.tempo.server_endpoint
  pyroscope_url  = module.pyroscope.pyroscope_url
}
