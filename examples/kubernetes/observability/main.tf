module "prometheus" {
  source = "../modules/prometheus"

  namespace = "monitoring"
}

module "loki" {
  source = "../modules/loki"

  depends_on = [module.prometheus]

  namespace     = "monitoring"
  s3_endpoint   = var.s3_endpoint
  s3_access_key = var.access_key
  s3_secret_key = var.secret_key
  bucket_name   = "loki"
}

module "tempo" {
  source = "../modules/tempo"

  depends_on = [module.prometheus]

  namespace      = "monitoring"
  prometheus_url = module.prometheus.prometheus_url
  s3_endpoint   = var.s3_endpoint
  s3_access_key = var.access_key
  s3_secret_key = var.secret_key
  bucket_name    = "tempo"
}

module "pyroscope" {
  source = "../modules/pyroscope"

  depends_on = [module.prometheus]

  namespace = "monitoring"
}

module "alloy" {
  source = "../modules/alloy"

  depends_on = [
    module.tempo,
    module.loki,
    module.prometheus,
  ]

  namespace            = "monitoring"
  cluster_name         = "demo"
  loki_endpoint        = module.loki.loki_write_url
  prometheus_endpoint  = module.prometheus.prometheus_url
  otel_traces_endpoint = module.tempo.otlp_grpc_receiver_endpoint
}

module "grafana" {
  source = "../modules/grafana"

  depends_on = [
    module.tempo,
    module.loki,
    module.prometheus,
    module.pyroscope
  ]

  namespace      = "monitoring"
  admin_user     = "admin"
  admin_password = "admin"
  prometheus_url = module.prometheus.prometheus_url
  loki_url       = module.loki.loki_read_url
  tempo_url      = module.tempo.server_endpoint
  pyroscope_url  = module.pyroscope.pyroscope_url
}
