resource "helm_release" "tempo" {
  name       = "tempo"
  repository = local.chart.repository
  chart      = local.chart.name
  version    = local.chart.version
  namespace  = var.namespace

  upgrade_install = true

  values = [
    templatefile("${path.module}/helm/values.yaml", {
      prometheus_url        = var.prometheus_url
      s3_endpoint           = var.s3_endpoint
      bucket_name           = var.bucket_name
      s3_secret_name        = var.s3_secret_name
      s3_ca_config_map_name = var.s3_ca_config_map_name
    })
  ]

  wait = true
}
