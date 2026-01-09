resource "helm_release" "tempo" {
  name       = "tempo"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "tempo"
  version    = var.tempo_version
  namespace  = var.namespace

  upgrade_install  = true
  create_namespace = true

  values = [
    templatefile("${path.module}/helm/values.yaml", {
      prometheus_url = var.prometheus_url
      s3_endpoint    = var.s3_endpoint
      s3_access_key  = var.s3_access_key
      s3_secret_key  = var.s3_secret_key
      bucket_name = var.bucket_name
    })
  ]

  wait = true
}
