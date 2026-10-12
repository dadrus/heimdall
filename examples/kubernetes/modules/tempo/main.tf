resource "helm_release" "tempo" {
  name       = "tempo"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "tempo"
  version    = var.tempo_version
  namespace  = var.namespace

  upgrade_install = true

  values = [
    templatefile("${path.module}/helm/values.yaml", {
      prometheus_url = var.prometheus_url
      s3_endpoint    = var.s3_endpoint
      bucket_name = var.bucket_name
    })
  ]

  wait = true
}
