resource "helm_release" "loki" {
  name       = "loki"
  repository = "https://grafana-community.github.io/helm-charts"
  chart      = "loki"
  version    = var.loki_version
  namespace  = var.namespace

  upgrade_install = true

  values = [
    templatefile("${path.module}/helm/values.yaml", {
      s3_endpoint   = var.s3_endpoint
      bucket_name   = var.bucket_name
    })
  ]

  wait = true
}
