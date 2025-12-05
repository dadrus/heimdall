resource "helm_release" "loki" {
  name       = "loki"
  repository = "https://grafana.github.io/helm-charts"
  chart      = "loki"
  version    = var.loki_version
  namespace  = var.namespace

  upgrade_install  = true
  create_namespace = true

  values = [
    templatefile("${path.module}/helm/values.yaml", {
      s3_endpoint   = var.s3_endpoint
      s3_access_key = var.s3_access_key
      s3_secret_key = var.s3_secret_key
      bucket_name   = var.bucket_name
    })
  ]

  wait = true
}
