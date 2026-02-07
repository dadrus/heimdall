resource "helm_release" "prometheus" {
  name       = "prometheus"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "prometheus"
  version    = var.prometheus_version
  namespace  = var.namespace

  upgrade_install  = true
  create_namespace = true

  values = [
    file("${path.module}/helm/values.yaml")
  ]

  wait = true
}