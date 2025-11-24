resource "helm_release" "prometheus" {
  name       = "prometheus"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "prometheus"
  version    = var.prometheus_version
  namespace  = var.namespace

  upgrade_install  = true
  create_namespace = true

  values = [
    file("${path.module}/helm/prometheus.yaml")
  ]

  wait = true
}

resource "helm_release" "prometheus_operator_crds" {
  name       = "prometheus-crds"
  repository = "oci://ghcr.io/prometheus-community/charts"
  chart      = "prometheus-operator-crds"
  version    = var.prometheus_operator_crd_version
  namespace  = var.namespace

  upgrade_install  = true
  create_namespace = true

  values = [
    file("${path.module}/helm/crds.yaml")
  ]

  wait = true
}