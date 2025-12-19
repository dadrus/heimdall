resource "helm_release" "grafana_operator" {
  name             = "grafana"
  repository       = "oci://ghcr.io/grafana/helm-charts"
  chart            = "grafana-operator"
  version          = var.grafana_version
  namespace        = var.namespace
  verify           = false
  create_namespace = false

  set = [
    {
      name  = "serviceMonitor.enabled"
      value = "true"
    },
    {
      name = "logging.encoder"
      value = "json"
    },
  ]

  wait            = true
  upgrade_install = true
  timeout         = 600
}

resource "kubectl_manifest" "grafana_datasources" {
  depends_on = [helm_release.grafana_operator]

  for_each = fileset(path.module, "./manifests/data-sources/*.yaml")

  yaml_body = templatefile("${path.module}/${each.value}", {
    namespace      = helm_release.grafana_operator.namespace
    loki_url       = var.loki_url
    prometheus_url = var.prometheus_url
    tempo_url      = var.tempo_url
    pyroscope_url  = var.pyroscope_url
  })
}

resource "kubectl_manifest" "grafana_instance" {
  depends_on = [helm_release.grafana_operator]

  yaml_body = templatefile("${path.module}/manifests/grafana.yaml", {
    namespace      = helm_release.grafana_operator.namespace
    admin_user     = var.admin_user
    admin_password = var.admin_password
  })
}
