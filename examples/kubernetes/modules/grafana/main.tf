resource "helm_release" "grafana_operator" {
  name       = "grafana"
  repository = "oci://ghcr.io/grafana/helm-charts"
  chart      = "grafana-operator"
  version    = var.grafana_version
  namespace  = var.namespace
  verify     = false

  take_ownership = true

  set = [
    {
      name  = "crds.immutable"
      value = "false"
    },
    {
      name  = "serviceMonitor.enabled"
      value = "true"
    },
    {
      name = "dashboard.enabled"
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

resource "kubectl_manifest" "grafana_instance" {
  depends_on = [helm_release.grafana_operator]

  yaml_body = templatefile("${path.module}/manifests/grafana.yaml", {
    namespace      = helm_release.grafana_operator.namespace
    admin_user     = var.admin_user
    admin_password = var.admin_password
  })
}
