resource "helm_release" "haproxy" {
  name       = "haproxy-controller"
  repository = "https://haproxy-ingress.github.io/charts"
  chart      = "haproxy-ingress"
  version    = var.haproxy_version
  namespace  = var.namespace

  create_namespace = true

  values = [
    templatefile("${path.module}/helm/values.yaml",{
      global_integration_enabled = var.global_integration_enabled
    })
  ]

  upgrade_install = true
  wait            = true
}
