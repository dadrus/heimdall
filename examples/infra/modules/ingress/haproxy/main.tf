resource "helm_release" "haproxy" {
  name       = "haproxy-controller"
  repository = "https://haproxy-ingress.github.io/charts"
  chart      = "haproxy-ingress"
  version    = var.haproxy_version
  namespace  = var.namespace

  create_namespace = true

  set = [{
    name  = "controller.ingressClassResource.enabled",
    value = "true"
  }]

  values = [
    file("${path.module}/helm/values.yaml")
  ]

  upgrade_install = true
  wait            = true
}
