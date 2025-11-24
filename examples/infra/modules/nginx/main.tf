resource "helm_release" "nginx" {
  name       = "ingress-nginx"
  repository = "https://kubernetes.github.io/ingress-nginx"
  chart      = "ingress-nginx"
  version    = var.nginx_version
  namespace  = var.namespace

  create_namespace = true

  values = [
    templatefile("${path.module}/helm/values.yaml", {
      global_integration_enabled = var.global_integration_enabled
    })
  ]

  upgrade_install = true
  wait            = true
}
