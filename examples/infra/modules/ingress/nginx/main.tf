resource "helm_release" "nginx" {
  name       = "ingress-nginx"
  repository = "https://kubernetes.github.io/ingress-nginx"
  chart      = "ingress-nginx"
  version    = var.nginx_version
  namespace  = var.namespace

  create_namespace = true

  values = [
    file("${path.module}/helm/values.yaml")
  ]

  upgrade_install = true
  wait            = true
}
