output "ingress_proxy" {
  value = {
    namespace = var.namespace
    labels = tomap({
      "app.kubernetes.io/name" = "ingress-nginx"
      "app.kubernetes.io/component" = "controller"
    })
  }
}
