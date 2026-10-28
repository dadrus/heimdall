output "ingress_proxy" {
  value = {
    namespace = var.namespace
    labels = tomap({
      "app.kubernetes.io/name" = "haproxy-ingress"
      "app.kubernetes.io/instance" = "haproxy-controller"
    })
  }
}
