output "ingress_proxy" {
  value = {
    namespace = var.namespace
    labels = tomap({
      "app.kubernetes.io/instance" = "contour"
      "app.kubernetes.io/component" = "envoy"
    })
  }
}
