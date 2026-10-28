output "ingress_proxy" {
  value = {
    namespace = var.namespace
    labels = tomap({
      "app.kubernetes.io/name" = "emissary"
      "app.kubernetes.io/instance" = "emissary"
    })
  }
}
