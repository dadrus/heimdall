output "ingress_proxy" {
  value = {
    namespace = var.namespace
    labels = tomap({
      "app.kubernetes.io/name" = "traefik"
      "app.kubernetes.io/instance" = "traefik-${var.namespace}"
    })
  }
}
