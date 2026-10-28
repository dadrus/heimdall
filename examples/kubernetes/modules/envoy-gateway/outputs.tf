output "ingress_proxy" {
  value = {
    namespace = var.namespace
    labels = tomap({
      "app.kubernetes.io/component" = "proxy"
      "gateway.envoyproxy.io/owning-gateway-name" = "eg"
      "gateway.envoyproxy.io/owning-gateway-namespace" = "demo"
    })
  }
}
