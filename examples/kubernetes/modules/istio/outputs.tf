output "ingress_proxy" {
  value = {
    namespace = kubernetes_namespace_v1.istio_gateway.metadata[0].name
    labels = var.gateway_api_enabled ? tomap({
      "gateway.networking.k8s.io/gateway-name" = "istio-gw"
    }) : tomap({
      istio = "ingressgateway"
    })
  }
}
