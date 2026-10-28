output "ingress_proxy" {
  description = "Namespace and Pod labels for the selected ExtAuth data-plane proxy."
  value = one(concat(
    module.contour[*].ingress_proxy,
    module.emissary[*].ingress_proxy,
    module.envoy_gateway[*].ingress_proxy,
    module.haproxy[*].ingress_proxy,
    module.istio[*].ingress_proxy,
    module.nginx[*].ingress_proxy,
    module.traefik[*].ingress_proxy,
  ))
}
