resource "kubernetes_namespace_v1" "ingress" {
  metadata {
    name = var.namespace
  }
}

module "contour" {
  depends_on = [kubernetes_namespace_v1.ingress]

  source = "../modules/contour"
  count  = var.ingress_controller == "contour" ? 1 : 0

  namespace = var.namespace
}

module "emissary" {
  depends_on = [kubernetes_namespace_v1.ingress]

  source = "../modules/emissary"
  count  = var.ingress_controller == "emissary" ? 1 : 0

  namespace       = var.namespace
  kubeconfig_path = var.kubeconfig_path
}

module "envoy_gateway" {
  depends_on = [kubernetes_namespace_v1.ingress]

  source = "../modules/envoy-gateway"
  count  = var.ingress_controller == "envoy-gateway" ? 1 : 0

  namespace       = var.namespace
  kubeconfig_path = var.kubeconfig_path
}

module "haproxy" {
  depends_on = [kubernetes_namespace_v1.ingress]

  source = "../modules/haproxy"
  count  = var.ingress_controller == "haproxy" ? 1 : 0

  namespace                  = var.namespace
  global_integration_enabled = var.global_integration_enabled
}

module "istio" {
  depends_on = [kubernetes_namespace_v1.ingress]

  source = "../modules/istio"
  count  = var.ingress_controller == "istio" ? 1 : 0

  gateway_api_enabled = var.gateway_api_enabled
}

module "nginx" {
  depends_on = [kubernetes_namespace_v1.ingress]

  source = "../modules/nginx"
  count  = var.ingress_controller == "nginx" ? 1 : 0

  namespace                  = var.namespace
  global_integration_enabled = var.global_integration_enabled
}

module "traefik" {
  depends_on = [kubernetes_namespace_v1.ingress]

  source = "../modules/traefik"
  count  = var.ingress_controller == "traefik" ? 1 : 0

  namespace                  = var.namespace
  global_integration_enabled = var.global_integration_enabled
  gateway_api_enabled        = var.gateway_api_enabled
  observability              = var.observability
}
