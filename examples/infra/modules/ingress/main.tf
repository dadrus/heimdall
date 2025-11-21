resource "kubernetes_namespace" "ingress" {
  metadata {
    name = var.namespace
  }
}

module "contour" {
  source = "./contour"
  count  = var.ingress_controller == "contour" ? 1 : 0

  namespace = var.namespace
}

module "emissary" {
  source = "./emissary"
  count  = var.ingress_controller == "emissary" ? 1 : 0

  namespace       = var.namespace
  kubeconfig_path = var.kubeconfig_path
}

module "envoy_gateway" {
  source = "./envoy-gateway"
  count  = var.ingress_controller == "envoy-gateway" ? 1 : 0

  namespace = var.namespace
}

module "haproxy" {
  source = "./haproxy"
  count  = var.ingress_controller == "haproxy" ? 1 : 0

  namespace = var.namespace
}

module "istio" {
  source = "./istio"
  count  = var.ingress_controller == "istio" ? 1 : 0
}

module "nginx" {
  source = "./nginx"
  count  = var.ingress_controller == "nginx" ? 1 : 0

  namespace = var.namespace
}

module "traefik" {
  source = "./traefik"
  count  = var.ingress_controller == "traefik" ? 1 : 0

  namespace = var.namespace
}
