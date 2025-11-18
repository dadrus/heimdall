module "contour" {
  source = "./modules/contour"
  count  = var.ingress_controller == "contour" ? 1 : 0
}

module "emissary" {
  source = "./modules/emissary"
  count  = var.ingress_controller == "emissary" ? 1 : 0
}

module "envoy_gateway" {
  source = "./modules/envoy-gateway"
  count  = var.ingress_controller == "envoy-gateway" ? 1 : 0
}

module "haproxy" {
  source = "./modules/haproxy"
  count  = var.ingress_controller == "haproxy" ? 1 : 0
}

module "istio" {
  source = "./modules/istio"
  count  = var.ingress_controller == "istio" ? 1 : 0
}

module "nginx" {
  source = "./modules/nginx"
  count  = var.ingress_controller == "contour" ? 1 : 0
}

module "traefik" {
  source = "./modules/traefik"
  count  = var.ingress_controller == "traefik" ? 1 : 0
}