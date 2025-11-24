resource "helm_release" "envoy_gateway" {
  name             = "envoygw"
  repository       = "oci://docker.io/envoyproxy"
  chart            = "gateway-helm"
  version          = var.envoygw_version
  namespace        = var.namespace
  verify           = false
  create_namespace = true

  values = [
    file("${path.module}/helm/values.yaml")
  ]

  wait            = true
  upgrade_install = true
  timeout         = 600
}

resource "kubectl_manifest" "gateway_class" {
  depends_on = [helm_release.envoy_gateway]

  yaml_body = file("${path.module}/manifests/gateway-class.yaml")
}
