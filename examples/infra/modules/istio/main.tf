resource "kubernetes_namespace" "istio_system" {
  metadata {
    name = "istio-system"
  }
}

resource "kubernetes_namespace" "istio_gateway" {
  metadata {
    name = "istio-gw"
  }
}

resource "kubectl_manifest" "tls_certificate" {
  yaml_body = templatefile("${path.module}/manifests/certificate.yaml", {
    namespace = kubernetes_namespace.istio_gateway.metadata[0].name
  })
}

resource "helm_release" "certmanager_istio_csr" {
  name       = "cert-manager-istio-csr"
  repository = "https://charts.jetstack.io"
  chart      = "cert-manager-istio-csr"
  version    = var.certmanager_istio_csr_version
  namespace  = kubernetes_namespace.istio_system.metadata[0].name

  values = [
    templatefile("${path.module}/helm/csr-values.yaml", {
      namespace = kubernetes_namespace.istio_system
    })
  ]

  upgrade_install = true
  wait            = true
}

resource "helm_release" "istio_base" {
  depends_on = [helm_release.certmanager_istio_csr]

  name       = "istio-base"
  repository = "https://istio-release.storage.googleapis.com/charts"
  chart      = "base"
  version    = var.istio_version
  namespace  = kubernetes_namespace.istio_system.metadata[0].name

  create_namespace = true

  set = [{
    name  = "defaultRevision"
    value = "default"
  }]

  upgrade_install = true
  wait            = true
}

resource "helm_release" "istio_discovery" {
  depends_on = [helm_release.istio_base]

  name       = "istio-discovery"
  repository = "https://istio-release.storage.googleapis.com/charts"
  chart      = "istiod"
  version    = var.istio_version
  namespace  = kubernetes_namespace.istio_system.metadata[0].name

  create_namespace = true

  values = [
    templatefile("${path.module}/helm/values.yaml", {
      namespace = kubernetes_namespace.istio_system.metadata[0].name
    })
  ]

  upgrade_install = true
  wait            = true
}

resource "kubectl_manifest" "destination_rule" {
  depends_on = [helm_release.istio_discovery]

  yaml_body = templatefile("${path.module}/manifests/destination-rule.yaml", {
    namespace = kubernetes_namespace.istio_system.metadata[0].name
  })
}

resource "helm_release" "ingress_gateway" {
  depends_on = [helm_release.istio_discovery]
  count      = var.gateway_api_enabled ? 0 : 1

  name       = "istio-gateway"
  repository = "https://istio-release.storage.googleapis.com/charts"
  chart      = "gateway"
  version    = var.istio_version
  namespace  = kubernetes_namespace.istio_gateway.metadata[0].name

  create_namespace = true

  upgrade_install = true
  wait            = true
}

resource "kubectl_manifest" "ingress_gateway" {
  depends_on = [helm_release.ingress_gateway]

  yaml_body = templatefile("${path.module}/manifests/ingress-gateway.yaml", {
    namespace = kubernetes_namespace.istio_gateway.metadata[0].name
  })
}

resource "kubectl_manifest" "gateway_api_resources" {
  depends_on = [helm_release.istio_base]

  # role and role binding are required to let the proxy
  # controlled by istio accessing the secret with key/certificate material
  # required to verify server certificates used by ext auth services
  # these are the same as installed by istio when ingress controller is installed

  for_each = toset(var.gateway_api_enabled ? [
    "${path.module}/manifests/role.yaml",
    "${path.module}/manifests/role-binding.yaml",
    "${path.module}/manifests/gateway.yaml",
  ] : [])

  yaml_body = templatefile(each.value, {
    namespace = kubernetes_namespace.istio_gateway.metadata[0].name
  })
}

