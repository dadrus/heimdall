# Install ESO and its CRDs once per cluster, independent of applications and RustFS.
resource "kubernetes_namespace_v1" "external_secrets" {
  metadata {
    name = "external-secrets"
  }
}

resource "helm_release" "external_secrets" {
  name       = "external-secrets"
  namespace  = kubernetes_namespace_v1.external_secrets.metadata[0].name
  repository = local.chart.repository
  chart      = local.chart.name
  version    = local.chart.version

  wait    = true
  timeout = 600

  values = [yamlencode({ installCRDs = true })]
}
