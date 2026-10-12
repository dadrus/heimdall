resource "helm_release" "emissary_crds" {
  name       = "emissary-crds"
  repository = "oci://ghcr.io/emissary-ingress"
  chart      = "emissary-crds-chart"
  version    = var.emissary_version
  namespace  = var.namespace

  values = [yamlencode({
    enableLegacyVersions = false
  })]

  wait = true
}

resource "helm_release" "emissary" {
  depends_on = [helm_release.emissary_crds]

  name       = "emissary"
  repository = "oci://ghcr.io/emissary-ingress"
  chart      = "emissary-ingress"
  version    = var.emissary_version
  namespace  = var.namespace

  values = [yamlencode({
    waitForApiext = {
      enabled = false
    }
  })]

  upgrade_install = true
  wait            = true
}

resource "kubectl_manifest" "listener" {
  depends_on = [helm_release.emissary]

  yaml_body = templatefile("${path.module}/manifests/listener.yaml", {
    namespace = var.namespace
  })
}
