resource "helm_release" "emissary_crds" {
  name       = "emissary-crds"
  repository = local.chart_repository
  chart      = local.chart_names.crds
  version    = local.chart_version
  namespace  = var.namespace

  values = [yamlencode({
    enableLegacyVersions = false
  })]

  wait = true
}

resource "helm_release" "emissary" {
  depends_on = [helm_release.emissary_crds]

  name       = "emissary"
  repository = local.chart_repository
  chart      = local.chart_names.controller
  version    = local.chart_version
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
