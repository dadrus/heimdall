resource "kubectl_manifest" "certificate" {
  yaml_body = templatefile("${path.module}/manifests/certificate.yaml", {
    namespace = var.namespace
  })
}

resource "helm_release" "traefik" {
  depends_on = [kubectl_manifest.certificate]

  name       = "traefik"
  repository = "https://traefik.github.io/charts"
  chart      = "traefik"
  version    = var.traefik_version
  namespace  = var.namespace

  create_namespace = true

  values = [
    file("${path.module}/helm/values.yaml")
  ]

  upgrade_install = true
  wait            = true
}

