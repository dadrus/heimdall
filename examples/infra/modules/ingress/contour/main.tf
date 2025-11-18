resource "helm_release" "contour" {
  name       = "contour"
  repository = "https://projectcontour.github.io/helm-charts/"
  chart      = "contour"
  version    = var.contour_version
  namespace  = var.namespace

  create_namespace = true

  values = [
    file("${path.module}/helm/values.yaml")
  ]

  upgrade_install  = true

  # not waiting as heimdall is not yet installed
  # and contour will fail to start

}
