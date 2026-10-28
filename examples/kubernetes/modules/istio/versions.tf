locals {
  istio_repository  = "https://blob.istio.io/istio-release/charts"
  istio_version     = "1.31.1"
  istio_chart_names = {
    base      = "base"
    discovery = "istiod"
    gateway   = "gateway"
  }

  csr_chart = {
    repository = "https://charts.jetstack.io"
    name       = "cert-manager-istio-csr"
    version    = "v0.17.0"
  }
}
