# kind uses self-signed kubelet serving certificates. This is deliberately a
# local-only exception; never use --kubelet-insecure-tls in cloud clusters.
# Metrics Server serves metrics.k8s.io for kubectl top, Headlamp and HPA; it is
# independent from the optional Prometheus/observability stack.
resource "helm_release" "metrics_server" {
  depends_on = [module.kind]

  name       = "metrics-server"
  namespace  = "kube-system" # pre-existing namespace; Helm must not own it
  repository = "https://kubernetes-sigs.github.io/metrics-server/"
  chart      = "metrics-server"
  version    = "3.14.0" # metrics-server v0.9.0, compatible with Kubernetes v1.35
  wait       = true
  timeout    = 600

  # Preserve the chart's defaultArgs (including preferred kubelet addresses).
  values = [yamlencode({
    args = ["--kubelet-insecure-tls"]
  })]
}
