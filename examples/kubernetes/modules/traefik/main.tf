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
    templatefile("${path.module}/helm/values.yaml", {
      global_integration_enabled = var.global_integration_enabled
      gateway_api_enabled        = var.gateway_api_enabled
      log_level                  = upper(var.observability.log_level)
      otel_metrics_enabled       = var.observability.metrics_enabled
      otel_metrics_exporter      = var.observability.metrics_exporter
      otel_metrics_protocol      = var.observability.metrics_protocol
      otel_metrics_endpoint      = var.observability.metrics_endpoint
      otel_tracing_enabled       = var.observability.tracing_enabled
      otel_tracing_protocol      = var.observability.tracing_protocol
      otel_tracing_endpoint      = var.observability.tracing_endpoint
    })
  ]

  upgrade_install = true
  wait            = true
}

