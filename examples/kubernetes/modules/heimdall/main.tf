locals {
  use_envoy_grpc = contains(["contour", "emissary", "envoy-gateway", "istio"], var.ingress_controller)

  extra_args = concat(
    ["--insecure-skip-secure-trusted-proxies-enforcement", "--insecure-skip-secure-default-rule-enforcement"],
    local.use_envoy_grpc ? ["--envoy-grpc"] : []
  )
}

resource "kubernetes_namespace" "heimdall" {
  metadata {
    name = var.namespace
  }
}

locals {
  certs_split_doc = split("---", templatefile("${path.module}/manifests/certificate.yaml", {
    namespace = var.namespace
  }))
  certs_valid_yaml = [for doc in local.certs_split_doc : doc if try(yamldecode(doc).metadata.name, "") != ""]
  certs_dict       = { for doc in toset(local.certs_valid_yaml) : yamldecode(doc).metadata.name => doc }
}

resource "kubectl_manifest" "certificates" {
  depends_on = [kubernetes_namespace.heimdall]

  for_each  = local.certs_dict
  yaml_body = each.value
}

resource "helm_release" "heimdall" {
  depends_on = [kubectl_manifest.certificates]

  name             = "heimdall"
  repository       = "../../charts"
  chart            = "heimdall"
  version          = var.heimdall_version
  namespace        = var.namespace
  create_namespace = true
  upgrade_install  = true
  take_ownership   = true

  values = [
    templatefile("${path.module}/configs/heimdall.yaml", {
      metrics_enabled   = var.observability.metrics_enabled
      tracing_enabled   = var.observability.tracing_enabled
      profiling_enabled = var.observability.profiling_enabled
      log_level         = var.observability.log_level
      log_format        = var.observability.log_format
    }),
    templatefile("${path.module}/helm/values.yaml", {
      otel_metrics_enabled  = var.observability.metrics_enabled
      otel_metrics_exporter = var.observability.metrics_exporter
      otel_metrics_protocol = var.observability.metrics_protocol
      otel_metrics_endpoint = var.observability.metrics_endpoint
      otel_tracing_enabled  = var.observability.tracing_enabled
      otel_tracing_exporter = var.observability.tracing_exporter
      otel_tracing_protocol = var.observability.tracing_protocol
      otel_tracing_endpoint = var.observability.tracing_endpoint
      profiling_enabled     = var.observability.profiling_enabled
    }),
  ]

  set = [{
    name  = "extraArgs"
    value = "{${join(",", local.extra_args)}}"
  }]

  wait = true
}

