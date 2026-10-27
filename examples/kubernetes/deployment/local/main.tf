# The platform prepares namespaces and optional RustFS credentials before the applications.
module "deployment" {
  source = "./.."

  # Wait for ExternalSecrets to be Ready before deploying their consumers.
  depends_on = [kubectl_manifest.namespaces, kubernetes_manifest.rustfs_external_secret]

  kubeconfig_path            = var.kubeconfig_path
  heimdall_namespace         = "heimdall"
  ingress_controller         = var.ingress_controller
  global_integration_enabled = var.global_integration_enabled
  gateway_api_enabled        = var.gateway_api_enabled
  cluster_domain             = var.cluster_domain
  rule_provider              = var.rule_provider

  observability_enabled  = var.observability_enabled
  s3_endpoint            = var.s3_endpoint
  rustfs_namespace       = var.rustfs_namespace
  rustfs_secret_name     = var.rustfs_secret_name
  loki_s3_secret_name    = local.loki_s3_secret_name
  tempo_s3_secret_name   = local.tempo_s3_secret_name
  # A blob deployment needs its bucket before Heimdall starts to poll.
  # This output is linked to successful completion of the bucket Job.
  rules_bucket_name            = var.rule_provider == "cloud_blob" ? module.storage.buckets["rules"] : var.rustfs_bucket_names.rules
  s3_region                    = var.rustfs_s3_region
  blob_s3_secret_name          = var.rule_provider == "cloud_blob" ? var.blob_credentials_secret_name : ""
  blob_rules_url = var.rule_provider == "cloud_blob" ? format(
    "s3://%s?region=%s%s&use_path_style=true&disable_https=%t&awssdk=v2",
    module.storage.buckets["rules"],
    urlencode(var.rustfs_s3_region),
    var.s3_endpoint != "" ? "&endpoint=${urlencode(var.s3_endpoint)}" : "",
    startswith(var.s3_endpoint, "http://")
  ) : ""

  loki_bucket_name  = var.observability_enabled ? module.storage.buckets["loki"] : var.rustfs_bucket_names.loki
  tempo_bucket_name = var.observability_enabled ? module.storage.buckets["tempo"] : var.rustfs_bucket_names.tempo
}

module "storage" {
  source = "../../storage/local"

  buckets = merge(
    (var.rule_provider == "cloud_blob" || var.rules_bucket_enabled) ? { rules = var.rustfs_bucket_names.rules } : {},
    (var.observability_enabled || var.observability_buckets_enabled) ? {
      loki  = var.rustfs_bucket_names.loki
      tempo = var.rustfs_bucket_names.tempo
    } : {}
  )

  rustfs_namespace   = var.rustfs_namespace
  rustfs_secret_name = var.rustfs_secret_name
  s3_endpoint        = var.s3_endpoint
  s3_region          = var.rustfs_s3_region
}
