# The deployment owns observability; RustFS itself remains in AP 1.
module "deployment" {
  source = "./.."

  kubeconfig_path            = var.kubeconfig_path
  ingress_controller         = var.ingress_controller
  global_integration_enabled = var.global_integration_enabled
  gateway_api_enabled        = var.gateway_api_enabled
  cluster_domain             = var.cluster_domain
  heimdall_image_repository  = var.heimdall_image_repository
  heimdall_image_tag         = var.heimdall_image_tag
  heimdall_image_pull_policy = var.heimdall_image_pull_policy

  observability_enabled   = var.observability_enabled
  rustfs_s3_endpoint      = var.rustfs_s3_endpoint
  rustfs_namespace        = var.rustfs_namespace
  rustfs_secret_name      = var.rustfs_secret_name
  # Depend on completed AP 3 bucket jobs only when the consumers need them.
  # Do not block/replan every shared deployment module on bucket toggles.
  loki_bucket_name  = var.observability_enabled ? module.storage.buckets["loki"] : var.rustfs_bucket_names.loki
  tempo_bucket_name = var.observability_enabled ? module.storage.buckets["tempo"] : var.rustfs_bucket_names.tempo
}

# AP 3: Only requested buckets are created. The RustFS service and Secret
# are managed by the independent cluster/local state.
module "storage" {
  source = "../../storage/local"

  buckets = merge(
    var.rules_bucket_enabled ? { rules = var.rustfs_bucket_names.rules } : {},
    (var.observability_enabled || var.observability_buckets_enabled) ? {
      loki  = var.rustfs_bucket_names.loki
      tempo = var.rustfs_bucket_names.tempo
    } : {}
  )

  rustfs_namespace   = var.rustfs_namespace
  rustfs_secret_name = var.rustfs_secret_name
  s3_endpoint        = var.rustfs_s3_endpoint
}
