# The local kind cluster and all of its permanent base components have one state.
# The application deployment is managed by a separate OpenTofu root.
module "kind" {
  source = "../../modules/kind"

  cluster_name       = var.cluster_name
  control_plane_nodes = var.control_plane_nodes
  worker_nodes       = var.worker_nodes
  kubeconfig_path    = local.kubeconfig_path
}

module "rustfs" {
  source = "../../modules/rustfs"

  depends_on = [module.kind]

  namespace        = var.rustfs_namespace
  release_name     = var.rustfs_release_name
  chart_repository = var.rustfs_chart_repository
  chart_version    = var.rustfs_chart_version
  storage_class    = var.rustfs_storage_class
  data_size        = var.rustfs_data_size
  cluster_domain   = var.cluster_domain
  access_key       = var.rustfs_access_key
  secret_key       = var.rustfs_secret_key
}

module "headlamp" {
  source = "../../modules/headlamp"

  depends_on = [module.kind]

  namespace        = var.headlamp_namespace
  release_name     = var.headlamp_release_name
  chart_repository = var.headlamp_chart_repository
  chart_version    = var.headlamp_chart_version

  # Only the local kind cluster: no login prompt; never expose this over Ingress.
  local_admin_auto_login = true
}
