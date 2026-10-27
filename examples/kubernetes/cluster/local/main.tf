module "kind" {
  source = "../../modules/kind"

  cluster_name       = var.cluster_name
  control_plane_nodes = var.control_plane_nodes
  worker_nodes       = var.worker_nodes
  kubeconfig_path    = local.kubeconfig_path
}

module "cert_manager" {
  source = "../../modules/cert-manager"

  depends_on = [module.kind]

  namespace       = "cert-manager"
  metrics_enabled = false
}

module "rustfs" {
  source = "../../modules/rustfs"

  depends_on = [module.cert_manager]

  namespace     = var.storage_namespace
  release_name  = "rustfs"
  storage_class = var.storage_class
  data_size     = var.rustfs_data_size
  access_key    = var.rustfs_access_key
  secret_key    = var.rustfs_secret_key
}

module "external_secrets" {
  source = "../../modules/external-secrets"

  depends_on = [module.kind]
}

module "headlamp" {
  source = "../../modules/headlamp"

  depends_on = [module.kind]

  namespace    = var.headlamp_namespace
  release_name = "headlamp"

  # Only the local kind cluster: no login prompt; never expose this over Ingress.
  local_admin_auto_login = true
}

resource "helm_release" "metrics_server" {
  depends_on = [module.kind]

  name       = "metrics-server"
  namespace  = "kube-system" # pre-existing namespace; Helm must not own it
  repository = local.metrics_server_chart.repository
  chart      = local.metrics_server_chart.name
  version    = local.metrics_server_chart.version
  wait       = true
  timeout    = 600

  values = [yamlencode({
    # because of the self-signed kubelet serving certificates used by kind
    args = ["--kubelet-insecure-tls"]
  })]
}
