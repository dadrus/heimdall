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
  release_name     = "rustfs"
  chart_repository = "https://charts.rustfs.com"
  chart_version    = "1.0.1"
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
  release_name     = "headlamp"
  chart_repository = "https://kubernetes-sigs.github.io/headlamp/"
  chart_version    = "0.45.0"

  # Only the local kind cluster: no login prompt; never expose this over Ingress.
  local_admin_auto_login = true
}

resource "helm_release" "metrics_server" {
  depends_on = [module.kind]

  name       = "metrics-server"
  namespace  = "kube-system" # pre-existing namespace; Helm must not own it
  repository = "https://kubernetes-sigs.github.io/metrics-server/"
  chart      = "metrics-server"
  version    = "3.14.0" # metrics-server v0.9.0, compatible with Kubernetes v1.35
  wait       = true
  timeout    = 600

  values = [yamlencode({
    # because of the self-signed kubelet serving certificates used by kind
    args = ["--kubelet-insecure-tls"]
  })]
}
