resource "kubernetes_namespace_v1" "rustfs" {
  metadata {
    name = var.namespace
  }
}

resource "helm_release" "rustfs" {
  name       = var.release_name
  namespace  = kubernetes_namespace_v1.rustfs.metadata[0].name
  repository = var.chart_repository
  chart      = "rustfs"
  version    = var.chart_version

  wait    = true
  timeout = 600

  # Upstream defaults to a multi-node distributed setup, a k3s-specific
  # StorageClass and ingress. None of those is appropriate for the kind base.
  values = [yamlencode({
    fullnameOverride = var.release_name
    replicaCount     = 1
    mode = {
      standalone  = { enabled = true }
      distributed = { enabled = false }
    }
    storageclass = {
      name            = var.storage_class
      dataStorageSize = var.data_size
    }
    config = {
      rustfs = {
        address           = ":${var.s3_port}"
        console_address   = ":${var.console_port}"
        obs_log_directory = "" # one data PVC; log to stdout
      }
    }
    service = {
      type     = "ClusterIP"
      endpoint = { port = var.s3_port }
      console  = { port = var.console_port }
    }
    ingress    = { enabled = false }
    gatewayApi = { enabled = false }
  })]

  set_sensitive = [
    { name = "secret.rustfs.access_key", value = var.access_key },
    { name = "secret.rustfs.secret_key", value = var.secret_key },
  ]
}
