resource "kubernetes_namespace_v1" "rustfs" {
  metadata {
    name = var.namespace
  }
}

resource "kubectl_manifest" "tls_certificate" {
  depends_on = [kubernetes_namespace_v1.rustfs]

  yaml_body = templatefile("${path.module}/manifests/certificate.yaml", {
    namespace      = var.namespace
    certificate    = "${var.release_name}-tls"
    service_name   = "${var.release_name}-svc"
  })
}

resource "helm_release" "rustfs" {
  depends_on = [kubectl_manifest.tls_certificate]

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
    extraEnv = [{ name = "RUSTFS_TLS_PATH", value = "/opt/rustfs-tls" }]
    extraVolumes = [{
      name = "rustfs-tls"
      secret = {
        secretName  = "${var.release_name}-tls"
        defaultMode = 288 # 0440; readable by the RustFS pod's fsGroup
        items = [
          { key = "tls.crt", path = "rustfs_cert.pem" },
          { key = "tls.key", path = "rustfs_key.pem" },
        ]
      }
    }]
    extraVolumeMounts = [{
      name      = "rustfs-tls"
      mountPath = "/opt/rustfs-tls"
      readOnly  = true
    }]
    # RustFS switches both API and console to HTTPS when RUSTFS_TLS_PATH is set.
    livenessProbe = { httpGet = { path = "/health", port = "endpoint", scheme = "HTTPS" } }
    readinessProbe = { httpGet = { path = "/health/ready", port = "endpoint", scheme = "HTTPS" } }
    ingress    = { enabled = false }
    gatewayApi = { enabled = false }
  })]

  set_sensitive = [
    { name = "secret.rustfs.access_key", value = var.access_key },
    { name = "secret.rustfs.secret_key", value = var.secret_key },
  ]
}
