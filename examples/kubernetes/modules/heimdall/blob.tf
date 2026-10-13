locals {
  blob_secret_sync_enabled = var.rule_provider == "cloud_blob" && var.blob_sync_rustfs_credentials
}

resource "kubectl_manifest" "blob_secret_sync_account" {
  count = local.blob_secret_sync_enabled ? 1 : 0

  yaml_body = templatefile("${path.module}/manifests/blob-secret-sync-serviceaccount.yaml", {
    namespace = var.rustfs_namespace
  })
}

resource "kubectl_manifest" "blob_secret_writer_role" {
  count      = local.blob_secret_sync_enabled ? 1 : 0
  depends_on = [kubernetes_namespace_v1.heimdall]

  yaml_body = templatefile("${path.module}/manifests/blob-secret-writer-role.yaml", {
    namespace   = var.namespace
    secret_name = var.blob_s3_secret_name
  })
}

resource "kubectl_manifest" "blob_secret_writer_binding" {
  count      = local.blob_secret_sync_enabled ? 1 : 0
  depends_on = [kubectl_manifest.blob_secret_sync_account, kubectl_manifest.blob_secret_writer_role]

  yaml_body = templatefile("${path.module}/manifests/blob-secret-writer-rolebinding.yaml", {
    namespace        = var.namespace
    rustfs_namespace = var.rustfs_namespace
  })
}

resource "kubernetes_manifest" "blob_secret_sync" {
  count      = local.blob_secret_sync_enabled ? 1 : 0
  depends_on = [kubectl_manifest.blob_secret_writer_binding]

  manifest = yamldecode(templatefile("${path.module}/manifests/blob-secret-sync-job.yaml", {
    namespace           = var.rustfs_namespace
    heimdall_namespace  = var.namespace
    secret_name         = var.blob_s3_secret_name
    rustfs_secret_name  = var.rustfs_secret_name
  }))

  wait {
    condition {
      type   = "Complete"
      status = "True"
    }
  }

  timeouts {
    create = "7m"
  }
}
