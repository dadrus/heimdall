locals {
  loki_s3_secret_name  = "loki-s3-credentials"
  tempo_s3_secret_name = "tempo-s3-credentials"

  rustfs_secret_targets = merge(
    var.rule_provider == "cloud_blob" ? {
      heimdall = { namespace = "heimdall", secret_name = var.blob_credentials_secret_name }
    } : {},
    var.observability_enabled ? {
      loki  = { namespace = "monitoring", secret_name = local.loki_s3_secret_name }
      tempo = { namespace = "monitoring", secret_name = local.tempo_s3_secret_name }
    } : {}
  )
}

resource "kubectl_manifest" "rustfs_eso_reader_account" {
  count = length(local.rustfs_secret_targets) > 0 ? 1 : 0

  yaml_body = templatefile("${path.module}/manifests/eso-reader-serviceaccount.yaml", {
    namespace = var.rustfs_namespace
  })
}

resource "kubectl_manifest" "rustfs_eso_reader_role" {
  count = length(local.rustfs_secret_targets) > 0 ? 1 : 0

  yaml_body = templatefile("${path.module}/manifests/eso-reader-role.yaml", {
    namespace = var.rustfs_namespace
  })
}

resource "kubectl_manifest" "rustfs_eso_reader_binding" {
  count      = length(local.rustfs_secret_targets) > 0 ? 1 : 0
  depends_on = [kubectl_manifest.rustfs_eso_reader_account, kubectl_manifest.rustfs_eso_reader_role]

  yaml_body = templatefile("${path.module}/manifests/eso-reader-rolebinding.yaml", {
    namespace = var.rustfs_namespace
  })
}

resource "kubernetes_manifest" "rustfs_secret_store" {
  count      = length(local.rustfs_secret_targets) > 0 ? 1 : 0
  depends_on = [kubectl_manifest.rustfs_eso_reader_binding]

  manifest = yamldecode(templatefile("${path.module}/manifests/eso-cluster-secret-store.yaml", {
    rustfs_namespace = var.rustfs_namespace
  }))

  wait {
    condition {
      type   = "Ready"
      status = "True"
    }
  }

  timeouts {
    create = "7m"
    update = "7m"
  }
}

resource "kubernetes_manifest" "rustfs_external_secret" {
  for_each   = local.rustfs_secret_targets
  depends_on = [kubectl_manifest.namespaces, kubernetes_manifest.rustfs_secret_store]

  manifest = yamldecode(templatefile("${path.module}/manifests/eso-external-secret.yaml", {
    namespace          = each.value.namespace
    secret_name        = each.value.secret_name
    rustfs_secret_name = var.rustfs_secret_name
  }))

  # Wait for the generated Kubernetes Secret.
  wait {
    condition {
      type   = "Ready"
      status = "True"
    }
  }

  timeouts {
    create = "7m"
    update = "7m"
  }
}
