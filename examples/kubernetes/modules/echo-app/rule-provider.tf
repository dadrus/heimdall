resource "kubectl_manifest" "kubernetes_rules" {
  count = var.rule_provider == "kubernetes" ? 1 : 0

  depends_on = [kubernetes_namespace_v1.echo_app]

  yaml_body = yamlencode({
    apiVersion = "heimdall.dadrus.github.com/v${local.echo_app_rules.version}"
    kind       = "RuleSet"
    metadata = {
      name      = local.echo_app_rules.name
      namespace = var.namespace
      labels = {
        "app.kubernetes.io/name" = "echo-app"
      }
    }
    spec = {
      rules = local.echo_app_rules.rules
    }
  })
}

resource "kubernetes_config_map_v1" "http_rules" {
  count = var.rule_provider == "http_endpoint" ? 1 : 0

  metadata {
    name      = "echo-app-rules"
    namespace = var.http_rules_namespace
  }

  data = {
    "echo-app.yaml" = file("${path.module}/rules/echo-app.yaml")
  }
}

resource "kubectl_manifest" "blob_rules_config" {
  count = var.rule_provider == "cloud_blob" ? 1 : 0

  yaml_body = templatefile("${path.module}/manifests/blob/configmap.yaml", {
    namespace  = var.blob_rules_namespace
    rules_yaml = indent(4, trimspace(file("${path.module}/rules/echo-app.yaml")))
  })

  lifecycle {
    precondition {
      condition     = length(trimspace(var.blob_rules_namespace)) > 0
      error_message = "blob_rules_namespace is required when rule_provider=cloud_blob."
    }
  }
}

locals {
  blob_rules_job_hash = substr(sha256(join(":", [
    filesha256("${path.module}/rules/echo-app.yaml"),
    filesha256("${path.module}/manifests/blob/upload-job.yaml"),
  ])), 0, 12)
}

resource "kubernetes_manifest" "blob_rules" {
  count      = var.rule_provider == "cloud_blob" ? 1 : 0
  depends_on = [kubectl_manifest.blob_rules_config]

  manifest = yamldecode(templatefile("${path.module}/manifests/blob/upload-job.yaml", {
    namespace    = var.blob_rules_namespace
    job_name     = "echo-app-publish-rules-${local.blob_rules_job_hash}"
    aws_cli_image = "amazon/aws-cli:2.37.12"
    s3_endpoint  = var.blob_rules_s3_endpoint
    bucket_name  = var.blob_rules_bucket_name
    object_key   = "${var.blob_rules_prefix}echo-app.yaml"
    s3_region    = var.blob_rules_s3_region
    secret_name  = var.blob_rules_secret_name
  }))

  wait {
    condition {
      type   = "Complete"
      status = "True"
    }
  }

  timeouts {
    create = "7m"
    update = "7m"
  }

  lifecycle {
    precondition {
      condition     = can(regex("^https?://[^/]+", var.blob_rules_s3_endpoint))
      error_message = "blob_rules_s3_endpoint must be an in-cluster S3 URL."
    }
    precondition {
      condition     = length(trimspace(var.blob_rules_bucket_name)) > 0
      error_message = "blob_rules_bucket_name is required when rule_provider=cloud_blob."
    }
    precondition {
      condition     = length(trimspace(var.blob_rules_s3_region)) > 0
      error_message = "blob_rules_s3_region is required when rule_provider=cloud_blob."
    }
    precondition {
      condition     = length(trimspace(var.blob_rules_secret_name)) > 0
      error_message = "blob_rules_secret_name is required for the current upload job when rule_provider=cloud_blob."
    }
  }
}
