resource "kubernetes_job_v1" "bucket" {
  for_each = var.buckets

  metadata {
    name      = "heimdall-create-bucket-${each.key}"
    namespace = var.rustfs_namespace
    labels = {
      "app.kubernetes.io/name"       = "heimdall-bucket-init"
      "app.kubernetes.io/managed-by" = "opentofu"
    }
  }

  wait_for_completion = true

  spec {
    backoff_limit            = 3
    active_deadline_seconds = 300

    template {
      metadata {}
      spec {
        restart_policy                  = "Never"
        automount_service_account_token = false

        container {
          name              = "create-bucket"
          image             = "amazon/aws-cli:2.37.12"
          image_pull_policy = "IfNotPresent"
          command = ["/bin/sh", "-ec", <<-SCRIPT
            # The Kubernetes DNS name is not wildcarded for bucket subdomains.
            # Force path-style requests to the in-cluster RustFS endpoint.
            printf '[default]\ns3 =\n  addressing_style = path\n' > "$AWS_CONFIG_FILE"

            if aws --endpoint-url "$S3_ENDPOINT" s3api head-bucket --bucket "$BUCKET_NAME" >/dev/null 2>&1; then
              echo "Bucket $BUCKET_NAME already exists"
            else
              aws --endpoint-url "$S3_ENDPOINT" s3api create-bucket --bucket "$BUCKET_NAME"
              aws --endpoint-url "$S3_ENDPOINT" s3api head-bucket --bucket "$BUCKET_NAME"
              echo "Created bucket $BUCKET_NAME"
            fi
          SCRIPT
          ]

          env {
            name  = "S3_ENDPOINT"
            value = var.s3_endpoint
          }
          env {
            name  = "BUCKET_NAME"
            value = each.value
          }
          env {
            name  = "AWS_DEFAULT_REGION"
            value = var.s3_region
          }
          env {
            name  = "AWS_CA_BUNDLE"
            value = "/etc/s3-ca/ca.crt"
          }
          env {
            name  = "AWS_CONFIG_FILE"
            value = "/tmp/aws-config"
          }
          env {
            name  = "AWS_PAGER"
            value = ""
          }
          env {
            name  = "AWS_EC2_METADATA_DISABLED"
            value = "true"
          }
          env {
            name  = "HOME"
            value = "/tmp"
          }
          env {
            name = "AWS_ACCESS_KEY_ID"
            value_from {
              secret_key_ref {
                name = var.rustfs_secret_name
                key  = "RUSTFS_ACCESS_KEY"
              }
            }
          }
          env {
            name = "AWS_SECRET_ACCESS_KEY"
            value_from {
              secret_key_ref {
                name = var.rustfs_secret_name
                key  = "RUSTFS_SECRET_KEY"
              }
            }
          }

          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            run_as_non_root            = true
            run_as_user                = 1000
            capabilities {
              drop = ["ALL"]
            }
          }

          resources {
            requests = { cpu = "50m", memory = "64Mi" }
            limits   = { cpu = "500m", memory = "256Mi" }
          }

          volume_mount {
            name       = "s3-ca"
            mount_path = "/etc/s3-ca"
            read_only  = true
          }

          volume_mount {
            name       = "tmp"
            mount_path = "/tmp"
          }
        }

        volume {
          name = "s3-ca"
          config_map {
            name = "cacerts"
          }
        }

        volume {
          name = "tmp"
          empty_dir {}
        }
      }
    }
  }

  timeouts {
    create = "7m"
    update = "7m"
  }

  lifecycle {
    precondition {
      condition     = can(regex("^https://[^/]+", var.s3_endpoint))
      error_message = "s3_endpoint must be an HTTPS URL reachable from inside Kubernetes."
    }
  }
}
