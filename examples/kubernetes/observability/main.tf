# The monitoring namespace has one explicit owner. No Helm release owns it.
resource "kubernetes_namespace_v1" "monitoring" {
  metadata {
    name = var.namespace
  }
}

# The RustFS Secret belongs to the permanent cluster state and cannot be
# mounted into another namespace. This short-lived Job copies only its two
# S3 credentials into monitoring using the Kubernetes API. Neither Terraform
# nor Helm ever reads the secret bytes, and the Job does not log them.
resource "kubernetes_service_account_v1" "secret_sync" {
  metadata {
    name      = "heimdall-rustfs-secret-sync"
    namespace = var.rustfs_namespace
  }
}

resource "kubernetes_role_v1" "secret_writer" {
  depends_on = [kubernetes_namespace_v1.monitoring]
  metadata {
    name      = "heimdall-rustfs-secret-writer"
    namespace = var.namespace
  }

  # Kubernetes Server-Side Apply requires create for first use and patch for
  # updates. Creation is namespace-scoped; patch is restricted to one name.
  rule {
    api_groups = [""]
    resources  = ["secrets"]
    verbs      = ["create"]
  }
  rule {
    api_groups     = [""]
    resources      = ["secrets"]
    resource_names = ["heimdall-rustfs-s3"]
    verbs          = ["patch"]
  }
}

resource "kubernetes_role_binding_v1" "secret_writer" {
  metadata {
    name      = "heimdall-rustfs-secret-writer"
    namespace = var.namespace
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role_v1.secret_writer.metadata[0].name
  }
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account_v1.secret_sync.metadata[0].name
    namespace = var.rustfs_namespace
  }
}

resource "kubernetes_job_v1" "secret_sync" {
  depends_on = [kubernetes_role_binding_v1.secret_writer]
  metadata {
    name      = "heimdall-sync-rustfs-s3"
    namespace = var.rustfs_namespace
  }
  wait_for_completion = true
  spec {
    backoff_limit           = 3
    active_deadline_seconds = 300
    template {
      metadata {}
      spec {
        service_account_name            = kubernetes_service_account_v1.secret_sync.metadata[0].name
        automount_service_account_token = true # only this bootstrap Job needs API access
        restart_policy                  = "Never"
        container {
          name              = "sync"
          image             = "curlimages/curl:8.22.0"
          image_pull_policy = "IfNotPresent"
          command = ["/bin/sh", "-ec", <<-SCRIPT
            # Do not enable shell tracing or print the rendered Secret.
            access_key="$(base64 /rustfs/RUSTFS_ACCESS_KEY | tr -d '\n')"
            secret_key="$(base64 /rustfs/RUSTFS_SECRET_KEY | tr -d '\n')"
            curl --fail --silent --show-error --retry 5 --retry-delay 2 \
              --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
              -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
              -H 'Content-Type: application/apply-patch+yaml' \
              -X PATCH --data-binary @- \
              'https://kubernetes.default.svc/api/v1/namespaces/${var.namespace}/secrets/heimdall-rustfs-s3?fieldManager=heimdall-rustfs-sync' \
              >/dev/null <<EOF
            apiVersion: v1
            kind: Secret
            metadata:
              name: heimdall-rustfs-s3
              namespace: ${var.namespace}
            type: Opaque
            data:
              AWS_ACCESS_KEY_ID: $access_key
              AWS_SECRET_ACCESS_KEY: $secret_key
            EOF
            echo 'S3 credentials available in monitoring namespace'
          SCRIPT
          ]
          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            run_as_non_root            = true
            run_as_user                = 1000
            capabilities {
              drop = ["ALL"]
            }
          }
          volume_mount {
            name       = "rustfs"
            mount_path = "/rustfs"
            read_only  = true
          }
          resources {
            requests = { cpu = "20m", memory = "32Mi" }
            limits   = { cpu = "200m", memory = "128Mi" }
          }
        }
        volume {
          name = "rustfs"
          secret {
            secret_name = var.rustfs_secret_name
          }
        }
      }
    }
  }
  timeouts {
    create = "7m"
  }
}

module "prometheus_operator_crds" {
  source = "../modules/prometheus-operator-crds"
  depends_on = [kubernetes_namespace_v1.monitoring]
  namespace = var.namespace
}

module "prometheus" {
  source = "../modules/prometheus"
  depends_on = [kubernetes_namespace_v1.monitoring]
  namespace = var.namespace
}

module "loki" {
  source = "../modules/loki"
  depends_on = [kubernetes_job_v1.secret_sync]
  namespace     = var.namespace
  s3_endpoint   = var.s3_endpoint
  bucket_name   = var.loki_bucket_name
}

module "tempo" {
  source = "../modules/tempo"
  depends_on = [kubernetes_job_v1.secret_sync, module.prometheus]
  namespace      = var.namespace
  prometheus_url = module.prometheus.prometheus_url
  s3_endpoint    = var.s3_endpoint
  bucket_name    = var.tempo_bucket_name
}

module "pyroscope" {
  source = "../modules/pyroscope"
  depends_on = [module.prometheus_operator_crds]
  namespace = var.namespace
}

module "alloy" {
  source = "../modules/alloy"
  depends_on = [module.tempo, module.loki, module.prometheus, module.pyroscope, module.prometheus_operator_crds]
  namespace            = var.namespace
  cluster_name         = "demo"
  loki_endpoint        = module.loki.loki_gateway_url
  prometheus_endpoint  = module.prometheus.prometheus_url
  otel_traces_endpoint = module.tempo.otlp_grpc_receiver_endpoint
  pyroscope_endpoint   = module.pyroscope.pyroscope_url
}

module "grafana" {
  source = "../modules/grafana"
  depends_on = [module.alloy, module.prometheus_operator_crds]
  namespace      = var.namespace
  admin_user     = "admin"
  admin_password = "admin" # local demo only; ClusterIP, localhost port-forward
}

# These are example dashboards and connections, not part of the reusable
# Grafana operator/instance module. They follow the Grafana CRD installation.
resource "kubectl_manifest" "grafana_datasources" {
  depends_on = [module.grafana]

  for_each = fileset(path.module, "manifests/data-sources/*.yaml")

  yaml_body = templatefile("${path.module}/${each.value}", {
    namespace      = var.namespace
    loki_url       = module.loki.loki_gateway_url
    prometheus_url = module.prometheus.prometheus_url
    tempo_url      = module.tempo.server_endpoint
    pyroscope_url  = module.pyroscope.pyroscope_url
  })
}

resource "kubectl_manifest" "heimdall_dashboard" {
  depends_on = [module.grafana, kubectl_manifest.grafana_datasources]

  yaml_body = templatefile("${path.module}/manifests/dashboards/heimdall.yaml", {
    namespace = var.namespace
  })
}
