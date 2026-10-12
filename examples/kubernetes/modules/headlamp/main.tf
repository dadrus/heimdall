resource "kubernetes_namespace_v1" "headlamp" {
  metadata {
    name = var.namespace
  }
}

resource "helm_release" "headlamp" {
  name       = var.release_name
  namespace  = kubernetes_namespace_v1.headlamp.metadata[0].name
  repository = var.chart_repository
  chart      = "headlamp"
  version    = var.chart_version

  wait    = true
  timeout = 600

  # Always accessible via port-forward without the selected Ingress/Gateway.
  values = [yamlencode({
    fullnameOverride = var.release_name
    service = {
      type = "ClusterIP"
      port = var.service_port
    }
    ingress = { enabled = false }

    # The kind root alone enables passwordless access for local development.
    # This deliberately gives every dashboard visitor the pod's permissions.
    config = {
      unsafeUseServiceAccountToken = var.local_admin_auto_login
    }
    serviceAccount = {
      create = true
    }
    automountServiceAccountToken = true
    clusterRoleBinding = {
      create          = var.local_admin_auto_login
      clusterRoleName = "cluster-admin"
    }
  })]
}
