resource "helm_release" "minio_operator" {
  name       = "minio-operator"
  repository = "https://operator.min.io"
  chart      = "operator"
  version    = var.minio_operator_version
  namespace  = "minio-operator"

  create_namespace = true
  upgrade_install  = true

  values = [
    file("${path.module}/helm/values.yaml")
  ]

  wait = true
}

resource "kubectl_manifest" "tls_certificate" {
  yaml_body = templatefile("${path.module}/manifests/certificate.yaml",{
    namespace = helm_release.minio_operator.namespace
  })
}

resource "time_sleep" "wait_for_certificate" {
  depends_on = [kubectl_manifest.tls_certificate]

  create_duration = "10s"   # meist reichen 30–90 Sekunden
}

data "kubernetes_secret" "tls_certificate" {
  depends_on = [
    kubectl_manifest.tls_certificate,
    time_sleep.wait_for_certificate,
  ]

  metadata {
    name      = "sts-tls"
    namespace = helm_release.minio_operator.namespace
  }
}

resource "kubernetes_secret" "operator_ca_tls_tenants" {
  depends_on = [data.kubernetes_secret.tls_certificate]

  metadata {
    name      = "operator-ca-tls-tenants"
    namespace = helm_release.minio_operator.namespace
  }

  type = "generic"

  data = {
    "ca.crt" = data.kubernetes_secret.tls_certificate.data["ca.crt"]
  }
}
