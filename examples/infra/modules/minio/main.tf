resource "kubernetes_namespace" "minio_operator" {
  metadata {
    name = "minio-operator"
  }
}

resource "helm_release" "minio_operator" {
  name       = "minio-operator"
  repository = "https://operator.min.io"
  chart      = "operator"
  version    = var.minio_operator_version
  namespace  = kubernetes_namespace.minio_operator.metadata[0].name

  upgrade_install  = true

  values = [
    file("${path.module}/helm/values.yaml")
  ]

  wait = true
}

resource "kubectl_manifest" "tls_certificate" {
  depends_on = [kubernetes_namespace.minio_operator]

  yaml_body = templatefile("${path.module}/manifests/certificate.yaml",{
    namespace = kubernetes_namespace.minio_operator.metadata[0].name
  })
}

resource "null_resource" "wait_for_certificate_secret" {
  depends_on = [
    kubectl_manifest.tls_certificate
  ]

  provisioner "local-exec" {
    command = templatefile("${path.module}/scripts/wait-for-resource.sh", {
      namespace       = kubernetes_namespace.minio_operator.metadata[0].name
      resource_type   = "secret"
      resource_name   = "sts-tls"
      timeout_seconds = 15
      sleep_interval  = 2
    })
  }
}

data "kubernetes_secret" "tls_certificate" {
  depends_on = [null_resource.wait_for_certificate_secret]

  metadata {
    name      = "sts-tls"
    namespace = kubernetes_namespace.minio_operator.metadata[0].name
  }
}

resource "kubernetes_secret" "operator_ca_tls_tenants" {
  depends_on = [data.kubernetes_secret.tls_certificate]

  metadata {
    name      = "operator-ca-tls-tenants"
    namespace = kubernetes_namespace.minio_operator.metadata[0].name
  }

  type = "generic"

  data = {
    "ca.crt" = data.kubernetes_secret.tls_certificate.data["ca.crt"]
  }
}
