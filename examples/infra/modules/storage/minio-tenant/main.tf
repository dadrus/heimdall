resource "kubernetes_namespace" "storage" {
  metadata {
    name = var.namespace
  }
}

resource "kubectl_manifest" "minio_tenant" {
  for_each = fileset(path.module, "./manifests/*.yaml")
  yaml_body = templatefile("${path.module}/${each.value}", {
    namespace = var.namespace
    tenant_name = var.tenant_name
  })
}

resource "null_resource" "wait_for_minio_pod" {
  depends_on = [
    kubectl_manifest.minio_tenant
  ]

  provisioner "local-exec" {
    command = templatefile("${path.module}/scripts/wait-for-resource.sh", {
      namespace       = var.namespace
      resource_type   = "pod"
      resource_name   = "minio-pool-0-0"
      timeout_seconds = 90
      sleep_interval  = 5
    })
  }
}

resource "null_resource" "wait_for_minio_pod_ready" {
  depends_on = [
    null_resource.wait_for_minio_pod
  ]

  provisioner "local-exec" {
    command = templatefile("${path.module}/scripts/wait-for-condition.sh", {
      namespace       = var.namespace
      condition       = "ready pod -l statefulset.kubernetes.io/pod-name=minio-pool-0-0"
      timeout_seconds = 90
    })
  }
}
