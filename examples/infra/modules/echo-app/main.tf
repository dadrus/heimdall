resource "kubernetes_namespace" "echo_app" {
  metadata {
    name = var.namespace
  }
}

resource "kubectl_manifest" "deployment" {
  depends_on = [kubernetes_namespace.echo_app]

  for_each = fileset(path.module, "./manifests/*.yaml")

  yaml_body = templatefile("${path.module}/${each.value}", {
    namespace = var.namespace
  })
}

locals {
  ingress_docs = split("---", templatefile("${path.module}/ingress/${var.ingress_controller}.yaml", {
    namespace                  = var.namespace
    global_integration_enabled = var.global_integration_enabled
    gateway_api_enabled        = var.gateway_api_enabled
  }))

  ingress_yaml      = [for doc in local.ingress_docs : doc if try(yamldecode(doc).metadata.name, "") != ""]
  ingress_manifests = { for doc in toset(local.ingress_yaml) : yamldecode(doc).metadata.name => doc }
}

resource "kubectl_manifest" "ingress" {
  depends_on = [kubectl_manifest.deployment]

  for_each  = local.ingress_manifests
  yaml_body = each.value
}

