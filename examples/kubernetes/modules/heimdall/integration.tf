locals {
  integration_manifest_docs  = split("---", templatefile("${path.module}/integrations/${var.ingress_controller}.yaml",{
    namespace = var.namespace
  }))
  integration_manifest_yaml = [for doc in local.integration_manifest_docs : doc if try(yamldecode(doc).metadata.name, "") != ""]
  integration_manifests       = { for doc in toset(local.integration_manifest_yaml) : yamldecode(doc).metadata.name => doc }
}

resource "kubectl_manifest" "integration_manifests" {
  depends_on = [helm_release.heimdall]

  for_each  = local.integration_manifests
  yaml_body = each.value
}