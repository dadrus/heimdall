locals {
  gateway_api_crds_split_doc  = split("---", file("${path.module}/manifests/gateway-api-v1.4.0.yaml"))
  gateway_api_crds_valid_yaml = [for doc in local.gateway_api_crds_split_doc : doc if try(yamldecode(doc).metadata.name, "") != ""]
  gateway_api_crds       = { for doc in toset(local.gateway_api_crds_valid_yaml) : yamldecode(doc).metadata.name => doc }
}

resource "kubectl_manifest" "gateway_api_crds" {
  depends_on = [kind_cluster.default]

  for_each  = local.gateway_api_crds
  yaml_body = each.value
}