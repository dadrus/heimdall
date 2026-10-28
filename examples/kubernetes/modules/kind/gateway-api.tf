# Gateway API CRDs are shared by all controllers.
data "http" "gateway_api_bundle" {
  url = "https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.3/standard-install.yaml"

  lifecycle {
    postcondition {
      condition = self.status_code == 200 && can(regex("gateway.networking.k8s.io/bundle-version: v1\\.6\\.3", self.response_body))
      error_message = "Could not retrieve the expected Gateway API v1.6.3 Standard bundle."
    }
  }
}

locals {
  gateway_api_docs = [
    for doc in split("\n---\n", trimspace(data.http.gateway_api_bundle.response_body)) : doc
    if try(yamldecode(doc).metadata.name, "") != ""
  ]
  gateway_api_manifests = {
    for doc in toset(local.gateway_api_docs) : "${yamldecode(doc).kind}/${yamldecode(doc).metadata.name}" => doc
  }
}

resource "kubectl_manifest" "gateway_api_manifests" {
  depends_on = [kind_cluster.default]

  for_each          = local.gateway_api_manifests
  yaml_body         = each.value
  server_side_apply = true
}
