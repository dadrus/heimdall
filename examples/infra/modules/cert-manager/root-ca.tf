locals {
  ca_split_doc  = split("---", file("${path.module}/manifests/ca.yaml"))
  ca_valid_yaml = [for doc in local.ca_split_doc : doc if try(yamldecode(doc).metadata.name, "") != ""]
  ca_dict       = { for doc in toset(local.ca_valid_yaml) : yamldecode(doc).metadata.name => doc }
}

resource "kubectl_manifest" "root_ca" {
  depends_on = [helm_release.cert_manager]

  for_each  = local.ca_dict
  yaml_body = each.value
}
