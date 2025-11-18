locals {
  ca_split_doc  = split("---", file("${path.module}/manifests/ca.yaml"))
  ca_valid_yaml = [for doc in local.ca_split_doc : doc if try(yamldecode(doc).metadata.name, "") != ""]
  ca_dict       = { for doc in toset(local.ca_valid_yaml) : yamldecode(doc).metadata.name => doc }
}

resource "kubectl_manifest" "root_ca" {
  depends_on = [
    null_resource.cert_manager_crds,
    null_resource.wait_for_webhook_ca
  ]

  for_each  = local.ca_dict
  yaml_body = each.value
}

resource "null_resource" "wait_for_root_ca" {
  depends_on = [
    helm_release.cert_manager,
    kubectl_manifest.root_ca
  ]

  provisioner "local-exec" {
    command = templatefile("${path.module}/scripts/wait-for-resource.sh", {
      namespace = helm_release.cert_manager.namespace
      resource_name = "root-ca"
      resource_type = "secret"
      timeout_seconds = 15
      sleep_interval = 2
    })
  }
}