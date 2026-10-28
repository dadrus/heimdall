resource "kubectl_manifest" "namespaces" {
  for_each = toset(concat(["heimdall"], var.observability_enabled ? ["monitoring"] : []))

  yaml_body = templatefile("${path.module}/manifests/namespace.yaml", {
    name = each.value
  })
}
