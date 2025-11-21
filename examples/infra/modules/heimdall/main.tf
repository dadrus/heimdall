locals {
  use_envoy_grpc = contains(["contour", "emissary", "envoy-gateway", "istio"], var.ingress_controller)

  extra_args = concat(
    ["--insecure-skip-secure-trusted-proxies-enforcement", "--insecure-skip-secure-default-rule-enforcement"],
    local.use_envoy_grpc ? ["--envoy-grpc"] : []
  )
}

resource "kubernetes_namespace" "heimdall" {
  metadata {
    name = var.namespace
  }
}

locals {
  certs_split_doc = split("---", templatefile("${path.module}/manifests/certificate.yaml", {
    namespace = var.namespace
  }))
  certs_valid_yaml = [for doc in local.certs_split_doc : doc if try(yamldecode(doc).metadata.name, "") != ""]
  certs_dict       = { for doc in toset(local.certs_valid_yaml) : yamldecode(doc).metadata.name => doc }
}

resource "kubectl_manifest" "certificates" {
  depends_on = [kubernetes_namespace.heimdall]

  for_each  = local.certs_dict
  yaml_body = each.value
}

resource "helm_release" "heimdall" {
  depends_on = [kubectl_manifest.certificates]

  name             = "heimdall"
  repository       = "../../charts"
  chart            = "heimdall"
  version          = "0.16.4"
  namespace        = var.namespace
  create_namespace = true
  upgrade_install  = true

  values = [
    file("${path.module}/configs/heimdall.yaml"),
    file("${path.module}/helm/values.yaml"),
  ]

  set = [{
    name  = "extraArgs"
    value = "{${join(",", local.extra_args)}}"
  }]

  wait = true
}
