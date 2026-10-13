resource "kubernetes_namespace_v1" "echo_app" {
  metadata {
    name = var.namespace

    labels = var.ingress_controller == "istio" ? {
      "istio-injection" = "enabled"
    } : {}
  }
}

resource "kubectl_manifest" "deployment" {
  depends_on = [kubernetes_namespace_v1.echo_app]

  for_each = fileset(path.module, "./manifests/*.yaml")

  yaml_body = templatefile("${path.module}/${each.value}", {
    namespace      = var.namespace
    cluster_domain = var.cluster_domain
  })
}

# All rule providers will publish this one service-owned rule set.
# For the Kubernetes provider, only the CRD-specific envelope is generated.
locals {
  echo_app_rules = yamldecode(file("${path.module}/rules/echo-app.yaml"))
}

resource "kubectl_manifest" "rules" {
  depends_on = [kubernetes_namespace_v1.echo_app]

  yaml_body = yamlencode({
    apiVersion = "heimdall.dadrus.github.com/v${local.echo_app_rules.version}"
    kind       = "RuleSet"
    metadata = {
      name      = local.echo_app_rules.name
      namespace = var.namespace
      labels = {
        "app.kubernetes.io/name" = "echo-app"
      }
    }
    spec = {
      rules = local.echo_app_rules.rules
    }
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
  depends_on = [kubectl_manifest.deployment, kubectl_manifest.rules]

  for_each  = local.ingress_manifests
  yaml_body = each.value
}

