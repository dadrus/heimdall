data "external" "emissary_app_version" {
  program = ["bash", "-c", <<EOF
    helm repo add emissary https://app.getambassador.io >/dev/null 2>&1 || true
    helm repo update emissary >/dev/null 2>&1 || true
    app_version=$(helm search repo emissary/emissary-ingress --version ${var.emissary_version} -o json | jq -r '.[0].app_version')
    jq -n --arg v "$app_version" '{"app_version": $v}'
  EOF
  ]
}

resource "null_resource" "emissary_crds" {
  triggers = {
    chart_version   = var.emissary_version
    app_version     = data.external.emissary_app_version.result.app_version
    kubeconfig_path = var.kubeconfig_path
  }

  # The CRD bundle also creates the emissary-apiext conversion webhook. Helm
  # reads Emissary CRDs during install, so it must wait for that webhook.
  provisioner "local-exec" {
    command = <<-EOT
      set -e
      kubectl --kubeconfig="${self.triggers.kubeconfig_path}" apply -f "https://app.getambassador.io/yaml/emissary/${self.triggers.app_version}/emissary-crds.yaml"
      kubectl --kubeconfig="${self.triggers.kubeconfig_path}" -n emissary-system rollout status deployment/emissary-apiext --timeout=180s
    EOT
  }

  provisioner "local-exec" {
    when       = destroy
    command    = "kubectl --kubeconfig=${self.triggers.kubeconfig_path} delete -f https://app.getambassador.io/yaml/emissary/${self.triggers.app_version}/emissary-crds.yaml"
    on_failure = continue
  }
}

resource "helm_release" "emissary" {
  depends_on = [null_resource.emissary_crds]

  name       = "emissary"
  repository = "https://app.getambassador.io"
  chart      = "emissary-ingress"
  version    = var.emissary_version
  namespace  = var.namespace

  upgrade_install = true

  wait = true
}

resource "kubectl_manifest" "listener" {
  depends_on = [helm_release.emissary]

  yaml_body = templatefile("${path.module}/manifests/listener.yaml", {
    namespace = var.namespace
  })
}

