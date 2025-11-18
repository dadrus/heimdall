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
    chart_version = var.emissary_version
    app_version   = data.external.emissary_app_version.result.app_version
  }

  provisioner "local-exec" {
    command = "kubectl apply -f https://app.getambassador.io/yaml/emissary/${self.triggers.app_version}/emissary-crds.yaml"
  }

  provisioner "local-exec" {
    when       = destroy
    command    = "kubectl delete -f https://app.getambassador.io/yaml/emissary/${self.triggers.app_version}/emissary-crds.yaml"
    on_failure = continue
  }
}

resource "null_resource" "wait_for_emissary_apiext_deployment" {
  depends_on = [
    null_resource.emissary_crds
  ]

  provisioner "local-exec" {
    command = templatefile("${path.module}/scripts/wait-for-condition.sh", {
      namespace       = "emissary-system"
      condition       = "available deployment emissary-apiext"
      timeout_seconds = 90
    })
  }
}

resource "helm_release" "emissary" {
  depends_on = [null_resource.wait_for_emissary_apiext_deployment]

  name       = "emissary"
  repository = "https://app.getambassador.io"
  chart      = "emissary-ingress"
  version    = var.emissary_version
  namespace  = var.namespace

  create_namespace = true
  upgrade_install  = true

  wait = true
}


resource "null_resource" "wait_for_emissary_controller" {
  depends_on = [helm_release.emissary]

  provisioner "local-exec" {
    command = templatefile("${path.module}/scripts/wait-for-condition.sh", {
      namespace       = var.namespace
      condition       = "available deployment emissary-emissary-${var.namespace}"
      timeout_seconds = 90
    })
  }
}

resource "kubectl_manifest" "listener" {
  depends_on = [null_resource.wait_for_emissary_controller]

  yaml_body = templatefile("${path.module}/manifests/listener.yaml", {
    namespace = var.namespace
  })
}

