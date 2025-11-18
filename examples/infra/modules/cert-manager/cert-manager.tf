resource "null_resource" "cert_manager_crds" {
  provisioner "local-exec" {
    command = "kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v${var.certmanager_version}/cert-manager.crds.yaml"
  }
}

resource "null_resource" "gateway_api_crds" {
  provisioner "local-exec" {
    command = "kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/standard-install.yaml"
  }
}

resource "helm_release" "cert_manager" {
  depends_on = [
    null_resource.cert_manager_crds,
    null_resource.gateway_api_crds
  ]

  name       = "cert-manager"
  repository = "https://charts.jetstack.io"
  chart      = "cert-manager"
  namespace  = "cert-manager"
  version    = var.certmanager_version

  create_namespace = true

  replace         = true
  upgrade_install = true

  set = [
    {
      name  = "installCRDs"
      value = "false"
    },
    {
      name  = "featureGates"
      value = "AdditionalCertificateOutputFormats=true"
    },
    {
      name  = "webhook.featureGates"
      value = "AdditionalCertificateOutputFormats=true"
    },
    {
      name  = "extraArgs[0]"
      value = "--enable-gateway-api"
    }
  ]

  wait = true
}

resource "null_resource" "wait_for_webhook_ca" {
  depends_on = [helm_release.cert_manager]

  provisioner "local-exec" {
    command = templatefile("${path.module}/scripts/wait-for-resource.sh", {
      namespace       = helm_release.cert_manager.namespace
      resource_name   = "cert-manager-webhook-ca"
      resource_type   = "secret"
      timeout_seconds = 15
      sleep_interval  = 2
    })
  }
}
