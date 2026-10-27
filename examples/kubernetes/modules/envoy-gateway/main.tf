resource "terraform_data" "envoy_gateway_crds" {
  input = {
    version         = local.chart.version
    kubeconfig_path = var.kubeconfig_path
  }

  triggers_replace = [local.chart.version, var.kubeconfig_path]

  provisioner "local-exec" {
    interpreter = ["bash", "-c"]
    environment = {
      ENVOY_GATEWAY_VERSION = self.input.version
      KUBECONFIG           = self.input.kubeconfig_path
    }
    command = <<-EOT
      set -euo pipefail
      helm template envoygw-crds oci://docker.io/envoyproxy/gateway-crds-helm \
        --version "$ENVOY_GATEWAY_VERSION" \
        --set crds.gatewayAPI.enabled=false \
        --set crds.envoyGateway.enabled=true \
        | kubectl apply --server-side -f -
      # A newly applied CRD may not have status.conditions yet. Poll the
      # condition explicitly and fail if it never becomes True.
      for attempt in {1..90}; do
        status="$(kubectl get crd/securitypolicies.gateway.envoyproxy.io \
          -o go-template='{{range .status.conditions}}{{if eq .type "Established"}}{{.status}}{{end}}{{end}}')"
        if [[ "$status" == "True" ]]; then
          break
        fi
        if (( attempt == 90 )); then
          echo "ERROR: Envoy SecurityPolicy CRD was not Established after 180s" >&2
          kubectl describe crd/securitypolicies.gateway.envoyproxy.io >&2
          exit 1
        fi
        sleep 2
      done
    EOT
  }

  # delete only Envoy's CRDs
  provisioner "local-exec" {
    when        = destroy
    on_failure  = continue
    interpreter = ["bash", "-c"]
    environment = {
      ENVOY_GATEWAY_VERSION = self.input.version
      KUBECONFIG           = self.input.kubeconfig_path
    }
    command = <<-EOT
      set -euo pipefail
      helm template envoygw-crds oci://docker.io/envoyproxy/gateway-crds-helm \
        --version "$ENVOY_GATEWAY_VERSION" \
        --set crds.gatewayAPI.enabled=false \
        --set crds.envoyGateway.enabled=true \
        | kubectl delete --ignore-not-found --wait=false -f -
    EOT
  }
}

resource "helm_release" "envoy_gateway" {
  depends_on = [terraform_data.envoy_gateway_crds]

  name       = "envoygw"
  repository = local.chart.repository
  chart      = local.chart.name
  version    = local.chart.version
  namespace  = var.namespace
  verify     = false

  values = [
    file("${path.module}/helm/values.yaml")
  ]

  wait            = true
  upgrade_install = true
  timeout         = 600
}

resource "kubectl_manifest" "gateway_class" {
  depends_on = [helm_release.envoy_gateway]

  yaml_body = file("${path.module}/manifests/gateway-class.yaml")
}
