resource "kubernetes_namespace_v1" "metallb" {
  depends_on = [null_resource.configure_nodes]

  metadata {
    name = var.lb_namespace
    labels = {
      "pod-security.kubernetes.io/enforce" = "privileged"
      "pod-security.kubernetes.io/audit"   = "privileged"
      "pod-security.kubernetes.io/warn"    = "privileged"
    }
  }
}

resource "helm_release" "metallb" {
  depends_on = [null_resource.configure_nodes]

  name       = "metallb"
  repository = local.metallb_chart.repository
  chart      = local.metallb_chart.name
  namespace  = kubernetes_namespace_v1.metallb.metadata[0].name
  version    = local.metallb_chart.version

  # This example uses Layer 2 only; MetalLB 0.16 defaults to FRR-K8s for BGP.
  values = [yamlencode({
    frrk8s = {
      enabled = false
    }
  })]

  wait       = true
}

locals {
  ipv4_subnet = [
    for cfg in data.docker_network.kind.ipam_config : cfg.subnet
    if length(regexall(":", cfg.subnet)) == 0
  ][0] # first IPv4 subnet
}

resource "kubectl_manifest" "ip-address-pool" {
  yaml_body = templatefile("${path.module}/templates/ip-address-pool.yaml", {
    namespace = helm_release.metallb.namespace
    ip_range  = "${cidrhost(local.ipv4_subnet, 10)}-${cidrhost(local.ipv4_subnet, 20)}"
  })
}

resource "kubectl_manifest" "l2-advertisement" {
  yaml_body = templatefile("${path.module}/templates/l2-advertisement.yaml", {
    namespace = helm_release.metallb.namespace
  })
}


