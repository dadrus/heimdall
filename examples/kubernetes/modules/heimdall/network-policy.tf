resource "kubectl_manifest" "network_policy" {
  count = var.network_policy == null ? 0 : 1

  yaml_body = templatefile("${path.module}/manifests/network-policy.yaml", {
    namespace           = var.namespace
    ingress_proxy       = var.ingress_proxy
    ingress_proxy_cidrs = var.network_policy.ingress_proxy_cidrs
    kubelet_cidrs       = var.network_policy.kubelet_cidrs
    api_server_cidrs    = var.network_policy.api_server_cidrs
    scraper_peer        = var.scraper_peer
    kubernetes_rules    = var.rule_provider == "kubernetes"
  })
}
