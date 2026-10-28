# Unlike Pod traffic, kubelet probes and the local API server originate from
# Kind node IPs. Discover the actual addresses after the cluster is ready.
data "kubernetes_nodes" "local" {
  depends_on = [module.kind]
}

locals {
  node_cidrs = sort(distinct(flatten([
    for node in data.kubernetes_nodes.local.nodes : [
      for address in node.status[0].addresses : "${address.address}/32"
      if address.type == "InternalIP"
    ]
  ])))
}
