# The entire mirror proxy setup happens imperatively
# as we want it to survive terraform destroy

resource "null_resource" "setup_proxy" {
  # Re-run setup on image changes; replacing an existing container is manual.
  triggers = { image = var.image_registry_proxy }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = templatefile("${path.module}/scripts/setup-registry-proxy.sh", {
      proxy_image    = var.image_registry_proxy
      container_name = var.image_registry_proxy_name
      cache_volume   = "registry-mirror-cache"
      certs_volume   = "registry-mirror-certs"
    })
  }
}

resource "null_resource" "attach_proxy_to_kind" {
  # Reattach the manually recreated proxy to kind after an image change.
  triggers = { image = var.image_registry_proxy }

  depends_on = [
    null_resource.setup_proxy,
    kind_cluster.default
  ]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = templatefile("${path.module}/scripts/attach-container-to-network.sh", {
      container = var.image_registry_proxy_name
      network   = data.docker_network.kind.name
    })
  }
}

resource "null_resource" "configure_nodes" {
  depends_on = [
    null_resource.attach_proxy_to_kind
  ]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command = templatefile("${path.module}/scripts/configure-nodes.sh", {
      cluster_name = kind_cluster.default.name
      proxy_host   = var.image_registry_proxy_name
      proxy_port   = 3128
    })
  }
}


