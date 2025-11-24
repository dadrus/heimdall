locals {
  control_planes = [
    for i in range(var.control_plane_nodes) : {
      role    = "control-plane"
      patches = [file("${path.module}/manifests/init-configuration.yaml")]
    }
  ]

  workers = [
    for i in range(var.worker_nodes) : {
      role    = "worker"
      patches = []
    }
  ]

  all_nodes = concat(local.control_planes, local.workers)
}

resource "kind_cluster" "default" {
  name            = var.cluster_name
  node_image      = var.node_image
  kubeconfig_path = pathexpand("/tmp/config")
  wait_for_ready  = true

  kind_config {
    kind        = "Cluster"
    api_version = "kind.x-k8s.io/v1alpha4"

    networking {
      ip_family = "ipv4"
    }

    dynamic "node" {
      for_each = local.all_nodes

      content {
        role                   = node.value.role
        kubeadm_config_patches = node.value.patches
      }
    }
  }
}

data "docker_network" "kind" {
  name = "kind"
}
