terraform {
  required_providers {
    kind = {
      source  = "tehcyx/kind",
      version = "0.11.0"
    }

    docker = {
      source  = "registry.opentofu.org/kreuzwerker/docker",
      version = "4.6.0"
    }

    kubectl = {
      source  = "gavinbunney/kubectl"
      version = "1.19.0"
    }
  }
}
