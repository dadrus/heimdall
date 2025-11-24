terraform {
  required_providers {
    kind = {
      source  = "tehcyx/kind",
      version = "0.9.0"
    }

    docker = {
      source  = "kreuzwerker/docker",
      version = "3.6.2"
    }

    kubectl = {
      source  = "gavinbunney/kubectl"
      version = "1.19.0"
    }
  }
}
