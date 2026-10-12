terraform {
  required_version = "= 1.12.6"

  required_providers {
    kind = {
      source  = "tehcyx/kind"
      version = "0.11.0"
    }
    docker = {
      source  = "kreuzwerker/docker"
      version = "4.6.0"
    }
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = "1.19.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "3.3.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "3.3.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "3.3.2"
    }
  }
}

# Preserve the provider wiring already used by the original single root.
# kind_cluster.default waits for the API before returning its connection data.
provider "kubernetes" {
  host                   = module.kind.endpoint
  client_certificate     = module.kind.client_certificate
  client_key             = module.kind.client_key
  cluster_ca_certificate = module.kind.cluster_ca_certificate
}

provider "kubectl" {
  host                   = module.kind.endpoint
  client_certificate     = module.kind.client_certificate
  client_key             = module.kind.client_key
  cluster_ca_certificate = module.kind.cluster_ca_certificate
  load_config_file       = false
}

provider "helm" {
  kubernetes = {
    host                   = module.kind.endpoint
    client_certificate     = module.kind.client_certificate
    client_key             = module.kind.client_key
    cluster_ca_certificate = module.kind.cluster_ca_certificate
  }
}
