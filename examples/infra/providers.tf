terraform {
  required_providers {
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = "1.19.0"
    }
  }
}

provider "kubectl" {
  config_path = module.cluster.kubeconfig_path
}

provider "kubernetes" {
  config_path = module.cluster.kubeconfig_path
}

provider "helm" {
  kubernetes = {
    config_path = module.cluster.kubeconfig_path
  }
}
