terraform {
  required_version = "= 1.12.6"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "3.3.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "3.3.0"
    }
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = "1.19.0"
    }
  }
}

provider "kubernetes" {
  config_path = var.kubeconfig_path
}

provider "kubectl" {
  config_path      = var.kubeconfig_path
  load_config_file = true
}

provider "helm" {
  kubernetes = {
    config_path = var.kubeconfig_path
  }
}
