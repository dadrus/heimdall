# Local Kubernetes Cluster with kind

This directory contains a simple kind config file, which creates a Kubernetes cluster consisting of one control plane node and three worker nodes. And all of that in Docker.

## Create Cluster

1. Create the actual cluster
   ```bash
   kind create cluster --config kind/kind.yaml --name demo
   ```

2. Deploy and Ingress Controller
   
   We're using NGINX for this purpose.

   ```bash
   kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml --wait=true
   ```
   You might want to wait until the ingress controller pods are up and running before you start using the cluster

## Delete Cluster

```bash
kind delete cluster --name demo
```