# Local Kubernetes Cluster with kind

This directory contains a simple kind config file, which creates a Kubernetes cluster consisting of one control plane node and three worker nodes. And all of that in Docker.

## Create Cluster

```bash
kind create cluster --config kind.yaml --name demo
```

## Delete Cluster

```bash
kind delete cluster --name demo
```