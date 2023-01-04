# Examples

This directory contains different examples related to heimdall usage and setup.

Those examples, which are based on docker compose are located in the `docker-compose` directory and those, which are implemented for Kubernetes, are located in `kubernetes` directory.

To be able to run the docker compose examples, you'll need Docker and docker-compose installed.

To be able to run the Kubernetes based examples, you'll need kubectl, kustomize, helm and a k8s cluster. Latter can also be created locally using kind. The `kind` directory contains corresponding configuration and a description on how to create and, when you're done, delete the cluster.