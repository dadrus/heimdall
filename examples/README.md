# Examples

This directory contains different examples related to heimdall usage and setup.

Those examples, which are based on docker compose are located in the `docker-compose` directory and those, which are implemented for Kubernetes, are located in `kubernetes` directory.

To be able to run the docker compose examples, you'll need Docker and docker-compose installed.

To be able to run the Kubernetes based examples, you'll need just, kubectl, kustomize, helm and a k8s cluster. Latter can also be created locally using kind. The examples are indeed using it.

**Note:** The main branch may have breaking changes (see pending release PRs for details under https://github.com/dadrus/heimdall/pulls) which would make the usage of the referenced heimdall images impossible (even though the configuration files and rules reflect the latest changes). In such situations you'll have to use the `dev` image, build a heimdall image by yourself and update the setups to use it, or switch to a tagged (released) version.