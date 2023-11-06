# Examples

This directory contains different examples related to heimdall usage and setup.

Those examples, which are based on docker compose are located in the `docker-compose` directory and those, which are implemented for Kubernetes, are located in `kubernetes` directory.

To be able to run the docker compose examples, you'll need Docker and docker-compose installed.

To be able to run the Kubernetes based examples, you'll need just, kubectl, kustomize, helm and a k8s cluster. Latter can also be created locally using kind. The examples are indeed using it.

The example in the `local` folder is intended for developement. You may start the heimdall together with a Redis cache and an example application. You may also ommit the heimdall container and run it from your IDE for debugging instead. 