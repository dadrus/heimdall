# Kubernetes Quickstarts

This directory contains working examples described in the getting started, as well as in the integration guides of the documentation. The demonstration of the decision operation mode is done via integration with the corresponding ingress controllers. As of now, these are [Contour](https://projectcontour.io), the [NGINX Ingress Controller](https://docs.nginx.com/nginx-ingress-controller/) and [HAProxy Ingress Controller](https://haproxy-ingress.github.io/).

# Prerequisites

To be able to install and play with quickstarts, you need

* [Just](https://github.com/casey/just), which is used to ease the installation and setup
* [Helm](https://helm.sh/) as it is used to install most of the required services, including heimdall
* [Kustomize](https://kustomize.io/), which is used to build the configuration of the demo service depending on the used ingress controller.
* [kubectl](https://kubernetes.io/docs/reference/kubectl/), used to apply the configuration and which you will need to inspect the cluster
* [kind](https://kind.sigs.k8s.io/), used to create a local kubernetes cluster using docker
* [Docker](https://www.docker.com/) to be able running containers
* [curl](https://curl.se/) to play around with the exposed APIs of the setup

# Install the demo

Depending on the Ingress Controller you want to install the demo for, execute

```bash
   just install-<ingress controller>-demo
   ```

with `<ingress controller>` being either `contour`, `nginx` or `haproxy`. That command line will install and set up a kind based k8s cluster locally including all required services and configuring the used ingress controller to forward all incoming requests to heimdall as external authorization middleware. Depending on the response from heimdall the ingress controller will either forward the request to the upstream service (in that case a simple echo service), or directly respond with an error from heimdall to the client.

Depending on your internet connection, it may take some minutes. So, maybe it's time to grab some coffee :)

# Play with the demo

Check which IP is used for the ingress-controller and set a variable to that value. You can easily achieve this with

```bash
export SERVICE_IP=$(kubectl get svc --namespace nginx-ingress-controller nginx-ingress-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
```

It is required for communication purposes with the demo service.

Now, use

```bash
curl -v --resolve echo-app.local:80:${SERVICE_IP} http://echo-app.local/anon/foo
curl -v --resolve echo-app.local:80:${SERVICE_IP} http://echo-app.local/pub/foo
curl -v --resolve echo-app.local:80:${SERVICE_IP} http://echo-app.local/redir/foo
curl -v --resolve echo-app.local:80:${SERVICE_IP} http://echo-app.local/foo
```

and check the responses.

# Delete the demo

```bash
just delete-cluster
```
