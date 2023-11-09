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
   just install-<ingress controller>-decision-demo
   ```

with `<ingress controller>` being either `contour`, `nginx`, `haproxy`, or `emissary`. That command line will install and set up a kind based k8s cluster locally including all required services and configuring the used ingress controller to forward all incoming requests to heimdall as external authorization middleware. Depending on the response from heimdall the ingress controller will either forward the request to the upstream service (in that case a simple echo service), or directly respond with an error from heimdall to the client.

Depending on your internet connection, it may take some minutes. So, maybe it's time to grab some coffee :)

# Play with the demo

Check which IP is used for the ingress-controller and set a variable to that value. You can easily achieve this by querying the LB IP address of the used ingress controller with e.g. 

```bash
export SERVICE_IP=$(kubectl get svc -n nginx-ingress-controller nginx-ingress-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
```

for NGINX. 

That IP is required for communication purposes with the demo service.

Now, use

```bash
curl -vk --resolve echo-app.local:443:${SERVICE_IP} https://echo-app.local/anon/foo
curl -vk --resolve echo-app.local:443:${SERVICE_IP} https://echo-app.local/pub/foo
curl -vk --resolve echo-app.local:443:${SERVICE_IP} https://echo-app.local/redir/foo
curl -vk --resolve echo-app.local:443:${SERVICE_IP} https://echo-app.local/foo
```

and check the responses.

Please note: Since nginx does not support 302 response codes from an external auth service, the call to `https://echo-app.local/redir/foo` will result in a 500 error code returned by nginx.

# Delete the demo

```bash
just delete-cluster
```
