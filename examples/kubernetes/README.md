# Kubernetes Quickstarts

This directory contains working examples described in the getting started, as well as in the integration guides of the documentation. The demonstration of the decision operation mode is done via integration with the different Ingress Controller, respectively Gateway API implementations.

**Note:** The main branch may have breaking changes (see pending release PRs for details under https://github.com/dadrus/heimdall/pulls) which would make the usage of the referenced heimdall images impossible (even though the configuration files and rules reflect the latest changes). In such situations you'll have to use the `dev` image, build a heimdall image by yourself and update the setups to use it, or switch to a tagged (released) version.

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

Depending on the Ingress Controller/Gateway API you want to install the demo for, execute

```bash
   just install-<setup-type>-demo
   ```

with `<setup-type>` being one of the following options:

* `ngnix` - integration with heimdall happens using annotations on Ingress Resource level.
* `ngnix-global` - heimdall is integrated globally.
* `contour` - heimdall is integrated globally.
* `haproxy` - integration with heimdall happens using annotations on Ingress Resource level.
* `emissary` - heimdall is integrated globally.
* `envoygw` - heimdall is integrated on a gateway level.
* `traefik-ingress` - heimdall is integrated globally. Standard k8s Ingress Resource is used four routing.
* `traefik-ingress-route` - heimdall is integrated as Middleware resource, which is then referenced in a Traefik's IngressRoute resource of the upstream service.
* `traefik-gw` - heimdall is integrated globally.
* `istio-ingress-gw` - heimdall is integrated globally. Routing happens using Istio's VirtualService resource.
* `istio-gw` - heimdall is integrated on a gateway level.

That command line will install and set up a kind based k8s cluster locally including all required services and configuring the used ingress controller, gateway api, respectively a vendor specific router implementation to forward incoming requests to heimdall as external authentication/authorization middleware. Depending on the response from heimdall the router implementation will either forward the request to the upstream service (in that case a simple echo service), or directly respond with an error from heimdall to the client. The above setup does also include an observability stack based on grafana components (Alloy, Loki, Tempo, Prometheus, Pyroscope, Grafana) 

Depending on your internet connection, it may take some minutes. So, maybe it's time to grab some coffee :)

**Note:** It might happen that the installation of the MetalLB fails due to a bad IP range configured. In such case, just delete the cluster, change `KIND_SUBNET=$(docker network inspect kind -f "{{(index .IPAM.Config 0).Subnet}}")` to `KIND_SUBNET=$(docker network inspect kind -f "{{(index .IPAM.Config 1).Subnet}}")` or similar (to get an IPv4 subnet) in the `metallb/configure.sh` file and restart the setup of the demo.

# Play with the demo

Check which IP is used for the router implementation and set a variable to that value. You can easily achieve this by querying the LB IP address of the used router with e.g. 

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

# Observe Telemetry Data

Establish port forwarding for the grafana service with

```bash
kubectl -n monitoring port-forward service/grafana-grafana-operator-grafana-service 3000:3000
```

Open http://grafana.127.0.0.1.nip.io:3000 in your browser to access it. Username is set to `admin` and password is `monitoring`.

**Note:** If a traefik based setup is used, you'll also be able to see the entire request traces. For all other setups, tracing is limited to heimdall only (configuration of other routers for OTEL is a TODO).

# Delete the demo

```bash
just delete-cluster
```
