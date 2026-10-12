# Kubernetes Quickstarts

These examples let you try Heimdall in **decision mode** with different
Kubernetes ingress controllers and Gateway API implementations. An echo
application is protected by Heimdall, which decides whether requests may
reach it.

> **Local demo only:** The cluster uses development certificates, demo
> credentials and convenient local administrator access. Do not expose its
> dashboards or reuse these settings in production.

## Prerequisites

- [Docker](https://www.docker.com/)
- [kind](https://kind.sigs.k8s.io/)
- [kubectl](https://kubernetes.io/docs/reference/kubectl/)
- [OpenTofu](https://opentofu.org/docs/intro/install/) **1.12.6**
- [just](https://github.com/casey/just)
- [curl](https://curl.se/)

## Install the demo

Choose the corresponding `just install-<setup-type>-demo` recipe:

- `install-nginx-demo` – NGINX, annotation on the Ingress resource
- `install-nginx-global-demo` – NGINX, global integration
- `install-contour-demo` – Contour, global integration
- `install-haproxy-demo` – HAProxy, annotation on the Ingress resource
- `install-haproxy-global-demo` – HAProxy, global integration
- `install-emissary-demo` – Emissary, global integration
- `install-envoygw-demo` – Envoy Gateway, Gateway API
- `install-traefik-ingress-demo` – Traefik, Kubernetes Ingress
- `install-traefik-ingress-route-demo` – Traefik, IngressRoute middleware
- `install-traefik-gw-demo` – Traefik, Gateway API
- `install-istio-ingress-gw-demo` – Istio, classic ingress gateway
- `install-istio-gw-demo` – Istio, Gateway API

> **NGINX Ingress maintenance:** The Kubernetes `ingress-nginx` project was
> retired in March 2026. It remains here only as a local integration
> example and no longer receives security fixes. Prefer a maintained
> controller for new deployments.

For example, to use Contour:

```bash
just install-contour-demo
```

The command creates a local kind cluster and installs the selected ingress
controller, Heimdall and an echo application.

To install the same demo with **observability** (Prometheus, Loki, Tempo,
Alloy, Grafana and Pyroscope), use:

```bash
OBS=true just install-contour-demo
```

# Play with the demo

Export the kubeconfig in your current shell session so that `kubectl` uses
the local cluster:

```bash
export KUBECONFIG="$(just kubeconfig)"
```

Check which IP is used for the router implementation and set a variable to that value. You can easily achieve this by querying the LB IP address of the used router with e.g.

```bash
export SERVICE_IP=$(kubectl get svc --all-namespaces -o jsonpath="{.items[?(@.spec.type=='LoadBalancer')].status.loadBalancer.ingress[0].ip}")
```

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

## Dashboards

The local cluster includes Headlamp and the RustFS development console.
Each recipe below opens a port-forward bound to `127.0.0.1` (keep its
terminal open while browsing):

```bash
just headlamp-dashboard       # Headlamp: http://127.0.0.1:8080
just storage-dashboard        # RustFS:   http://127.0.0.1:9001
```

If you installed with `OBS=true`, you can also open Grafana:

```bash
just observability-dashboard  # Grafana:  http://127.0.0.1:3000
```

Sign in using **admin / admin** (local demo only) and open
**Dashboards → Heimdall → Heimdall Metrics**. The existing Heimdall
metrics dashboard and the Prometheus, Loki, Tempo and Pyroscope data sources
are provisioned automatically.

## Delete the demo

```bash
just delete-local-cluster
```

This removes both the demo deployment and the local kind cluster. To remove the deployment but keep
the kind cluster and its storage, use `just delete-demo` instead.
