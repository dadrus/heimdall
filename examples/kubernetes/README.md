# Kubernetes Quickstarts

This directory contains working examples described in the getting started, as well as in the integration guides of the documentation. The demonstration of the decision operation mode is done via integration with the corresponding ingress controllers. As of now, these are [Contour](https://projectcontour.io) and the [NGINX Ingress Controller](https://docs.nginx.com/nginx-ingress-controller/).

# Prerequisites

To be able to install and play with quickstarts, you need

* [Just](https://github.com/casey/just), which is used to ease the installation and setup
* [Helm](https://helm.sh/) as it is used to install most of the required services, including heimdall
* [Kustomize](https://kustomize.io/), which is used to build the configuration of the demo service depending on the used ingress controller.
* [kubectl](https://kubernetes.io/docs/reference/kubectl/), used to apply the configuration and which you will need to inspect the cluster
* [kind](https://kind.sigs.k8s.io/), used to create a local kubernetes cluster using docker
* [Docker](https://www.docker.com/) to be able running containers
* [curl](https://curl.se/) to play around with the exposed APIs of the setup

# Demo with NGINX Ingress Controller

In that setup heimdall is integrated with NGINX Ingress Controller. All incoming requests are sent to NGINX, which then contacts heimdall as external authorization middleware and depending on the response from heimdall either forwards the request to the upstream service, or directly responses with an error from heimdall.

1. Set up the demo

   ```bash
   just install-ngnix-demo
   ```
   
   Depending on your internet connection, it may take some minutes. So, maybe it's time to grab some coffee :)
   When just finishes doing its job, you'll have a fully configured kubernetes cluster running locally.
2. Check which IP is used for the ingress-controller and set a variable to that value. You can easily achieve this with
   ```bash
   export SERVICE_IP=$(kubectl get svc --namespace nginx-ingress-controller nginx-ingress-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
   ```
   It is required for communication purposes with the demo service
3. Play with it

   ```bash
   curl -v --resolve echo-app.local:80:${SERVICE_IP} http://echo-app.local/anon/foo
   curl -v --resolve echo-app.local:80:${SERVICE_IP} http://echo-app.local/pub/foo
   curl -v --resolve echo-app.local:80:${SERVICE_IP} http://echo-app.local/foo
   ```

   Check the responses

4. Delete the cluster

   ```bash
   just delete-cluster
   ```

# Demo with Contour Ingress Controller

In that setup heimdall is integrated with Contour Ingress Controller. All incoming requests are sent to Contour, which then contacts heimdall as external authorization middleware and depending on the response from heimdall either forwards the request to the upstream service, or directly responses with an error from heimdall.

1. Set up the demo

   ```bash
   just install-contour-demo
   ```

   Depending on your internet connection, it may take some minutes. So, maybe it's time to grab some coffee :)
   When just finishes doing its job, you'll have a fully configured kubernetes cluster running locally.
2. Check which IP is used for the ingress controller and set a variable to that value. You can easily achieve this with
   ```bash
   export SERVICE_IP=$(kubectl get svc --namespace projectcontour contour-ingress-controller-envoy -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
   ```
   It is required for communication purposes with the demo service
3. Play with it

   ```bash
   curl -v --resolve echo-app.local:443:${SERVICE_IP} https://echo-app.local/anon/foo
   curl -v --resolve echo-app.local:443:${SERVICE_IP} https://echo-app.local/pub/foo
   curl -v --resolve echo-app.local:443:${SERVICE_IP} https://echo-app.local/foo
   ```

   Check the responses

4. Delete the cluster

   ```bash
   just delete-cluster
   ```
