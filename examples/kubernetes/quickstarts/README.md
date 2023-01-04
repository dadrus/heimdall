# Kubernetes Quickstarts

This directory contains examples described in the getting started section of the documentation. The demonstration of the decision operation mode is done via integration with the available Ingress Controller.

# Decision Mode with NGINX Ingress Controller

In that setup heimdall is integrated with NGINX Ingress Controller. All incoming requests are sent to NGINX, which then contacts heimdall as external authorization middleware and depending on the response from heimdall either forwards the request to the upstream service, or directly responses with an error from heimdall.

Prerequisite: 
* You need a running Kubernetes cluster in which you can install heimdall including CRDs, service account, etc.
* The default ingress class is configured

If you don't have one, you can easily create it using kind. Checkout the `examples/kind` directory. You'll find a config and a description on how to create a cluster. It also sets the default ingress class.

1. Deploy heimdall into the cluster

   If you have not added heimdall's Helm repository, do the following:
   
   ```bash
   helm repo add dadrus https://dadrus.github.io/heimdall/charts
   helm repo update
   ```

   Otherwise, just install heimdall

   ```bash
   helm install heimdall -f heimdall.yaml --namespace heimdall --create-namespace dadrus/heimdall
   ```
   
   The above command with install heimdall into a namespace `heimdall` (it will create the namespace as well). The name of the chart installation is `heimdall` as well.

2. Deploy a simple application, which just echoes everything back.

   ```bash
   kustomize build | kubectl apply -f -
   ```

3. Play with it

   ```bash
   curl -v http://127.0.0.1/anonymous
   curl -v http://127.0.0.1/public
   curl -v http://127.0.0.1/foo
   ```

   Check the responses

4. Delete the simple application

   ```bash
   kustomize build | kubectl delete -f -
   ```
   
5. Uninstall heimdall

   ```bash
   helm uninstall heimdall
   ```
