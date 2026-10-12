# Deployment into the local kind cluster

This is the **second OpenTofu root**. It installs the selected ingress/Gateway
controller, Heimdall, the echo app and optional observability. It does not
create or delete kind, MetalLB, RustFS or Headlamp; those belong to
[`../../cluster/local/`](../../cluster/local/README.md).

For end users, start with [`../../README.md`](../../README.md) and use an
`install-*-demo` recipe. For development iterations:

```bash
cd examples/kubernetes
just install-contour-demo
export KUBECONFIG="$(just kubeconfig)"
kubectl get svc -A
```

The public install recipes delegate to the private `_install_demo` recipe,
which accepts a controller, Gateway API flag, global integration flag and two
optional bucket flags. It first applies `cluster/local` (which is a no-op for
an unchanged cluster), then applies this deployment root. `OBS=true` enables
the monitoring stack and requests its buckets automatically; without OBS the
demo stays small.
The default RuleSet source is Kubernetes CRDs.

Both OpenTofu roots must be initialized independently. `just` reads the local
cluster's kubeconfig and RustFS endpoint and passes them to this deployment
root; no third bootstrap state or duplicated credentials are required.
Use `just delete-demo` to remove this root without destroying the local base,
or `just delete-local-cluster` to destroy the deployment before the base.

See [`../../DEVELOPMENT.md`](../../DEVELOPMENT.md) for telemetry checks,
advanced bucket tests, provider pinning and known limitations.
