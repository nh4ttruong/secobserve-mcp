# Deploying on Kubernetes

`kubernetes/` holds a Deployment, a Service and a NetworkPolicy to edit and apply; `helm/secobserve-mcp` is the same three objects parameterised through `values.yaml`.
Both are a starting point to adapt: no Ingress, no TLS, no autoscaling — how this is exposed is the operator's decision.

## The server has no authentication of its own

The HTTP transport authenticates nobody.
Anything that can open a connection to port 8931 can call every tool with the permissions of the single `SECOBSERVE_API_TOKEN` in the pod, and there is no per-caller identity to turn on.
That is why the NetworkPolicy ships as part of the deployment rather than as an option: it is the only thing between that token and the rest of the cluster.
Put an authenticating gateway in front, point the policy at it, and do not expose 8931 through an Ingress or a LoadBalancer.

## Create the Secret

The token never goes in a manifest; create it yourself and reference it by name.

```bash
kubectl create secret generic secobserve-mcp-token --from-literal=token="$SECOBSERVE_API_TOKEN"
```

## Plain manifests

Set `SECOBSERVE_BASE_URL` in `kubernetes/deployment.yaml` and both gateway selectors in `kubernetes/networkpolicy.yaml`, then apply the directory.

```bash
kubectl apply -f kubernetes/
```

## Helm

```bash
helm install secobserve-mcp ./helm/secobserve-mcp \
  --set secobserve.baseUrl=https://secobserve.example.com \
  --set secobserve.tokenSecret.name=secobserve-mcp-token \
  --set networkPolicy.gateway.namespace=mcp-gateway \
  --set networkPolicy.gateway.podSelector."app\.kubernetes\.io/name"=mcp-gateway
```

The install fails when the gateway namespace or selector is unset or empty, and no value renders a policy that allows everything.

## What the defaults decide for you

- `SECOBSERVE_READ_ONLY` is `true`, because one token serves every caller of the port; writes are opt-in with `--set secobserve.readOnly=false`.
- `SECOBSERVE_ALLOW_DELETE` is `false`, and deletes cascade in SecObserve.
- The readiness probe hits `/healthz`, which never calls SecObserve, so it only reports that the listener is up. A SecObserve outage leaves the pod in the Service on purpose: there is no healthier replica to fail over to, and the tool's error text says more than a refused connection.
- The image tag is pinned, since `latest` would move the tool surface under an already-configured client.
- Exports land in an `emptyDir` and cannot be fetched over HTTP, so the export tools are of little use in this deployment.
- `args` replaces the image `CMD`. If a newer image refuses to start in HTTP mode with a token from the environment, it wants an explicit opt-in flag: run the image with `--help` and add it there.
