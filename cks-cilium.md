# CKS Practice — Scenario 16: Cilium Network Policy

## Context
Namespace `app-ns` has a Deployment `web`. Configure Cilium policies for:
1. Allow Pods in `app-ns` to access `web` Pods
2. Require mutual authentication
3. Allow host access to `web` Pods without mutual auth

## Setup
```bash
kubectl create namespace app-ns
kubectl label namespace app-ns name=app-ns
kubectl create deployment web --image=nginx -n app-ns
kubectl expose deployment web --port=80 -n app-ns
```

## Solution

### Policy 1: Allow namespace with mutual auth
```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-app-ns-mutual-auth
  namespace: app-ns
spec:
  endpointSelector:
    matchLabels:
      app: web
  ingress:
  - fromEndpoints:
    - matchLabels:
        k8s:io.kubernetes.pod.namespace: app-ns
    authentication:
      mode: "required"
```

### Policy 2: Allow host access without mutual auth
```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-host-no-auth
  namespace: app-ns
spec:
  endpointSelector:
    matchLabels:
      app: web
  ingress:
  - fromEntities:
    - host
```

## Key Concepts
- `authentication.mode: "required"` = mutual TLS required
- `fromEntities: [host]` = allow traffic from the node itself
- Cilium policies are additive — multiple policies combine with OR logic
