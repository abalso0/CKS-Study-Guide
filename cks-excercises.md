# CKS Exam Exercises 

---

## HOW TO USE THIS FILE
1. Read the task — don't look at the solution
2. Try it on KillerCoda CKS playground
3. Check your answer against the solution
4. Repeat until you can do it from memory

---

## CLUSTER SETUP (run once on KillerCoda)
```bash
# Verify cluster is ready
kubectl get nodes
kubectl get pods -A
```

---

# SECTION A — System Hardening  (WEAK AREA)

---

## Exercise A1: Harden the Kubelet

**Task:**
On node `node01`, ensure the kubelet:
- Disables anonymous authentication
- Uses Webhook authorization

<details>
<summary>Solution</summary>

```bash
ssh node01
sudo -i
vi /var/lib/kubelet/config.yaml
```

```yaml
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
authorization:
  mode: Webhook
```

```bash
systemctl daemon-reload && systemctl restart kubelet
# Verify
curl -sk https://localhost:10250/pods | head -5
# Should return 401 Unauthorized, not pod list
```
</details>

---

## Exercise A2: Harden the API Server

**Task:**
Edit the API server manifest to:
- Disable anonymous access
- Set authorization mode to `Node,RBAC`
- Enable `NodeRestriction` admission plugin

<details>
<summary>Solution</summary>

```bash
vi /etc/kubernetes/manifests/kube-apiserver.yaml
```

Add/update these flags:
```yaml
- --anonymous-auth=false
- --authorization-mode=Node,RBAC
- --enable-admission-plugins=NodeRestriction
```

```bash
# Wait for API server to restart
kubectl get pods -n kube-system | grep apiserver
# Verify anonymous is blocked
kubectl get pods --as=system:anonymous 2>&1 | grep Forbidden
```
</details>

---

## Exercise A3: Secure Docker Daemon

**Task:**
- Remove user `dev` from the `docker` group
- Ensure `/var/run/docker.sock` is owned by `root:docker` with permissions `660`

<details>
<summary>Solution</summary>

```bash
gpasswd -d dev docker
chown root:docker /var/run/docker.sock
chmod 660 /var/run/docker.sock

# Verify
groups dev          # docker should not appear
ls -la /var/run/docker.sock
```
</details>

---

## Exercise A4: Fix etcd TLS

**Task:**
Ensure etcd is configured with:
- `--client-cert-auth=true`
- `--peer-client-cert-auth=true`

<details>
<summary>Solution</summary>

```bash
vi /etc/kubernetes/manifests/etcd.yaml
```

Ensure these flags exist:
```yaml
- --client-cert-auth=true
- --peer-client-cert-auth=true
- --cert-file=/etc/kubernetes/pki/etcd/server.crt
- --key-file=/etc/kubernetes/pki/etcd/server.key
- --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
```

```bash
# Verify etcd health
ETCDCTL_API=3 etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  endpoint health
```
</details>

---

## Exercise A5: Upgrade Worker Node

**Task:**
Node `node01` runs Kubernetes `1.32.0`. Upgrade it to `1.32.1`.

<details>
<summary>Solution</summary>

```bash
# Control plane
kubectl drain node01 --ignore-daemonsets --delete-emptydir-data --force

ssh node01
sudo -i

apt-mark unhold kubeadm
apt-get install -y kubeadm=1.32.1-1.1
apt-mark hold kubeadm
kubeadm upgrade node

apt-mark unhold kubelet kubectl
apt-get install -y kubelet=1.32.1-1.1 kubectl=1.32.1-1.1
apt-mark hold kubelet kubectl

systemctl daemon-reload && systemctl restart kubelet
exit

kubectl uncordon node01
kubectl get nodes  # node01 should show v1.32.1
```
</details>

---

# SECTION B — Minimize Microservice Vulnerabilities  (WEAK AREA)

---

## Exercise B1: Fix Container Security Context

**Setup:**
```bash
kubectl create deployment app --image=nginx
```

**Task:**
Edit the deployment `app` to set on the container:
- `runAsUser: 30000`
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`

<details>
<summary>Solution</summary>

```bash
kubectl edit deployment app
```

```yaml
spec:
  template:
    spec:
      containers:
      - name: nginx
        image: nginx
        securityContext:
          runAsUser: 30000
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
```

```bash
kubectl get pod -l app=app -o jsonpath='{.items[0].spec.containers[0].securityContext}'
```
</details>

---

## Exercise B2: Fix Dockerfile

**Task:**
Fix this Dockerfile to follow security best practices:

```dockerfile
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
COPY app /app
CMD ["/app"]
```

<details>
<summary>Solution</summary>

```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
COPY app /app
USER nobody
CMD ["/app"]
```

And in the Deployment:
```yaml
securityContext:
  runAsUser: 65535
  readOnlyRootFilesystem: true
  privileged: false
```
</details>

---

## Exercise B3: Disable ServiceAccount Token Auto-Mount

**Setup:**
```bash
kubectl create namespace prod
kubectl create serviceaccount app-sa -n prod
kubectl create deployment app --image=nginx -n prod
```

**Task:**
1. Disable `automountServiceAccountToken` on ServiceAccount `app-sa`
2. In the Deployment, mount the token manually via a projected volume (read-only)

<details>
<summary>Solution</summary>

```bash
kubectl edit serviceaccount app-sa -n prod
```
```yaml
automountServiceAccountToken: false
```

```bash
kubectl edit deployment app -n prod
```
```yaml
spec:
  template:
    spec:
      serviceAccountName: app-sa
      automountServiceAccountToken: false
      volumes:
      - name: token
        projected:
          sources:
          - serviceAccountToken:
              path: token
              expirationSeconds: 3600
              audience: api
      containers:
      - name: nginx
        image: nginx
        volumeMounts:
        - name: token
          mountPath: /var/run/secrets/kubernetes.io/serviceaccount
          readOnly: true
```
</details>

---

## Exercise B4: NetworkPolicy — Deny All, Allow One Namespace

**Setup:**
```bash
kubectl create namespace backend
kubectl create namespace frontend
kubectl label namespace frontend name=frontend
kubectl create deployment api --image=nginx -n backend
kubectl expose deployment api --port=80 -n backend
```

**Task:**
In namespace `backend`, deny all ingress traffic. Allow ingress only from Pods in namespace `frontend`.

<details>
<summary>Solution</summary>

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-only
  namespace: backend
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: frontend
```

```bash
kubectl apply -f netpol.yaml
kubectl get networkpolicy -n backend
```
</details>

---

## Exercise B5: Pod Security Standards — Restricted

**Setup:**
```bash
kubectl create namespace secure-ns
kubectl label namespace secure-ns \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest
kubectl create deployment bad-app --image=nginx -n secure-ns
```

**Task:**
The Deployment `bad-app` fails to schedule. Fix it to comply with `restricted` PSS.

<details>
<summary>Solution</summary>

```bash
kubectl edit deployment bad-app -n secure-ns
```

```yaml
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: nginx
        image: nginx
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
```

```bash
kubectl get pods -n secure-ns  # Pod should be Running
```
</details>

---

## Exercise B6: ImagePolicyWebhook

**Task:**
Configure the API server to use ImagePolicyWebhook. Set it to **deny** images when the webhook backend is unavailable.

<details>
<summary>Solution</summary>

Create `/etc/kubernetes/admission/config.yaml`:
```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: ImagePolicyWebhook
  configuration:
    imagePolicy:
      kubeConfigFile: /etc/kubernetes/admission/kubeconfig.yaml
      allowTTL: 50
      denyTTL: 50
      retryBackoff: 500
      defaultAllow: false
```

Edit `/etc/kubernetes/manifests/kube-apiserver.yaml`:
```yaml
- --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
- --admission-control-config-file=/etc/kubernetes/admission/config.yaml
```
</details>

---

## Exercise B7: TLS Secret + Ingress

**Task:**
1. Create a TLS secret `myapp-tls` from existing `tls.crt` and `tls.key` files
2. Create an Ingress for service `myapp` on port 80 with TLS termination and SSL redirect

<details>
<summary>Solution</summary>

```bash
kubectl create secret tls myapp-tls --cert=tls.crt --key=tls.key
```

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: myapp-ingress
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - myapp.example.com
    secretName: myapp-tls
  rules:
  - host: myapp.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: myapp
            port:
              number: 80
```
</details>

---

## Exercise B8: Cilium Network Policy with Mutual Auth

**Setup:**
```bash
kubectl create namespace app-ns
kubectl label namespace app-ns name=app-ns
kubectl create deployment web --image=nginx -n app-ns
```

**Task:**
1. Allow Pods in `app-ns` to access `web` Pods with mutual authentication required
2. Allow host access to `web` Pods without mutual auth

<details>
<summary>Solution</summary>

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-with-auth
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
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: allow-host
  namespace: app-ns
spec:
  endpointSelector:
    matchLabels:
      app: web
  ingress:
  - fromEntities:
    - host
```
</details>

---

# SECTION C — Monitoring, Logging and Runtime Security  (WEAK AREA)

---

## Exercise C1: Write a Custom Falco Rule

**Task:**
Write a Falco rule that:
- Detects any process opening `/dev/mem`
- Outputs: pod name, namespace, command, user
- Priority: WARNING

Then find the offending Pod and scale its Deployment to 0.

<details>
<summary>Solution</summary>

Create `/etc/falco/rules.d/custom.yaml`:
```yaml
- rule: Detect /dev/mem Access
  desc: Alert when any process reads /dev/mem
  condition: open_read and fd.name = /dev/mem
  output: "/dev/mem accessed (user=%user.name cmd=%proc.cmdline pod=%k8s.pod.name ns=%k8s.ns.name)"
  priority: WARNING
  tags: [filesystem]
```

```bash
systemctl restart falco

# Find the bad pod
journalctl -u falco | grep "/dev/mem"
# or
kubectl logs -n falco -l app=falco | grep "/dev/mem"

# Scale to 0
kubectl scale deployment <name> --replicas=0
```
</details>

---

## Exercise C2: Configure Audit Logging

**Task:**
Configure the API server with:
- Audit policy file at `/etc/kubernetes/audit/policy.yaml`
- Log path: `/var/log/kubernetes/audit.log`
- Max 2 backup files
- Max age: 7 days

<details>
<summary>Solution</summary>

```bash
mkdir -p /etc/kubernetes/audit
```

Create `/etc/kubernetes/audit/policy.yaml`:
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: None
  users: ["system:kube-proxy"]
- level: Metadata
  resources:
  - group: ""
    resources: ["secrets", "configmaps"]
- level: RequestResponse
  resources:
  - group: ""
    resources: ["pods"]
- level: Metadata
```

Edit `/etc/kubernetes/manifests/kube-apiserver.yaml`:
```yaml
- --audit-policy-file=/etc/kubernetes/audit/policy.yaml
- --audit-log-path=/var/log/kubernetes/audit.log
- --audit-log-maxbackup=2
- --audit-log-maxage=7
- --audit-log-maxsize=100
```

Also mount the audit dir as a hostPath volume in the manifest.

```bash
# Verify
ls /var/log/kubernetes/audit.log
tail -f /var/log/kubernetes/audit.log | python3 -m json.tool
```
</details>

---

## Exercise C3: SPDX BOM — Find and Remove Vulnerable Image

**Task:**
Two images are used in Deployment `multi-app`: `alpine:3.18.0` and `alpine:3.19.1`.
Find which one contains `libcrypto3` and remove that container from the Deployment.

<details>
<summary>Solution</summary>

```bash
bom generate --image alpine:3.18.0 --output alpine-3.18.spdx
bom generate --image alpine:3.19.1 --output alpine-3.19.spdx

grep libcrypto3 alpine-3.18.spdx
grep libcrypto3 alpine-3.19.spdx
```

Whichever file has a match — remove that container:
```bash
kubectl edit deployment multi-app
# Delete the container block using the vulnerable image
```
</details>

---

# SECTION D — Other Exam Topics

---

## Exercise D1: Create TLS Secret (referenced by existing Deployment)

**Task:**
A Deployment already references a secret named `app-tls`. Create it from `tls.crt` and `tls.key`.

<details>
<summary>Solution</summary>

```bash
kubectl create secret tls app-tls --cert=tls.crt --key=tls.key
kubectl get secret app-tls
```
</details>

---

## Exercise D2: Pod Accessing /dev/mem — Full Workflow

**Task (combines Falco + scale down):**
1. Write Falco rule for `/dev/mem` access
2. Restart Falco
3. Check logs to identify the Pod
4. Scale the Deployment to 0

*(See Exercise C1 for full solution)*

---

# QUICK REFERENCE CARD

```
KUBELET HARDENING
  /var/lib/kubelet/config.yaml
  anonymous.enabled: false | authorization.mode: Webhook

API SERVER FLAGS
  --anonymous-auth=false
  --authorization-mode=Node,RBAC
  --enable-admission-plugins=NodeRestriction

AUDIT LOG FLAGS
  --audit-policy-file=  --audit-log-path=
  --audit-log-maxbackup=2  --audit-log-maxage=7

PSS RESTRICTED (all required)
  runAsNonRoot: true
  seccompProfile.type: RuntimeDefault
  allowPrivilegeEscalation: false
  capabilities.drop: [ALL]

FALCO RULE STRUCTURE
  condition: open_read and fd.name = /dev/mem
  output: "... pod=%k8s.pod.name ns=%k8s.ns.name"
  priority: WARNING

IMAGEPOLICYWEBHOOK
  defaultAllow: false  ← deny when backend down

SA TOKEN MANUAL MOUNT
  automountServiceAccountToken: false on SA + Deployment
  projected volume → serviceAccountToken

INGRESS TLS ANNOTATION
  nginx.ingress.kubernetes.io/ssl-redirect: "true"

SPDX BOM
  bom generate --image <img> --output file.spdx
  grep <package> file.spdx

DOCKER GROUP
  gpasswd -d <user> docker
  chown root:docker /var/run/docker.sock

NODE UPGRADE ORDER
  drain → ssh → kubeadm upgrade node → kubelet/kubectl → restart → uncordon
```

---

## EXAM DAY TIPS
- Read each question twice before touching the keyboard
- Always `kubectl config use-context <ctx>` at the start of each question
- Use `kubectl explain` when you forget field names
- `--dry-run=client -o yaml` to generate manifests fast
- Check `/etc/kubernetes/manifests/` for static pod configs
- After editing API server manifest, wait ~60s for it to restart
```
