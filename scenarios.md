# CKS Practice Scenarios - KillerCoda Style

---

## PART 1 — Minimize Microservice Vulnerabilities

---

### Scenario 1: Fix Insecure Container Security Context

**Setup:**
```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app-deploy
  template:
    metadata:
      labels:
        app: app-deploy
    spec:
      containers:
      - name: nginx
        image: nginx
        # NOTE: No securityContext — this is the problem
EOF
kubectl wait --for=condition=available deployment/app-deploy --timeout=60s
```

**Task:**
Edit the Deployment `app-deploy` and add a security context to the container:
- `runAsUser: 30000`
- `readOnlyRootFilesystem: true`
- `allowPrivilegeEscalation: false`

**Solution:**
```bash
kubectl edit deployment app-deploy
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

**Verify:**
```bash
kubectl get pod -l app=app-deploy -o jsonpath='{.items[0].spec.containers[0].securityContext}'
# Expected: {"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"runAsUser":30000}
```

**Cleanup:**
```bash
kubectl delete deployment app-deploy
```

---

### Scenario 2: Dockerfile Security Best Practices

**Setup:**
```bash
mkdir -p /tmp/dockerfile-lab && cd /tmp/dockerfile-lab

cat <<'EOF' > app.sh
#!/bin/sh
echo "Hello from secure container"
sleep 3600
EOF
chmod +x app.sh

# Create the INSECURE Dockerfile
cat <<'EOF' > Dockerfile
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
COPY app.sh /app.sh
CMD ["/app.sh"]
EOF

docker build -t insecure-app:v1 .

cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dockerfile-lab
spec:
  replicas: 1
  selector:
    matchLabels:
      app: dockerfile-lab
  template:
    metadata:
      labels:
        app: dockerfile-lab
    spec:
      containers:
      - name: app
        image: insecure-app:v1
EOF
```

**Task:**
1. Fix the Dockerfile: use specific tag (not `latest`), add `USER nobody`
2. Fix the Deployment: set `runAsUser: 65535`, `readOnlyRootFilesystem: true`, `privileged: false`

**Solution — Fixed Dockerfile:**
```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
COPY app.sh /app.sh
USER nobody
CMD ["/app.sh"]
```

```bash
docker build -t secure-app:v1 .
```

**Solution — Fixed Deployment:**
```bash
kubectl edit deployment dockerfile-lab
```
```yaml
      containers:
      - name: app
        image: secure-app:v1
        securityContext:
          runAsUser: 65535
          readOnlyRootFilesystem: true
          privileged: false
```

**Verify:**
```bash
kubectl get pods -l app=dockerfile-lab
kubectl exec $(kubectl get pod -l app=dockerfile-lab -o jsonpath='{.items[0].metadata.name}') -- id
# Expected: uid=65535(nobody)
kubectl exec $(kubectl get pod -l app=dockerfile-lab -o jsonpath='{.items[0].metadata.name}') -- touch /tmp/test 2>&1
# Expected: Read-only file system
```

**Cleanup:**
```bash
kubectl delete deployment dockerfile-lab
rm -rf /tmp/dockerfile-lab
```

---

### Scenario 3: Disable ServiceAccount Token Auto-Mounting

**Setup:**
```bash
kubectl create namespace prod

cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: prod
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-deploy
  namespace: prod
spec:
  replicas: 1
  selector:
    matchLabels:
      app: app-deploy
  template:
    metadata:
      labels:
        app: app-deploy
    spec:
      serviceAccountName: app-sa
      containers:
      - name: nginx
        image: nginx
EOF
kubectl wait --for=condition=available deployment/app-deploy -n prod --timeout=60s
```

**Verify the problem — token is auto-mounted:**
```bash
kubectl exec -n prod $(kubectl get pod -n prod -l app=app-deploy -o jsonpath='{.items[0].metadata.name}') -- ls /var/run/secrets/kubernetes.io/serviceaccount/
# You'll see: ca.crt, namespace, token — this is the problem
```

**Task:**
1. Disable `automountServiceAccountToken` on ServiceAccount `app-sa`
2. Edit the Deployment to disable auto-mount and mount the token manually via a projected volume (read-only)

**Solution:**
```bash
kubectl edit serviceaccount app-sa -n prod
```
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-sa
  namespace: prod
automountServiceAccountToken: false
```

```bash
kubectl edit deployment app-deploy -n prod
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

**Verify:**
```bash
kubectl exec -n prod $(kubectl get pod -n prod -l app=app-deploy -o jsonpath='{.items[0].metadata.name}') -- ls /var/run/secrets/kubernetes.io/serviceaccount/
# Should only show: token (not ca.crt or namespace)
kubectl exec -n prod $(kubectl get pod -n prod -l app=app-deploy -o jsonpath='{.items[0].metadata.name}') -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
# Should show a JWT token
```

**Cleanup:**
```bash
kubectl delete namespace prod
```

---

### Scenario 4: NetworkPolicy — Deny All + Allow Specific Namespace

**Setup:**
```bash
kubectl create namespace backend
kubectl create namespace frontend
kubectl label namespace frontend name=frontend

cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: backend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
      - name: nginx
        image: nginx
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: backend
spec:
  selector:
    app: api
  ports:
  - port: 80
---
apiVersion: v1
kind: Pod
metadata:
  name: test-frontend
  namespace: frontend
  labels:
    app: test
spec:
  containers:
  - name: curl
    image: curlimages/curl
    command: ["sleep", "3600"]
---
apiVersion: v1
kind: Pod
metadata:
  name: test-other
  namespace: default
spec:
  containers:
  - name: curl
    image: curlimages/curl
    command: ["sleep", "3600"]
EOF

kubectl wait --for=condition=ready pod/test-frontend -n frontend --timeout=60s
kubectl wait --for=condition=ready pod/test-other -n default --timeout=60s
```

**Verify the problem — everyone can reach the api:**
```bash
kubectl exec -n frontend test-frontend -- curl -s --max-time 3 api.backend.svc
kubectl exec -n default test-other -- curl -s --max-time 3 api.backend.svc
# Both return nginx HTML — this is the problem
```

**Task:**
Create a NetworkPolicy in namespace `backend` that:
- Denies all ingress traffic
- Allows ingress only from Pods in namespace `frontend`

**Solution:**
```bash
cat <<'EOF' | kubectl apply -f -
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
EOF
```

**Verify:**
```bash
# This should WORK (frontend namespace)
kubectl exec -n frontend test-frontend -- curl -s --max-time 3 api.backend.svc | head -3

# This should FAIL/timeout (default namespace)
kubectl exec -n default test-other -- curl -s --max-time 3 api.backend.svc
# Expected: timeout
```

**Cleanup:**
```bash
kubectl delete namespace backend frontend
kubectl delete pod test-other -n default
```

---

### Scenario 5: Pod Security Standards — Restricted

**Setup:**
```bash
kubectl create namespace secure-ns
kubectl label namespace secure-ns \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest

cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad-deploy
  namespace: secure-ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: bad-deploy
  template:
    metadata:
      labels:
        app: bad-deploy
    spec:
      containers:
      - name: nginx
        image: nginx
EOF
```

**Verify the problem:**
```bash
kubectl get pods -n secure-ns
# No pods running — ReplicaSet can't create pods due to PSS violations
kubectl get events -n secure-ns --sort-by='.lastTimestamp' | tail -5
# You'll see: "violates PodSecurity" errors
```

**Task:**
Fix the Deployment `bad-deploy` to comply with `restricted` Pod Security Standard.

**Solution:**
```bash
kubectl edit deployment bad-deploy -n secure-ns
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

**Verify:**
```bash
kubectl get pods -n secure-ns
# Pod should now be Running (or CrashLoopBackOff if nginx needs root — that's OK, the PSS part is fixed)
kubectl get events -n secure-ns --sort-by='.lastTimestamp' | tail -5
# No more PSS violation errors
```

**Cleanup:**
```bash
kubectl delete namespace secure-ns
```

---

### Scenario 6: ImagePolicyWebhook

**Setup:**
```bash
# Create the required directories
mkdir -p /etc/kubernetes/admission

# Create the webhook kubeconfig (points to a dummy backend)
cat <<'EOF' > /etc/kubernetes/admission/kubeconfig.yaml
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://image-policy-webhook:1234/policy
    certificate-authority: /etc/kubernetes/pki/ca.crt
  name: image-policy
contexts:
- context:
    cluster: image-policy
    user: api-server
  name: image-policy
current-context: image-policy
users:
- name: api-server
  user:
    client-certificate: /etc/kubernetes/pki/apiserver.crt
    client-key: /etc/kubernetes/pki/apiserver.key
EOF

# Create the admission config with defaultAllow: true (INSECURE — this is the problem)
cat <<'EOF' > /etc/kubernetes/admission/config.yaml
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
      defaultAllow: true
EOF
```

**Task:**
1. Change `defaultAllow` to `false` (deny images when backend is unavailable)
2. Enable `ImagePolicyWebhook` admission plugin in the API server
3. Point the API server to the admission config file
4. Mount the admission directory into the API server pod

**Solution:**

Fix the admission config:
```bash
vi /etc/kubernetes/admission/config.yaml
# Change: defaultAllow: true → defaultAllow: false
```

Edit `/etc/kubernetes/manifests/kube-apiserver.yaml`:
```yaml
spec:
  containers:
  - command:
    - kube-apiserver
    # Add these flags:
    - --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
    - --admission-control-config-file=/etc/kubernetes/admission/config.yaml
    # Add volume mount:
    volumeMounts:
    - name: admission
      mountPath: /etc/kubernetes/admission
      readOnly: true
  # Add volume:
  volumes:
  - name: admission
    hostPath:
      path: /etc/kubernetes/admission
      type: DirectoryOrCreate
```

**Verify:**
```bash
# Wait for API server to restart (~60s)
kubectl get pods -n kube-system | grep apiserver

# Check the admission plugin is loaded
kubectl -n kube-system describe pod kube-apiserver-controlplane | grep admission
```

---

### Scenario 7: TLS Secret + Ingress with HTTPS

**Setup:**
```bash
# Generate self-signed cert
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /tmp/tls.key -out /tmp/tls.crt -subj "/CN=myapp.example.com"

# Create deployment and service
cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
      - name: nginx
        image: nginx
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: myapp
spec:
  selector:
    app: myapp
  ports:
  - port: 80
    targetPort: 80
EOF
kubectl wait --for=condition=available deployment/myapp --timeout=60s
```

**Task:**
1. Create a TLS secret named `myapp-tls` using the cert and key at `/tmp/tls.crt` and `/tmp/tls.key`
2. Create an Ingress for host `myapp.example.com` with TLS termination and SSL redirect annotation

**Solution:**
```bash
kubectl create secret tls myapp-tls --cert=/tmp/tls.crt --key=/tmp/tls.key
```

```bash
cat <<'EOF' | kubectl apply -f -
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
EOF
```

**Verify:**
```bash
kubectl get secret myapp-tls
kubectl get ingress myapp-ingress
kubectl describe ingress myapp-ingress | grep -A5 TLS
# Should show: myapp.example.com terminates with myapp-tls
```

**Cleanup:**
```bash
kubectl delete ingress myapp-ingress
kubectl delete secret myapp-tls
kubectl delete deployment myapp
kubectl delete service myapp
rm /tmp/tls.crt /tmp/tls.key
```

---

## PART 2 — Monitoring, Logging and Runtime Security

---

### Scenario 8: Custom Falco Rule — Detect /dev/mem Access

**Setup:**
```bash
# Ensure Falco is installed (on KillerCoda CKS it usually is)
systemctl status falco || echo "Falco not running as service"

# Create a bad pod that tries to access sensitive files
cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: bad-app
  template:
    metadata:
      labels:
        app: bad-app
    spec:
      containers:
      - name: bad
        image: busybox
        command: ["sh", "-c", "while true; do cat /dev/mem 2>/dev/null; sleep 30; done"]
        securityContext:
          privileged: true
EOF

# Create the Falco rules directory if it doesn't exist
mkdir -p /etc/falco/rules.d
```

**Task:**
1. Write a custom Falco rule in `/etc/falco/rules.d/custom.yaml` to detect `/dev/mem` access
2. Restart Falco
3. Check Falco logs to identify the bad Pod
4. Scale the bad Deployment to 0 replicas

**Solution:**

```bash
cat <<'EOF' > /etc/falco/rules.d/custom.yaml
- rule: Detect /dev/mem Access
  desc: Detects any process accessing /dev/mem
  condition: open_read and fd.name = /dev/mem
  output: "Sensitive file /dev/mem opened (user=%user.name command=%proc.cmdline pod=%k8s.pod.name ns=%k8s.ns.name)"
  priority: WARNING
  tags: [filesystem, mitre_discovery]
EOF
```

```bash
# Restart Falco
systemctl restart falco

# Wait a few seconds, then check logs
journalctl -u falco --since "1 minute ago" | grep "/dev/mem"
# Output will show: pod=bad-app-xxxxx ns=default

# Scale to 0
kubectl scale deployment bad-app --replicas=0
```

**Verify:**
```bash
kubectl get pods -l app=bad-app
# Expected: No resources found
```

**Cleanup:**
```bash
kubectl delete deployment bad-app
rm /etc/falco/rules.d/custom.yaml
systemctl restart falco
```

---

### Scenario 9: Audit Logging

**Setup:**
```bash
# Create the audit directory
mkdir -p /etc/kubernetes/audit
mkdir -p /var/log/kubernetes

# Verify current API server has NO audit flags
cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep audit
# Should return nothing
```

**Task:**
1. Create an audit policy at `/etc/kubernetes/audit/policy.yaml`:
   - Log `Metadata` for secrets and configmaps
   - Log `RequestResponse` for pods
   - Ignore `system:kube-proxy`
   - Default: `Metadata` for everything else
2. Configure the API server with:
   - Audit policy file
   - Log path: `/var/log/kubernetes/audit.log`
   - Max 2 backup files
   - Max age: 7 days

**Solution:**

Create the audit policy:
```bash
cat <<'EOF' > /etc/kubernetes/audit/policy.yaml
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
EOF
```

Edit `/etc/kubernetes/manifests/kube-apiserver.yaml`:
```bash
vi /etc/kubernetes/manifests/kube-apiserver.yaml
```

Add these flags to the `kube-apiserver` command:
```yaml
    - --audit-policy-file=/etc/kubernetes/audit/policy.yaml
    - --audit-log-path=/var/log/kubernetes/audit.log
    - --audit-log-maxage=7
    - --audit-log-maxbackup=2
    - --audit-log-maxsize=100
```

Add volume mounts to the container:
```yaml
    volumeMounts:
    # ... existing mounts ...
    - name: audit-policy
      mountPath: /etc/kubernetes/audit
      readOnly: true
    - name: audit-log
      mountPath: /var/log/kubernetes
```

Add volumes to the pod spec:
```yaml
  volumes:
  # ... existing volumes ...
  - name: audit-policy
    hostPath:
      path: /etc/kubernetes/audit
      type: DirectoryOrCreate
  - name: audit-log
    hostPath:
      path: /var/log/kubernetes
      type: DirectoryOrCreate
```

**Verify:**
```bash
# Wait ~60s for API server to restart
kubectl get pods -n kube-system | grep apiserver

# Check audit log exists and has entries
ls -la /var/log/kubernetes/audit.log
tail -5 /var/log/kubernetes/audit.log | python3 -m json.tool
```

---

### Scenario 10: Generate SPDX BOM and Remove Vulnerable Image

**Setup:**
```bash
# Install bom tool if not present
which bom || (curl -L https://github.com/kubernetes-sigs/bom/releases/latest/download/bom-linux-amd64 -o /usr/local/bin/bom && chmod +x /usr/local/bin/bom)

# Create a multi-container Deployment
cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: multi-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: multi-app
  template:
    metadata:
      labels:
        app: multi-app
    spec:
      containers:
      - name: container-a
        image: alpine:3.18.0
        command: ["sleep", "3600"]
      - name: container-b
        image: alpine:3.19.1
        command: ["sleep", "3600"]
EOF
kubectl wait --for=condition=available deployment/multi-app --timeout=120s
```

**Task:**
1. Use `bom` to generate SPDX documents for both Alpine images
2. Find which image contains `libcrypto3`
3. Remove that container from the Deployment

**Solution:**
```bash
# Generate SPDX for both images
bom generate --image alpine:3.18.0 --output /tmp/alpine-3.18.spdx
bom generate --image alpine:3.19.1 --output /tmp/alpine-3.19.spdx

# Search for libcrypto3
grep -l libcrypto3 /tmp/alpine-3.18.spdx /tmp/alpine-3.19.spdx
# Identify which file has the match
```

```bash
# Edit the deployment and remove the container with the vulnerable image
kubectl edit deployment multi-app
# Delete the entire container block for the matching image
```

**Verify:**
```bash
kubectl get deployment multi-app -o jsonpath='{.spec.template.spec.containers[*].image}'
# Should show only one image (the safe one)
kubectl get pods -l app=multi-app
# Pod should be running with 1/1 containers
```

**Cleanup:**
```bash
kubectl delete deployment multi-app
rm /tmp/alpine-3.18.spdx /tmp/alpine-3.19.spdx
```

---

## PART 3 — System Hardening

---

### Scenario 11: Fix Insecure Kubelet Configuration

**Setup:**
```bash
# Verify the problem — anonymous access is enabled
curl -sk https://localhost:10250/pods | head -20
# If you get pod data back, anonymous auth is ON (insecure)

# Or check the config directly
ssh node01
sudo cat /var/lib/kubelet/config.yaml | grep -A3 anonymous
# anonymous.enabled: true = INSECURE
exit
```

**Task:**
On `node01`, configure the kubelet to:
- Disable anonymous authentication
- Use Webhook authorization

**Solution:**
```bash
ssh node01
sudo -i
vi /var/lib/kubelet/config.yaml
```

Find and update these sections:
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
systemctl daemon-reload
systemctl restart kubelet
exit
```

**Verify:**
```bash
# From controlplane, test anonymous access to node01
curl -sk https://node01:10250/pods
# Expected: 401 Unauthorized (not pod data)
```

---

### Scenario 12: Fix Insecure etcd Configuration

**Setup:**
```bash
# Check current etcd config
cat /etc/kubernetes/manifests/etcd.yaml | grep -E "client-cert-auth|peer-client-cert-auth"
# If these flags are missing or set to false, etcd is insecure
```

**Task:**
Ensure etcd uses certificate-based authentication:
- `--client-cert-auth=true`
- `--peer-client-cert-auth=true`

**Solution:**
```bash
vi /etc/kubernetes/manifests/etcd.yaml
```

Ensure these flags exist in the etcd command:
```yaml
    - --cert-file=/etc/kubernetes/pki/etcd/server.crt
    - --key-file=/etc/kubernetes/pki/etcd/server.key
    - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
    - --client-cert-auth=true
    - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt
    - --peer-key-file=/etc/kubernetes/pki/etcd/peer.key
    - --peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
    - --peer-client-cert-auth=true
```

**Verify:**
```bash
# Wait for etcd to restart
kubectl get pods -n kube-system | grep etcd

# Test etcd health with certs
ETCDCTL_API=3 etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  endpoint health
# Expected: 127.0.0.1:2379 is healthy

# Test WITHOUT certs (should fail)
ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 endpoint health
# Expected: connection error (cert required)
```

---

### Scenario 13: Secure Docker Daemon

**Setup:**
```bash
# Create a test user and add to docker group (simulating the insecure state)
useradd -m dev-user
usermod -aG docker dev-user

# Verify the problem
groups dev-user
# Expected: dev-user : dev-user docker  ← user is in docker group (BAD)

ls -la /var/run/docker.sock
# Check current ownership
```

**Task:**
1. Remove user `dev-user` from the `docker` group
2. Ensure `/var/run/docker.sock` is owned by `root:docker` with permissions `660`

**Solution:**
```bash
# Remove user from docker group
gpasswd -d dev-user docker

# Fix socket ownership and permissions
chown root:docker /var/run/docker.sock
chmod 660 /var/run/docker.sock
```

**Verify:**
```bash
groups dev-user
# Expected: dev-user : dev-user  (no docker group)

ls -la /var/run/docker.sock
# Expected: srw-rw---- 1 root docker ... /var/run/docker.sock

# Test that dev-user can't use docker
su - dev-user -c "docker ps" 2>&1
# Expected: permission denied
```

**Cleanup:**
```bash
userdel -r dev-user
```

---

### Scenario 14: API Server Hardening

**Setup:**
```bash
# Check current API server config
cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -E "anonymous-auth|authorization-mode|admission-plugins"
# Note what's currently set
```

**Task:**
Edit the API server manifest to:
- Disable anonymous access (`--anonymous-auth=false`)
- Set authorization mode to `Node,RBAC`
- Enable `NodeRestriction` admission controller

**Solution:**
```bash
vi /etc/kubernetes/manifests/kube-apiserver.yaml
```

Add or update these flags:
```yaml
    - --anonymous-auth=false
    - --authorization-mode=Node,RBAC
    - --enable-admission-plugins=NodeRestriction
```

**Verify:**
```bash
# Wait ~60s for API server to restart
kubectl get pods -n kube-system | grep apiserver

# Test anonymous access is blocked
kubectl get pods --as=system:anonymous 2>&1
# Expected: Error from server (Forbidden)

# Verify authorization mode
kubectl -n kube-system describe pod kube-apiserver-controlplane | grep authorization-mode
# Expected: --authorization-mode=Node,RBAC
```

---

### Scenario 15: Upgrade Worker Node

**Setup:**
```bash
# Check current versions
kubectl get nodes
# node01 should show an older version than controlplane
# Example: controlplane v1.32.1, node01 v1.32.0
```

**Task:**
Upgrade worker node `node01` from `v1.32.0` to `v1.32.1` (match the control plane version).

**Solution:**
```bash
# Step 1: Drain the node (from controlplane)
kubectl drain node01 --ignore-daemonsets --delete-emptydir-data --force

# Step 2: SSH to node and upgrade
ssh node01
sudo -i

# Find exact version
apt-cache madison kubeadm | grep 1.32.1

# Upgrade kubeadm
apt-mark unhold kubeadm
apt-get install -y kubeadm=1.32.1-1.1
apt-mark hold kubeadm

# Upgrade node config
kubeadm upgrade node

# Upgrade kubelet and kubectl
apt-mark unhold kubelet kubectl
apt-get install -y kubelet=1.32.1-1.1 kubectl=1.32.1-1.1
apt-mark hold kubelet kubectl

# Restart kubelet
systemctl daemon-reload
systemctl restart kubelet

exit

# Step 3: Uncordon (from controlplane)
kubectl uncordon node01
```

**Verify:**
```bash
kubectl get nodes
# Expected: node01 Ready v1.32.1
```

---

### Scenario 16: Cilium Network Policy with Mutual Auth

**Setup:**
```bash
kubectl create namespace app-ns
kubectl label namespace app-ns name=app-ns

cat <<'EOF' | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: app-ns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: nginx
        image: nginx
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: app-ns
spec:
  selector:
    app: web
  ports:
  - port: 80
---
apiVersion: v1
kind: Pod
metadata:
  name: test-client
  namespace: app-ns
  labels:
    app: client
spec:
  containers:
  - name: curl
    image: curlimages/curl
    command: ["sleep", "3600"]
EOF
kubectl wait --for=condition=ready pod/test-client -n app-ns --timeout=60s
```

**Task:**
1. Create a CiliumNetworkPolicy that allows Pods in `app-ns` to access `web` Pods with mutual authentication required
2. Create a second CiliumNetworkPolicy that allows host access to `web` Pods without mutual auth

**Solution:**
```bash
cat <<'EOF' | kubectl apply -f -
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
EOF
```

**Verify:**
```bash
kubectl get ciliumnetworkpolicy -n app-ns
# Should show both policies

kubectl exec -n app-ns test-client -- curl -s --max-time 3 web.app-ns.svc | head -3
# Should work (same namespace, mutual auth)
```

**Cleanup:**
```bash
kubectl delete namespace app-ns
```

---

## Quick Reference Cheatsheet

| Topic | Key Command/Concept |
|---|---|
| Falco rules | `/etc/falco/rules.d/` — condition + output + priority |
| Audit log | `--audit-log-maxbackup=2 --audit-log-maxage=7` + volume mounts! |
| PSS Restricted | `runAsNonRoot`, `drop ALL caps`, `seccompProfile: RuntimeDefault` |
| NetworkPolicy deny-all | `podSelector: {}` + `policyTypes: [Ingress]` with no ingress rules |
| Kubelet anon auth | `anonymous.enabled: false` + `authorization.mode: Webhook` |
| ImagePolicyWebhook | `defaultAllow: false` = deny when backend down + volume mount! |
| SA token | `automountServiceAccountToken: false` + projected volume |
| SPDX BOM | `bom generate --image <img> --output file.spdx` |
| Docker group | `gpasswd -d <user> docker` |
| etcd TLS | `--client-cert-auth=true` + `--peer-client-cert-auth=true` |
| Cilium mutual auth | `authentication.mode: "required"` |
| Cilium host access | `fromEntities: [host]` |
| Node upgrade | drain → ssh → kubeadm → kubelet/kubectl → restart → uncordon |
