# CKS Practice — Security Tools Exercises

> Tools: kube-bench, Trivy, bom (SPDX), strace

---

## TOOL 1 — kube-bench

---

### KB1: Run kube-bench on Control Plane

**Setup:**
```bash
curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.8.0/kube-bench_0.8.0_linux_amd64.tar.gz | tar xz -C /usr/local/bin/
```

**Task:** Find all FAIL items on the master node.

```bash
kube-bench run --targets master
kube-bench run --targets master | grep "\[FAIL\]"
```

---

### KB2: Run kube-bench on Worker Node

```bash
ssh node01
kube-bench run --targets node
kube-bench run --targets node | grep "\[FAIL\]"
```

---

### KB3: Fix API Server Findings (section 1.2)

**Setup:**
```bash
kube-bench run --targets master --check 1.2 | grep "\[FAIL\]"
```

**Task:** Fix the failures.

**Common fixes — `/etc/kubernetes/manifests/kube-apiserver.yaml`:**
```yaml
- --anonymous-auth=false
- --authorization-mode=Node,RBAC
- --enable-admission-plugins=NodeRestriction
- --audit-log-path=/var/log/kubernetes/audit.log
- --audit-log-maxage=30
- --audit-log-maxbackup=10
```

**Verify:**
```bash
kube-bench run --targets master --check 1.2 | grep "\[FAIL\]"
```

---

### KB4: Fix Kubelet Findings (section 4.2)

```bash
ssh node01
kube-bench run --targets node --check 4.2 | grep "\[FAIL\]"
```

**Common fixes — `/var/lib/kubelet/config.yaml`:**
```yaml
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
authorization:
  mode: Webhook
readOnlyPort: 0
protectKernelDefaults: true
rotateCertificates: true
```

```bash
systemctl daemon-reload && systemctl restart kubelet
kube-bench run --targets node --check 4.2 | grep "\[FAIL\]"
```

---

### KB5: Run kube-bench as a Job

```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: kube-bench
spec:
  template:
    spec:
      hostPID: true
      nodeSelector:
        node-role.kubernetes.io/control-plane: ""
      tolerations:
      - key: node-role.kubernetes.io/control-plane
        effect: NoSchedule
      containers:
      - name: kube-bench
        image: aquasec/kube-bench:v0.8.0
        command: ["kube-bench", "run", "--targets", "master"]
        volumeMounts:
        - name: var-lib-kubelet
          mountPath: /var/lib/kubelet
          readOnly: true
        - name: etc-kubernetes
          mountPath: /etc/kubernetes
          readOnly: true
      restartPolicy: Never
      volumes:
      - name: var-lib-kubelet
        hostPath:
          path: /var/lib/kubelet
      - name: etc-kubernetes
        hostPath:
          path: /etc/kubernetes
EOF

kubectl wait --for=condition=complete job/kube-bench --timeout=120s
kubectl logs job/kube-bench | grep "\[FAIL\]"
kubectl delete job kube-bench
```

---

## TOOL 2 — Trivy

---

### T1: Scan an Image (default table output)

**Setup:**
```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

```bash
trivy image nginx:1.25
```

---

### T2: Filter by Severity

```bash
# Only CRITICAL and HIGH
trivy image --severity CRITICAL,HIGH nginx:1.25

# Only CRITICAL
trivy image --severity CRITICAL alpine:3.18.0

# Ignore unfixed vulns
trivy image --severity CRITICAL,HIGH --ignore-unfixed nginx:1.25
```

---

### T3: Output Formats

```bash
# Table (default)
trivy image nginx:1.25 -o /tmp/trivy-table.txt

# JSON
trivy image --format json -o /tmp/trivy.json nginx:1.25
cat /tmp/trivy.json | python3 -m json.tool | head -30

# SARIF (CI/CD integration)
trivy image --format sarif -o /tmp/trivy.sarif nginx:1.25
```

**Verify:**
```bash
ls -la /tmp/trivy*
```

---

### T4: Scan All Images in a Namespace

```bash
# Get unique images from kube-system
kubectl get pods -n kube-system -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | sort -u > /tmp/images.txt

cat /tmp/images.txt

# Scan each
while read img; do
  echo "=== $img ==="
  trivy image --severity CRITICAL "$img" 2>/dev/null
done < /tmp/images.txt
```

---

### T5: Scan a Dockerfile for Misconfigurations

**Setup:**
```bash
mkdir -p /tmp/trivy-lab
cat <<'EOF' > /tmp/trivy-lab/Dockerfile
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
COPY app /app
CMD ["/app"]
EOF
```

```bash
trivy config /tmp/trivy-lab/Dockerfile
# Findings: latest tag, no USER instruction
```

**Cleanup:**
```bash
rm -rf /tmp/trivy-lab
```

---

### T6: Scan Kubernetes YAML Manifests

**Setup:**
```bash
cat <<'EOF' > /tmp/insecure-deploy.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: insecure
  template:
    metadata:
      labels:
        app: insecure
    spec:
      containers:
      - name: app
        image: nginx
        securityContext:
          privileged: true
          runAsUser: 0
EOF
```

```bash
trivy config /tmp/insecure-deploy.yaml
# Findings: privileged, root user, no limits, no readOnlyRootFilesystem
```

---

## TOOL 3 — bom (SPDX)

---

### S1: Install bom and Generate SPDX

**Setup:**
```bash
curl -L https://github.com/kubernetes-sigs/bom/releases/latest/download/bom-linux-amd64 -o /usr/local/bin/bom
chmod +x /usr/local/bin/bom
```

```bash
bom generate --image alpine:3.18.0 --output /tmp/alpine-3.18.spdx
bom generate --image alpine:3.19.1 --output /tmp/alpine-3.19.spdx

head -20 /tmp/alpine-3.18.spdx
```

---

### S2: Find a Package in SPDX

**Task:** Which Alpine image has `libcrypto3`?

```bash
grep libcrypto3 /tmp/alpine-3.18.spdx
grep libcrypto3 /tmp/alpine-3.19.spdx

# Or find which file matches
grep -l libcrypto3 /tmp/alpine-*.spdx
```

---

### S3: SPDX in JSON Format

```bash
bom generate --image nginx:1.25 --format json --output /tmp/nginx.spdx.json
cat /tmp/nginx.spdx.json | python3 -m json.tool | head -40
```

---

### S4: Full CKS Exam Scenario

**Setup:**
```bash
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
      - name: web
        image: alpine:3.18.0
        command: ["sleep", "3600"]
      - name: cache
        image: alpine:3.19.1
        command: ["sleep", "3600"]
EOF
kubectl wait --for=condition=available deployment/multi-app --timeout=120s
```

**Task:** Find which image has `libcrypto3` and remove that container.

```bash
bom generate --image alpine:3.18.0 --output /tmp/a18.spdx
bom generate --image alpine:3.19.1 --output /tmp/a19.spdx
grep -l libcrypto3 /tmp/a18.spdx /tmp/a19.spdx

# Remove the vulnerable container
kubectl edit deployment multi-app
```

**Verify:**
```bash
kubectl get deployment multi-app -o jsonpath='{.spec.template.spec.containers[*].image}'
# Should show only one image
```

**Cleanup:**
```bash
kubectl delete deployment multi-app
rm /tmp/a18.spdx /tmp/a19.spdx
```

---

## TOOL 4 — strace

---

### ST1: Basic strace

```bash
# Trace all syscalls
strace ls /tmp

# Only file-related syscalls
strace -e trace=file ls /tmp

# Only network syscalls
strace -e trace=network curl -s https://example.com > /dev/null
```

---

### ST2: Trace a Running Process

**Setup:**
```bash
sleep 3600 &
PID=$!
echo "PID: $PID"
```

```bash
# Attach to running process (Ctrl+C to stop)
strace -p $PID

# With timestamps
strace -p $PID -t

# Save to file
strace -p $PID -o /tmp/strace-out.txt &
sleep 5 && kill %2
cat /tmp/strace-out.txt
```

**Cleanup:**
```bash
kill $PID
```

---

### ST3: Trace a Container Process

**Setup:**
```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: suspicious-pod
spec:
  containers:
  - name: app
    image: busybox
    command: ["sh", "-c", "while true; do wget -q -O /dev/null http://example.com; sleep 10; done"]
EOF
kubectl wait --for=condition=ready pod/suspicious-pod --timeout=60s
```

**Task:** Find the container PID and trace its network calls.

```bash
# Option 1: crictl
CONTAINER_ID=$(crictl ps --name app -q)
PID=$(crictl inspect $CONTAINER_ID | python3 -c "import sys,json; print(json.load(sys.stdin)['info']['pid'])")

# Option 2: pgrep
PID=$(pgrep -f "wget.*example.com")

# Trace network calls
strace -p $PID -e trace=network -f 2>&1 | head -50
# You'll see connect() calls — suspicious outbound traffic
```

**Cleanup:**
```bash
kubectl delete pod suspicious-pod
```

---

### ST4: Detect Sensitive File Access

**Setup:**
```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: file-reader
spec:
  containers:
  - name: app
    image: busybox
    command: ["sh", "-c", "while true; do cat /etc/shadow 2>/dev/null; sleep 15; done"]
    securityContext:
      privileged: true
EOF
kubectl wait --for=condition=ready pod/file-reader --timeout=60s
```

**Task:** Use strace to catch the `/etc/shadow` read.

```bash
PID=$(pgrep -f "cat /etc/shadow")
strace -p $PID -e trace=openat -f 2>&1 | head -30
# You'll see: openat(AT_FDCWD, "/etc/shadow", O_RDONLY)
```

**Cleanup:**
```bash
kubectl delete pod file-reader
```

---

### ST5: strace + Falco Together

**Setup:**
```bash
cat <<'EOF' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: bad-actor
spec:
  containers:
  - name: app
    image: busybox
    command: ["sh", "-c", "while true; do cat /etc/passwd; sleep 20; done"]
EOF
kubectl wait --for=condition=ready pod/bad-actor --timeout=60s
mkdir -p /etc/falco/rules.d
```

**Task:**
1. Use strace to identify the suspicious syscall
2. Write a Falco rule to detect it
3. Verify Falco catches it

**Step 1 — strace:**
```bash
PID=$(pgrep -f "cat /etc/passwd")
strace -p $PID -e trace=openat 2>&1 | head -10
# Shows: openat(AT_FDCWD, "/etc/passwd", O_RDONLY)
```

**Step 2 — Falco rule:**
```bash
cat <<'EOF' > /etc/falco/rules.d/detect-passwd.yaml
- rule: Detect /etc/passwd Read in Container
  desc: Detects reading /etc/passwd inside a container
  condition: open_read and fd.name = /etc/passwd and container.id != host
  output: "Sensitive file read (user=%user.name cmd=%proc.cmdline pod=%k8s.pod.name file=%fd.name)"
  priority: WARNING
  tags: [filesystem]
EOF
systemctl restart falco
```

**Step 3 — Verify:**
```bash
journalctl -u falco --since "1 minute ago" | grep "/etc/passwd"
# Should show alert with pod name
```

**Cleanup:**
```bash
kubectl delete pod bad-actor
rm /etc/falco/rules.d/detect-passwd.yaml
systemctl restart falco
```

---

## Quick Reference

| Tool | Command | Purpose |
|---|---|---|
| kube-bench | `kube-bench run --targets master` | CIS benchmark control plane |
| kube-bench | `kube-bench run --targets node` | CIS benchmark worker |
| kube-bench | `--check 1.2` | Run specific section |
| trivy | `trivy image <img>` | Scan image vulns |
| trivy | `--severity CRITICAL,HIGH` | Filter severity |
| trivy | `--format json -o file.json` | JSON output |
| trivy | `trivy config <path>` | Scan Dockerfile/YAML |
| bom | `bom generate --image <img> --output f.spdx` | SPDX text |
| bom | `--format json` | SPDX JSON |
| bom | `grep <pkg> file.spdx` | Find package |
| strace | `strace -p <PID>` | Trace running process |
| strace | `-e trace=file` | Only file syscalls |
| strace | `-e trace=network` | Only network syscalls |
| strace | `-e trace=openat` | Only open calls |
| strace | `-o output.txt` | Save to file |
| strace | `-f` | Follow child processes |
