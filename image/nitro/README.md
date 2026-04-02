# Nitro Enclave Deployment

## Architecture

```
Internet -> Parent EC2 (TCP:3001, socat proxy) -> vsock -> Nitro Enclave (toprf-node)
```

- Parent: runs Amazon Linux, has SSH, runs socat TCP-to-vsock proxy
- Enclave: runs Alpine + toprf-node binary, NO SSH, NO network, vsock only
- Parent CANNOT access enclave memory (Nitro hypervisor isolation)

## Image

The enclave image uses Alpine (not `FROM scratch`) because the Nitro init
requires a minimal userspace to bootstrap the process. `FROM scratch` crashes.

```
alpine:3.21 (pinned by digest)
├── /toprf-node        — static musl binary
└── /etc/ssl/certs/    — CA certificates
```

The default entrypoint is `toprf-node --join --port 3001`. For genesis mode,
this is overridden with a custom init.sh (see Genesis below).

## Build Pipeline

### 1. CI builds the Docker image

Trigger: Actions -> "Build Nitro Enclave Image" -> Run workflow

CI produces:
- `toprf-node-enclave.tar.gz` — Docker image
- `toprf-node` — standalone binary
- `build-info.json` — Rust version, Alpine digest, commit hash
- `hashes.txt` — SHA256 hashes

### 2. Download artifacts

```bash
gh run download <run-id> --name nitro-enclave-image -D /tmp/nitro-artifacts
```

### 3. Provision EC2 instances

Requirements:
- Instance type: c5a.xlarge (4 vCPU) or larger with Nitro Enclave support
- c8a.large (2 vCPU) does NOT work — not enough CPUs for enclave allocator
- `--enclave-options Enabled=true` at launch
- Security group: ports 22 (SSH) + 3001 (node)

```bash
aws ec2 run-instances \
    --region <region> \
    --image-id <amazon-linux-2023-ami> \
    --instance-type c5a.xlarge \
    --key-name <key> \
    --security-group-ids <sg> \
    --associate-public-ip-address \
    --enclave-options Enabled=true \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=toprf-v2-nitro}]'
```

### 4. Set up each instance

```bash
ssh -i <key> ec2-user@<ip>

# Install Nitro CLI + Docker
sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker
sudo systemctl enable --now docker
sudo systemctl enable --now nitro-enclaves-allocator
sudo usermod -aG docker ec2-user
sudo usermod -aG ne ec2-user

# Configure allocator (2 CPUs for enclave, 2 for parent)
sudo tee /etc/nitro_enclaves/allocator.yaml > /dev/null <<EOF
---
memory_mib: 512
cpu_count: 2
EOF
sudo systemctl restart nitro-enclaves-allocator
```

### 5. Upload artifacts

```bash
scp -i <key> toprf-node-enclave.tar.gz toprf-node ec2-user@<ip>:~
```

### 6. Load the Docker image and build the EIF

**For join mode** (adding new nodes later, or post-genesis operation):

The CI-built image works as-is — all nodes use the same image with the same
default entrypoint (`toprf-node --join --port 3001`). This means all nodes
have identical PCR values.

```bash
sudo docker load < ~/toprf-node-enclave.tar.gz
sudo nitro-cli build-enclave \
    --docker-uri toprf-node-enclave:latest \
    --output-file ~/toprf-node.eif
```

**For genesis mode** (initial DKG ceremony):

Genesis requires per-node args (node-id, peers, threshold). Since Nitro
enclaves cannot receive runtime args, you override the entrypoint with a
custom init.sh on each instance. This means each node has different PCR0
values during genesis, which is expected — the well-known config records
per-node PCR values.

```bash
# Create per-node init.sh (adjust node-id and peer URLs per instance)
cat > /tmp/init.sh <<'SCRIPT'
#!/bin/sh
exec /toprf-node \
    --genesis "http://<peer1>:3001,http://<peer2>:3001" \
    --node-id 1 \
    --threshold 2 \
    --total 3 \
    --port 3001
SCRIPT
chmod +x /tmp/init.sh

# Rebuild image with custom init.sh
cat > /tmp/Dockerfile.genesis <<'EOF'
FROM toprf-node-enclave:latest
COPY init.sh /init.sh
RUN chmod +x /init.sh
ENTRYPOINT ["/init.sh"]
CMD []
EOF

cp ~/toprf-node /tmp/toprf-node
cd /tmp
sudo docker build -t toprf-node-enclave:genesis -f Dockerfile.genesis .
sudo nitro-cli build-enclave \
    --docker-uri toprf-node-enclave:genesis \
    --output-file ~/toprf-node.eif
```

After DKG completes and keys are sealed, nodes can be restarted using the
standard join-mode image (same PCRs across all nodes).

### 7. Launch enclave + proxy

```bash
# Launch enclave
sudo nitro-cli run-enclave \
    --eif-path ~/toprf-node.eif \
    --cpu-count 2 \
    --memory 256 \
    --enclave-cid 16

# Start parent-side vsock proxy (TCP:3001 -> vsock CID 16 port 3001)
nohup socat TCP-LISTEN:3001,fork,reuseaddr VSOCK-CONNECT:16:3001 > ~/proxy.log 2>&1 &

# Verify
curl -sf http://127.0.0.1:3001/health
```

### 8. Run DKG (from any machine that can reach all nodes)

```bash
# Upload DKG CLI to one of the instances (or run locally)
./toprf-dkg-cli init --nodes http://<node1>:3001,http://<node2>:3001,http://<node3>:3001

# Optional: deploy contract to Base Sepolia
DEPLOYER_PRIVATE_KEY=<key> RPC_URL=https://sepolia.base.org \
    ./toprf-dkg-cli init --nodes http://<node1>:3001,http://<node2>:3001,http://<node3>:3001
```

### 9. Test evaluations

```bash
BP="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
CDH=$(echo -n "$BP" | xxd -r -p | sha256sum | cut -d' ' -f1)

curl -X POST http://<node-ip>:3001/partial-evaluate \
    -H "Content-Type: application/json" \
    -d "{\"blinded_point\": \"$BP\", \"attestation\": {\"platform\": \"test\", \"client_data_hash\": \"$CDH\"}}"
```

## Debugging

```bash
# Launch in debug mode (PCRs go to all zeros — don't use in production)
sudo nitro-cli run-enclave --eif-path ~/toprf-node.eif \
    --cpu-count 2 --memory 256 --enclave-cid 16 --debug-mode

# View console output
EID=$(sudo nitro-cli describe-enclaves | python3 -c \
    "import json,sys; d=json.load(sys.stdin); print(d[0]['EnclaveID'] if d else '')")
sudo nitro-cli console --enclave-id "$EID"

# Check enclave status
sudo nitro-cli describe-enclaves

# Terminate enclave
sudo nitro-cli terminate-enclave --all

# Check proxy log
cat ~/proxy.log
```

## Why socat?

Nitro Enclaves have zero network access — no TCP, no UDP, no ethernet. The
only communication channel is vsock (virtio socket) between the parent EC2
and the enclave.

socat runs on the parent and bridges the gap:

```
External client -> TCP:3001 -> socat (parent) -> vsock CID 16:3001 -> enclave binary
```

The binary inside the enclave listens on vsock natively (tokio-vsock). socat
is just the TCP-to-vsock translator on the parent side.

## Why Alpine?

The binary crashes when used as a direct ENTRYPOINT in a `FROM scratch` image
inside the Nitro enclave. The Nitro init system requires a minimal userspace
to set up the process environment. Alpine (~7MB) provides this. After boot,
the binary is the only running process — Alpine's shell is not accessible.

## Known Issues

1. **c8a.large (2 vCPU) doesn't work** — the Nitro allocator can't isolate CPUs
   with only 2 vCPUs and 1 thread per core. Use c5a.xlarge (4 vCPU) or larger.

2. **Debug mode zeros all PCRs** — never use `--debug-mode` in production.
   The reshare handler rejects all-zero PCRs.

3. **Genesis images have different PCRs** — because each node's init.sh differs.
   After DKG, switch to the standard join-mode image for identical PCRs.

## Instance Sizing

| Instance | vCPUs | Works? | Monthly | Notes |
|----------|-------|--------|---------|-------|
| c8a.large | 2 | No | ~$99 | Allocator fails |
| c5a.xlarge | 4 | Yes | ~$127 | Cheapest working |
| c6a.xlarge | 4 | Yes | ~$142 | AMD EPYC Milan |
| c7a.xlarge | 4 | Yes | ~$110 | AMD EPYC Genoa |
