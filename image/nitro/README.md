# Nitro Enclave Deployment

## Architecture

```
Internet → Parent EC2 (TCP:3001, socat proxy) → vsock → Nitro Enclave (toprf-node)
```

- Parent: runs Amazon Linux, has SSH, runs socat TCP-to-vsock proxy
- Enclave: runs Alpine + toprf-node binary, NO SSH, NO network, vsock only
- Parent CANNOT access enclave memory (Nitro hypervisor isolation)

## Image Structure

The enclave image uses Alpine (not `FROM scratch`) because the Nitro init
requires a shell to properly set up the process environment via the init.sh wrapper.

```
alpine:3.21
├── /toprf-node        — static musl binary
├── /init.sh           — shell wrapper: sets env vars, exec's into binary
└── /etc/ssl/certs/    — CA certificates
```

The init.sh wrapper is required because running the binary directly as
ENTRYPOINT causes crashes inside the Nitro enclave kernel. The shell wrapper
sets up the environment and `exec`s into the binary (replacing the shell).

## Build Pipeline

### 1. CI builds the Docker image (manual dispatch)

Trigger: Actions → "Build Nitro Enclave Image" → Run workflow

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

### 4. Upload artifacts to each instance

```bash
scp -i <key> toprf-node-enclave.tar.gz toprf-node ec2-user@<ip>:~
```

### 5. Set up each instance

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

# Load Docker image
sudo docker load < ~/toprf-node-enclave.tar.gz

# Build EIF (note the PCR values — they must match across all nodes)
sudo nitro-cli build-enclave \
    --docker-uri toprf-node-enclave:latest \
    --output-file ~/toprf-node.eif
```

### 6. Build the enclave Docker image on each instance

The Docker image must be built on the instance because the init.sh contains
node-specific configuration (genesis peers, node ID, etc.).

```bash
# Create init.sh with node-specific config
cat > /tmp/init.sh <<'EOF'
#!/bin/sh
TOPRF_ALLOW_TEST_ATTESTATION=1 exec /toprf-node \
    --genesis "http://<peer1>:3001,http://<peer2>:3001" \
    --node-id <N> \
    --threshold 2 \
    --total 3 \
    --port 3001
EOF
chmod +x /tmp/init.sh

# For join mode (adding new nodes later):
cat > /tmp/init.sh <<'EOF'
#!/bin/sh
TOPRF_ALLOW_TEST_ATTESTATION=1 exec /toprf-node --join --port 3001
EOF
chmod +x /tmp/init.sh

# Build Docker image
cat > /tmp/Dockerfile.nitro <<'EOF'
FROM alpine:3.21
RUN apk --no-cache add ca-certificates && rm -rf /var/cache/apk/*
COPY toprf-node /toprf-node
RUN chmod +x /toprf-node
COPY init.sh /init.sh
RUN chmod +x /init.sh
ENTRYPOINT ["/init.sh"]
EOF

cp ~/toprf-node /tmp/toprf-node
cd /tmp
sudo docker build -t toprf-node-enclave -f Dockerfile.nitro .
sudo nitro-cli build-enclave \
    --docker-uri toprf-node-enclave:latest \
    --output-file ~/toprf-node.eif
```

### 7. Launch enclave + proxy

```bash
# Launch enclave
sudo nitro-cli run-enclave \
    --eif-path ~/toprf-node.eif \
    --cpu-count 2 \
    --memory 256 \
    --enclave-cid 16

# Start parent-side vsock proxy (TCP:3001 → vsock CID 16 port 3001)
nohup socat TCP-LISTEN:3001,fork,reuseaddr VSOCK-CONNECT:16:3001 > ~/proxy.log 2>&1 &

# Verify
curl -sf http://127.0.0.1:3001/health
```

### 8. Run DKG (from any machine that can reach all nodes)

```bash
# Upload DKG CLI to one of the instances
scp -i <key> toprf-dkg-cli ec2-user@<node1-ip>:~

# Run DKG
ssh -i <key> ec2-user@<node1-ip>
chmod +x ~/toprf-dkg-cli
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

## Known Issues

1. **c8a.large (2 vCPU) doesn't work** — the Nitro allocator can't isolate CPUs
   with only 2 vCPUs and 1 thread per core. Use c5a.xlarge (4 vCPU) or larger.

2. **FROM scratch doesn't work** — the binary crashes inside the enclave when
   used as a direct ENTRYPOINT. Using Alpine with a shell wrapper (init.sh that
   `exec`s into the binary) works.

3. **Enclaves have NO network** — all communication goes through vsock.
   The parent runs a socat proxy to bridge TCP:3001 to vsock.

4. **Debug mode zeros all PCRs** — never use `--debug-mode` in production.
   Verifiers would reject zero PCR values.

## Instance Sizing

| Instance | vCPUs | Works? | Monthly | Notes |
|----------|-------|--------|---------|-------|
| c8a.large | 2 | No | ~$99 | Allocator fails |
| c5a.xlarge | 4 | Yes | ~$127 | Cheapest working |
| c6a.xlarge | 4 | Yes | ~$142 | AMD EPYC Milan |
| c7a.xlarge | 4 | Yes | ~$110 | AMD EPYC Genoa |
