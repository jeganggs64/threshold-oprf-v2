# Nitro Enclave Deployment

## Architecture

```
Internet -> Parent EC2 (TCP:3001, socat proxy) -> vsock -> Nitro Enclave (toprf-node)
```

- Parent: runs Amazon Linux, has SSH, runs socat TCP-to-vsock proxy
- Enclave: runs Alpine + toprf-node binary, NO SSH, NO network, vsock only
- Parent CANNOT access enclave memory (Nitro hypervisor isolation)
- Enclave has NO internet access — well-known config fetch at boot will fail (expected)

## Image

The enclave image uses Alpine (not `FROM scratch`) because the Nitro init
requires a minimal userspace to bootstrap the process. `FROM scratch` crashes.

```
alpine:3.21 (pinned by digest)
├── /toprf-node        — static musl binary (built with --features nitro)
└── /etc/ssl/certs/    — CA certificates
```

The default entrypoint is `toprf-node --join --port 3001`. For genesis mode,
this is overridden with a custom init.sh (see the deploy script).

**Important:** The binary must be built with `--features nitro` to include
the Nitro attestation endpoint (`/attestation`). Without the feature flag,
the attestation endpoint is not registered.

## Quick Start (scripted deployment)

### Prerequisites

- AWS CLI configured with credentials
- GitHub CLI (`gh`) for downloading artifacts
- A wallet with Base Sepolia ETH (for on-chain registry deployment)
  - Get testnet ETH from a faucet (e.g. https://www.alchemy.com/faucets/base-sepolia)

### 1. Build the image (CI)

Trigger: Actions -> "Build Nitro Enclave Image" -> Run workflow

### 2. Download artifacts

```bash
# Nitro image
gh run download <run-id> --name nitro-enclave-image -D /tmp/nitro-artifacts

# CLI binaries + contracts
gh run download <ci-run-id> --name binaries -D /tmp/cli-binaries
gh run download <ci-run-id> --name contracts -D /tmp/contracts
chmod +x /tmp/cli-binaries/*
```

### 3. Deploy nodes

```bash
cp scripts/deploy-nodes.env.example scripts/deploy-nodes.env
# Edit deploy-nodes.env:
#   TOPRF_REGIONS, TOPRF_KEY_NAME, TOPRF_IMAGE_DIR, TOPRF_CLI_DIR

bash scripts/deploy-nodes.sh
```

The script:
- Creates security groups in each region (if they don't exist)
- Provisions EC2 instances with Nitro Enclave support
- Installs Nitro CLI, Docker, socat
- Uploads the image, builds EIF
- Creates per-node init.sh for genesis mode (or uses default for join mode)
- Launches enclaves with socat TCP-to-vsock proxy
- Outputs node IPs and config for the next step

### 4. Run DKG

```bash
cp scripts/run-dkg.env.example scripts/run-dkg.env
# Edit run-dkg.env:
#   TOPRF_NODE_URLS (from deploy output)
#   TOPRF_DKG_HOST (from deploy output)
#   TOPRF_KEY_NAME (must match deploy-nodes.env)
#   DEPLOYER_PRIVATE_KEY (wallet private key for on-chain registry)
#   RPC_URL (defaults to Base Sepolia)

bash scripts/run-dkg.sh
```

The script:
- Verifies all nodes are healthy
- Uploads deployer credentials to the DKG host
- Uploads contracts and installs foundry (for on-chain deployment)
- Runs the DKG ceremony (FROST rounds 1-3)
- Deploys the TOPRFRegistry contract to Base (if DEPLOYER_PRIVATE_KEY is set)
- Downloads `dkg-data.json` locally
- Verifies all nodes are ready after DKG

### 5. Test evaluations

```bash
BP="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
CDH=$(echo -n "$BP" | xxd -r -p | sha256sum | cut -d' ' -f1)

curl -X POST http://<node-ip>:3001/partial-evaluate \
    -H "Content-Type: application/json" \
    -d "{\"blinded_point\": \"$BP\", \"attestation\": {\"platform\": \"test\", \"client_data_hash\": \"$CDH\"}}"
```

### 6. Resharing (adding a new node)

```bash
# 1. Deploy a new node in join mode
#    Set TOPRF_MODE="join" in deploy-nodes.env, run deploy-nodes.sh

# 2. Update well-known config with the new node's URL, platform, PCR values

# 3. Run reshare CLI (from any machine that can reach all nodes)
toprf-reshare-cli --new-node http://<new-ip>:3001
```

## Manual Deployment (step by step)

If you prefer to deploy manually without the scripts, follow these steps.

### Provision EC2

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

### Set up instance

```bash
ssh -i <key> ec2-user@<ip>

# Install Nitro CLI + Docker + socat
sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker socat
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

### Upload and build

```bash
# Upload image + binary
scp -i <key> toprf-node-enclave.tar.gz toprf-node ec2-user@<ip>:~

# Load Docker image
sudo docker load < ~/toprf-node-enclave.tar.gz

# For join mode: use the image as-is
sudo nitro-cli build-enclave \
    --docker-uri toprf-node-enclave:latest \
    --output-file ~/toprf-node.eif

# For genesis mode: create per-node init.sh (no --tcp!)
cat > /tmp/init.sh <<'SCRIPT'
#!/bin/sh
TOPRF_ALLOW_TEST_ATTESTATION=1 exec /toprf-node \
    --genesis "http://<peer1-ip>:3001,http://<peer2-ip>:3001" \
    --node-id 1 \
    --threshold 2 \
    --total 3 \
    --port 3001
SCRIPT
chmod +x /tmp/init.sh

cat > /tmp/Dockerfile.genesis <<'EOF'
FROM toprf-node-enclave:latest
COPY init.sh /init.sh
RUN chmod +x /init.sh
ENTRYPOINT ["/init.sh"]
CMD []
EOF

cd /tmp
sudo docker build -t toprf-node-enclave:genesis -f Dockerfile.genesis .
sudo nitro-cli build-enclave \
    --docker-uri toprf-node-enclave:genesis \
    --output-file ~/toprf-node.eif
```

### Launch

```bash
sudo nitro-cli run-enclave \
    --eif-path ~/toprf-node.eif \
    --cpu-count 2 \
    --memory 256 \
    --enclave-cid 16

# Start socat proxy
nohup socat TCP-LISTEN:3001,fork,reuseaddr VSOCK-CONNECT:16:3001 > ~/proxy.log 2>&1 &

# Wait ~10s for boot, then verify
sleep 10
curl -sf http://127.0.0.1:3001/health
```

### Run DKG

```bash
# From an EC2 instance with the DKG CLI
./toprf-dkg-cli init --nodes http://<n1>:3001,http://<n2>:3001,http://<n3>:3001
```

## Debugging

```bash
# Launch in debug mode (PCRs go to all zeros — testing only)
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

## Common Pitfalls

1. **`--tcp` flag in init.sh** — Do NOT use `--tcp` inside the enclave. The
   enclave has no network. The binary defaults to vsock on Linux, which is
   correct.

2. **socat not installed** — Amazon Linux does not have socat by default.
   Install it explicitly or the proxy won't start.

3. **Health check fails immediately after launch** — The enclave takes ~10
   seconds to boot (well-known config fetch times out). Wait before checking.

4. **c8a.large (2 vCPU) doesn't work** — The Nitro allocator can't isolate
   CPUs with only 2 vCPUs. Use c5a.xlarge (4 vCPU) or larger.

5. **Debug mode zeros all PCRs** — Never use `--debug-mode` in production.
   The reshare handler rejects all-zero PCRs.

6. **Genesis images have different PCRs** — Each node's init.sh differs, so
   PCR0 differs per node. After DKG, switch to the standard join-mode image.

7. **DKG CLI is a Linux binary** — Built with musl for Linux x86_64. Run it
   from an EC2 instance, not from macOS.

8. **Keys are ephemeral** — Nitro enclaves have no persistent storage. If the
   enclave restarts, the DKG key share is lost.

## Why socat?

Nitro Enclaves have zero network access. The only communication channel is
vsock between the parent EC2 and the enclave. socat bridges TCP:3001 on
the parent to vsock CID 16 port 3001 in the enclave. It is NOT pre-installed
on Amazon Linux.

## Why Alpine?

The binary crashes as a direct ENTRYPOINT in a `FROM scratch` image inside
Nitro. The init system requires a minimal userspace. Alpine (~7MB) provides
this. After boot, the binary is the only running process.

## Instance Sizing

| Instance | vCPUs | Works? | Monthly | Notes |
|----------|-------|--------|---------|-------|
| c8a.large | 2 | No | ~$99 | Allocator fails |
| c5a.xlarge | 4 | Yes | ~$127 | Cheapest working |
| c6a.xlarge | 4 | Yes | ~$142 | AMD EPYC Milan |
| c7a.xlarge | 4 | Yes | ~$110 | AMD EPYC Genoa |
