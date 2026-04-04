# Nitro Enclave Deployment

## Architecture

```
Inbound:  Internet -> TCP:3001 -> socat (parent) -> vsock -> Enclave
Outbound: Enclave -> vsock -> vsock-proxy (parent) -> internet (TLS end-to-end)
```

- Parent: runs Amazon Linux, has SSH, runs socat (inbound) + vsock-proxy (outbound)
- Enclave: runs Alpine + toprf-node binary, NO SSH, NO network interfaces, vsock only
- Parent CANNOT access enclave memory (Nitro hypervisor isolation)
- Outbound TLS is end-to-end (enclave to remote server) — parent is a dumb relay
- vsock-proxy allowlist restricts outbound to AWS, Google, and ruonlabs.com

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

### One-time AWS + Google Cloud setup

**AWS IAM** — EC2 instances need an IAM role for Workload Identity Federation:

```bash
# Create role (allows EC2 to assume it)
aws iam create-role --role-name toprf-node-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# Create instance profile and attach role
aws iam create-instance-profile --instance-profile-name toprf-node-profile
aws iam add-role-to-instance-profile \
  --instance-profile-name toprf-node-profile \
  --role-name toprf-node-role
```

The deploy script automatically attaches `toprf-node-profile` to launched instances.

**Google Cloud WIF** — for Android Play Integrity verification via the enclave:

1. Go to IAM & Admin → Workload Identity Federation → Create Pool
   - Name: `aws-nitro-pool`, Provider: AWS, Account ID: your AWS account ID
2. Add a provider: `aws-nitro-provider`, type AWS
3. Grant the pool access to impersonate the Play Integrity service account:
   - Service account: `play-integrity-verifier@ruonid.iam.gserviceaccount.com`
   - Select "service account impersonation"
   - Attribute: `aws_role`, Value: `arn:aws:sts::<account-id>:assumed-role/toprf-node-role`

The enclave uses this to get a Google access token via WIF (AWS credentials →
Google STS → service account impersonation) without any API keys or secrets
in the image. The WIF pool/provider identifiers are hardcoded in the binary
(they're public identifiers, not secrets).

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
- Creates security groups and SSH keys (if they don't exist)
- Provisions EC2 instances with elastic IPs and Nitro Enclave support
- Installs Nitro CLI, Docker, socat
- Uploads the image, builds EIF (same image for all nodes)
- Launches enclaves with inbound socat + outbound vsock-proxy
- Sets up iptables rate limiting (10 conn/min/IP)
- Outputs node IPs and DKG command

### 4. Run DKG

Run the DKG CLI from your local machine (macOS or Linux). It configures
each node via POST /configure, then runs the FROST DKG ceremony.

```bash
# Ensure .env has DEPLOYER_PRIVATE_KEY and RPC_URL for on-chain deployment
toprf-dkg-cli init --nodes http://<n1>:3001,http://<n2>:3001,http://<n3>:3001
```

The CLI:
- Sends POST /configure to each node (sets genesis mode, node ID, threshold)
- Runs FROST DKG rounds 1-3 (CLI is a blind relay, never sees key shares)
- Deploys TOPRFRegistry contract to Base (if DEPLOYER_PRIVATE_KEY is set in .env)
- Each node seals its own key share in enclave memory

After DKG, each node's health returns `{"status":"ready","node_id":N}`.

### 5. Resharing (adding a new node)

```bash
# 1. Deploy a new node (same image — all nodes are identical)
bash scripts/deploy-nodes.sh

# 2. Update well-known config (/.well-known/toprf-nodes.json) — add the new node
#    with platform, all 3 PCR measurements, and no verificationShare (yet).
#    PCR values are the same as existing nodes since the image is identical.

# 3. Run reshare CLI (configures new node in join mode automatically)
toprf-reshare-cli --new-node http://<new-ip>:3001
```

### Well-known config format

The well-known endpoint (`/.well-known/toprf-nodes.json`) must follow this format:

```json
{
  "threshold": 2,
  "groupPublicKey": "03ab8d...",
  "registryContract": {
    "chain": "base-sepolia",
    "chainId": 84532,
    "address": "0x85B7..."
  },
  "sourceRepo": "https://github.com/jeganggs64/threshold-oprf-v2",
  "nodes": [
    {
      "id": 1,
      "url": "http://<ip>:3001",
      "verificationShare": "02abc...",
      "platform": "nitro",
      "measurements": {
        "pcr0": "abc123...",
        "pcr1": "def456...",
        "pcr2": "789abc..."
      }
    },
    {
      "id": 4,
      "url": "http://<new-ip>:3001",
      "platform": "nitro",
      "measurements": {
        "pcr0": "abc123...",
        "pcr1": "def456...",
        "pcr2": "789abc..."
      }
    }
  ]
}
```

Existing nodes have `verificationShare`. New join nodes don't (until resharing completes).
The reshare CLI identifies existing vs new nodes by the presence of `verificationShare`.
The `measurements` field must include all 3 PCR values for the reshare handler to verify
the new node's attestation.

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
# Upload image
scp -i <key> toprf-node-enclave.tar.gz ec2-user@<ip>:~

# Load Docker image and build EIF (same image for all nodes)
sudo docker load < ~/toprf-node-enclave.tar.gz
sudo nitro-cli build-enclave \
    --docker-uri toprf-node-enclave:latest \
    --output-file ~/toprf-node.eif
```

All nodes use the same image — genesis vs join mode is configured at runtime
via POST /configure from the DKG or reshare CLI.

### POST /configure

Called once per node. Returns 403 if already configured.

**Genesis mode** (for DKG):
```json
POST /configure
{
  "mode": "genesis",
  "node_id": 1,
  "threshold": 2,
  "total": 3
}
```

**Join mode** (for resharing):
```json
POST /configure
{ "mode": "join" }
```

The DKG and reshare CLIs handle this automatically — you don't need to call
it manually unless debugging.

### Launch

```bash
sudo nitro-cli run-enclave \
    --eif-path ~/toprf-node.eif \
    --cpu-count 2 \
    --memory 256 \
    --enclave-cid 16

# Inbound proxy: clients reach the enclave via TCP:3001
nohup socat TCP-LISTEN:3001,fork,reuseaddr VSOCK-CONNECT:16:3001 > ~/proxy.log 2>&1 &

# Outbound proxies: enclave reaches external services via vsock-proxy
# Configure the allowlist first:
sudo tee /etc/nitro_enclaves/vsock-proxy.yaml > /dev/null <<EOF
allowlist:
- {address: 169.254.169.254, port: 80}
- {address: sts.amazonaws.com, port: 443}
- {address: sts.googleapis.com, port: 443}
- {address: playintegrity.googleapis.com, port: 443}
- {address: ruonlabs.com, port: 443}
- {address: iamcredentials.googleapis.com, port: 443}
EOF

nohup vsock-proxy 8080 169.254.169.254 80 > ~/proxy-metadata.log 2>&1 &
nohup vsock-proxy 8443 sts.googleapis.com 443 > ~/proxy-sts.log 2>&1 &
nohup vsock-proxy 8444 playintegrity.googleapis.com 443 > ~/proxy-play.log 2>&1 &
nohup vsock-proxy 8445 ruonlabs.com 443 > ~/proxy-wellknown.log 2>&1 &
nohup vsock-proxy 8446 iamcredentials.googleapis.com 443 > ~/proxy-iam.log 2>&1 &

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

1. **socat not installed** — Amazon Linux does not have socat by default.
   The deploy script installs it, but if deploying manually, run `sudo dnf install socat`.

2. **c8a.large (2 vCPU) doesn't work** — The Nitro allocator can't isolate
   CPUs with only 2 vCPUs. Use c5a.xlarge (4 vCPU) or larger.

3. **Debug mode zeros all PCRs** — Never use `--debug-mode` in production.
   The reshare handler rejects all-zero PCRs.

4. **Keys are ephemeral** — Nitro enclaves have no persistent storage. If the
   enclave restarts, the key share is lost. Use resharing to recover.

5. **No localhost in enclaves** — Nitro enclaves have no network interfaces at
   all, not even 127.0.0.1. Outbound connections use AF_VSOCK directly.

6. **vsock-proxy must be running** — The outbound proxies (vsock-proxy) on the
   parent must be started before the enclave can fetch well-known config or
   call Google APIs. The deploy script handles this.

7. **SSH drops during enclave launch** — The enclave steals CPUs from the parent,
   which can kill SSH sessions. The deploy script handles this by reconnecting.

7. **Keys are ephemeral** — Nitro enclaves have no persistent storage. If the
   enclave restarts, the DKG key share is lost. Use resharing to restore.

8. **No localhost in enclaves** — Nitro enclaves have no network interfaces at
   all, not even 127.0.0.1. The binary uses AF_VSOCK directly for outbound
   connections (not TCP localhost bridges).

## Why socat + vsock-proxy?

Nitro Enclaves have zero network interfaces. The only communication is vsock.

**Inbound** (clients reaching the enclave): `socat` on the parent bridges
TCP:3001 to vsock CID 16 port 3001. socat is NOT pre-installed on Amazon
Linux — install it with `dnf install socat`.

**Outbound** (enclave reaching the internet): `vsock-proxy` on the parent
listens on vsock ports and forwards to specific TCP endpoints. The enclave
connects via AF_VSOCK to CID 3 (parent), does TLS end-to-end with the
remote server (rustls inside the enclave). The parent's vsock-proxy is a
dumb byte relay — it cannot read or modify the encrypted traffic.

The vsock-proxy allowlist (`/etc/nitro_enclaves/vsock-proxy.yaml`) restricts
which hosts the enclave can reach: AWS metadata, Google APIs, and ruonlabs.com.

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
