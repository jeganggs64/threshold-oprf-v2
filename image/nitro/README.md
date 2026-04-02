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
this is overridden with a custom init.sh (see Genesis below).

**Important:** The binary must be built with `--features nitro` to include
the Nitro attestation endpoint (`/attestation`). Without the feature flag,
the attestation endpoint is not registered.

## Build Pipeline

### 1. CI builds the Docker image

Trigger: Actions -> "Build Nitro Enclave Image" -> Run workflow

CI produces:
- `toprf-node-enclave.tar.gz` — Docker image
- `toprf-node` — standalone binary
- `build-info.json` — Rust version, Alpine digest, commit hash, binary SHA256
- `hashes.txt` — SHA256 hashes

CI also auto-commits `deployments/builds/nitro-<commit>.json` with full
build provenance for public verifiability.

### 2. Download artifacts

```bash
# Find the latest successful build run ID
gh run list --repo <repo> --workflow "Build Nitro Enclave Image (EIF)" --status success --limit 1

# Download
gh run download <run-id> --name nitro-enclave-image -D /tmp/nitro-artifacts
```

Also download the CLI binaries and contracts from the latest CI run:

```bash
gh run list --repo <repo> --workflow CI --status success --limit 1
gh run download <run-id> --name binaries -D /tmp/cli-binaries
gh run download <run-id> --name contracts -D /tmp/contracts
chmod +x /tmp/cli-binaries/*
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

**Note:** socat is not pre-installed on Amazon Linux — you must install it
explicitly. Without it, the TCP-to-vsock bridge won't work and the node
will be unreachable from outside the parent.

### 5. Upload artifacts

```bash
scp -i <key> /tmp/nitro-artifacts/toprf-node-enclave.tar.gz ec2-user@<ip>:~
scp -i <key> /tmp/nitro-artifacts/toprf-node ec2-user@<ip>:~
```

### 6. Load the Docker image and build the EIF

**For join mode** (adding new nodes via resharing):

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
values during genesis, which is expected.

```bash
# Create per-node init.sh (adjust node-id and peer URLs per instance)
# IMPORTANT: Do NOT use --tcp. The enclave has no network.
# The binary listens on vsock by default on Linux.
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

# Rebuild image with custom init.sh
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

**Notes on the genesis init.sh:**
- Peer URLs use the **public IPs** of the other instances (socat bridges to vsock)
- `TOPRF_ALLOW_TEST_ATTESTATION=1` enables test mode for device attestation
  on `/partial-evaluate`. Remove this for production.
- The `--genesis` flag takes a comma-separated list of all **other** nodes' URLs
- Each node needs a unique `--node-id` (1, 2, 3, ...)

### 7. Launch enclave + proxy

```bash
# Launch enclave (use --debug-mode for testing, omit for production)
sudo nitro-cli run-enclave \
    --eif-path ~/toprf-node.eif \
    --cpu-count 2 \
    --memory 256 \
    --enclave-cid 16 \
    --debug-mode

# Start parent-side vsock proxy (TCP:3001 -> vsock CID 16 port 3001)
nohup socat TCP-LISTEN:3001,fork,reuseaddr VSOCK-CONNECT:16:3001 > ~/proxy.log 2>&1 &

# Wait for enclave to boot (fetches well-known config which will timeout
# since the enclave has no internet — this is expected and non-fatal)
sleep 10

# Verify
curl -sf http://127.0.0.1:3001/health
# Expected: {"status":"waiting_for_key"} (genesis mode, pre-DKG)
# Expected: {"status":"ready","node_id":1} (after DKG or with --key-file)
```

**Important:** The enclave takes ~10 seconds to boot because it attempts to
fetch the well-known config from the internet. Since the enclave has no
network access, this times out after 10 seconds and continues. The health
check will fail if you run it too early.

### 8. Run DKG + deploy on-chain registry

The DKG CLI is a Linux binary — run it from one of the EC2 instances.
If `DEPLOYER_PRIVATE_KEY` and `RPC_URL` are set in `.env`, the CLI
automatically deploys the TOPRFRegistry contract to Base after DKG.

```bash
# Upload CLI binaries, contracts, and .env to an instance
scp -i <key> /tmp/cli-binaries/toprf-dkg-cli ec2-user@<ip>:~
scp -i <key> /tmp/cli-binaries/toprf-reshare-cli ec2-user@<ip>:~
scp -i <key> /tmp/contracts/contracts.tar.gz ec2-user@<ip>:~
scp -i <key> .env ec2-user@<ip>:~

# SSH in and set up
ssh -i <key> ec2-user@<ip>
chmod +x ~/toprf-dkg-cli ~/toprf-reshare-cli

# Unpack contracts
mkdir -p ~/contracts && tar xzf ~/contracts.tar.gz -C ~/contracts

# Install foundry (needed for contract deployment)
curl -L https://foundry.paradigm.xyz | bash
source ~/.bashrc
foundryup

# Create .env for the DKG CLI (reads DEPLOYER_PRIVATE_KEY and RPC_URL)
# Edit .env and add your deployer private key (hex, no 0x prefix)
# RPC_URL defaults to https://sepolia.base.org

# Run DKG (from ~ so it finds ./contracts/ and ./.env)
./toprf-dkg-cli init --nodes http://<node1-ip>:3001,http://<node2-ip>:3001,http://<node3-ip>:3001
```

The CLI:
1. Runs the FROST DKG ceremony (rounds 1-3)
2. Each node self-seals its key share
3. Writes `dkg-data.json`
4. If `.env` has `DEPLOYER_PRIVATE_KEY` + `RPC_URL` and `contracts/` exists:
   deploys the TOPRFRegistry contract via forge
5. Prints the contract address

After DKG, each node's health should return `{"status":"ready","node_id":N}`.

The deployed contract is immutable — no owner, no functions, no mutations.
View it on [Basescan Sepolia](https://sepolia.basescan.org).

### 9. Test evaluations

```bash
BP="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
CDH=$(echo -n "$BP" | xxd -r -p | sha256sum | cut -d' ' -f1)

curl -X POST http://<node-ip>:3001/partial-evaluate \
    -H "Content-Type: application/json" \
    -d "{\"blinded_point\": \"$BP\", \"attestation\": {\"platform\": \"test\", \"client_data_hash\": \"$CDH\"}}"
```

### 10. Resharing (adding a new node)

1. Provision and set up a new instance (steps 3-5)
2. Load the **standard** image (not genesis) and build EIF (step 6, join mode)
3. Launch the enclave + socat proxy (step 7)
4. Update the well-known config (`/.well-known/toprf-nodes.json`) with the
   new node's URL, platform (`"nitro"`), measurements (PCR values), and id
5. Run the reshare CLI:

```bash
./toprf-reshare-cli --new-node http://<new-node-ip>:3001
```

The CLI automatically:
- Discovers existing nodes from the well-known config
- Fetches the new node's attestation document and ephemeral pubkey
- Sends reshare requests to each existing donor node
- Each donor fetches fresh well-known config and verifies the new node's
  attestation (PCR values) before sending its contribution
- Delivers contributions to the new node
- Verifies the new node is operational

## Debugging

```bash
# Launch in debug mode (PCRs go to all zeros — don't use in production)
sudo nitro-cli run-enclave --eif-path ~/toprf-node.eif \
    --cpu-count 2 --memory 256 --enclave-cid 16 --debug-mode

# View console output (shows kernel boot + binary startup logs)
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
is just the TCP-to-vsock translator on the parent side. It is NOT pre-installed
on Amazon Linux — you must `sudo dnf install -y socat` in step 4.

## Why Alpine?

The binary crashes when used as a direct ENTRYPOINT in a `FROM scratch` image
inside the Nitro enclave. The Nitro init system requires a minimal userspace
to set up the process environment. Alpine (~7MB) provides this. After boot,
the binary is the only running process — Alpine's shell is not accessible.

## Common Pitfalls

1. **`--tcp` flag in init.sh** — Do NOT use `--tcp` inside the enclave. The
   enclave has no network. The binary defaults to vsock on Linux, which is
   correct. Using `--tcp` makes the binary listen on TCP inside the enclave
   where there is no TCP stack — it will be unreachable.

2. **socat not installed** — Amazon Linux does not have socat by default.
   Install it in step 4 or the proxy won't start.

3. **Health check fails immediately after launch** — The enclave takes ~10
   seconds to boot because it tries to fetch the well-known config (which
   times out since there's no internet). Wait 10 seconds before checking health.

4. **c8a.large (2 vCPU) doesn't work** — The Nitro allocator can't isolate
   CPUs with only 2 vCPUs and 1 thread per core. Use c5a.xlarge (4 vCPU)+.

5. **Debug mode zeros all PCRs** — Never use `--debug-mode` in production.
   The reshare handler rejects all-zero PCRs.

6. **Genesis images have different PCRs** — Each node's init.sh differs, so
   PCR0 differs per node. This is expected during genesis. After DKG, switch
   to the standard join-mode image for identical PCRs across all nodes.

7. **DKG CLI is a Linux binary** — Built with musl for Linux. Run it from
   an EC2 instance, not from macOS. Upload it via scp along with the `.env` file.

8. **Keys are ephemeral** — Nitro enclaves have no persistent storage. If the
   enclave restarts, the DKG key share is lost. Do not terminate enclaves
   between DKG and testing/resharing.

## Instance Sizing

| Instance | vCPUs | Works? | Monthly | Notes |
|----------|-------|--------|---------|-------|
| c8a.large | 2 | No | ~$99 | Allocator fails |
| c5a.xlarge | 4 | Yes | ~$127 | Cheapest working |
| c6a.xlarge | 4 | Yes | ~$142 | AMD EPYC Milan |
| c7a.xlarge | 4 | Yes | ~$110 | AMD EPYC Genoa |
