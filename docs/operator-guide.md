# Independent Operator Guide

How to run a TOPRF node as an independent operator, joining the existing
RuonID node pool.

## What you're running

A Nitro Enclave containing the TOPRF node binary. The enclave:
- Holds one FROST key share (received via resharing from existing nodes)
- Serves partial OPRF evaluations with DLEQ proofs
- Has no SSH, no shell, no network. Only vsock to the parent EC2.
- Runs the same open-source image as all other nodes (verifiable via PCR values)

## Prerequisites

- AWS account with Nitro Enclave support (c5a.xlarge or larger)
- AWS CLI configured
- Contact RuonLabs to:
  1. Get your AWS account ID added to the WIF pool (for Play Integrity verification)
  2. Get added to the well-known config after resharing completes

## Steps

### 1. Verify the image

Before running anything, verify the image matches the open-source code:

```bash
# Clone the repo at the commit from the on-chain registry
git clone https://github.com/jeganggs64/threshold-oprf-v2.git
cd threshold-oprf-v2

# Check the build record for the Rust version
cat deployments/builds/nitro-*.json

# Build with the same Rust version
rustup install <version>
cargo build --release --target x86_64-unknown-linux-musl -p toprf-node --features nitro

# Compare binary hash
sha256sum target/x86_64-unknown-linux-musl/release/toprf-node
# Must match binary_sha256 from the build record

# Build Docker image + EIF on a Nitro-capable EC2 instance
docker build -t toprf-node-enclave -f image/nitro/Dockerfile image/nitro/
nitro-cli build-enclave --docker-uri toprf-node-enclave:latest --output-file toprf-node.eif

# Compare PCR values against the well-known config
nitro-cli describe-eif --eif-path toprf-node.eif
# PCR0, PCR1, PCR2 must match what's in the well-known endpoint
```

See [docs/verification-guide.md](verification-guide.md) for the full verification process.

### 2. Set up AWS IAM

Create an IAM role for your EC2 instances:

```bash
aws iam create-role --role-name toprf-node-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

aws iam create-instance-profile --instance-profile-name toprf-node-profile
aws iam add-role-to-instance-profile \
  --instance-profile-name toprf-node-profile \
  --role-name toprf-node-role
```

Send your AWS account ID and role ARN to RuonLabs so they can add you to
the Google Cloud WIF pool for Play Integrity verification.

### 3. Deploy your node

Use the deploy script or deploy manually:

```bash
# Download the CI-built image (or build your own from source)
gh run download <run-id> --name nitro-enclave-image -D /tmp/image

# Deploy
bash scripts/deploy-nodes.sh
```

Or manually:

```bash
# Provision EC2 with Nitro support + your instance profile
aws ec2 run-instances \
  --instance-type c5a.xlarge \
  --enclave-options Enabled=true \
  --iam-instance-profile Name=toprf-node-profile \
  ...

# Set up Nitro CLI, Docker, socat, build EIF, launch enclave
# See image/nitro/README.md for detailed steps
```

### 4. Join the network via resharing

Once your node is running, RuonLabs will:

1. Add your node to the well-known config (URL, platform, PCR measurements)
2. Run the reshare CLI: `toprf-reshare-cli --new-node http://<your-ip>:3001`
3. Your node receives a key share from the existing nodes
4. Update the well-known config with your verification share

After resharing, your node is operational and serving partial evaluations.

## What you can verify

As an operator, you can independently verify:

| Check | How |
|-------|-----|
| Your node runs the correct code | Build from source, compare PCRs |
| DKG was done correctly | On-chain registry: verification shares interpolate to group public key |
| DKG happened inside enclaves | On-chain attestation documents bind commitments to PCR values |
| Other nodes run the same code | Fetch their /attestation endpoint, verify PCRs match yours |
| The master key never existed | FROST DKG commitments on-chain prove distributed generation |

## What you trust

- **AWS Nitro hypervisor**: that it correctly isolates enclave memory
- **RuonLabs**: only for well-known config management (adding/removing nodes)
- **Google**: for Play Integrity verification (device attestation)

You do NOT need to trust RuonLabs with key material. The resharing protocol
ensures your key share is encrypted to your enclave's ephemeral key and never
visible to anyone.

## Elastic IPs

Use an elastic IP for your node so the well-known config URL survives
instance restarts. If your enclave restarts (key lost), the existing nodes
can reshare to you again at the same IP. No well-known config update needed.

## Monitoring

Monitor your node's health:

```bash
curl http://<your-ip>:3001/health
# {"status":"ready","node_id":N,"mode":"join"}
```

If the enclave restarts and returns `"waiting_for_config"`, contact
RuonLabs to trigger a reshare to restore your key share.
