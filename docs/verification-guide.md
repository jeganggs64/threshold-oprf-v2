# Independent Verification Guide

How to independently verify that TOPRF nodes run the correct code and hold legitimate key shares, without trusting RuonLabs.

## What you're verifying

1. The binary running inside each enclave matches the open-source code
2. The DKG was done correctly (verification shares interpolate to the group public key)
3. Each node's attestation is signed by AWS and matches the expected measurements
4. No debug mode, no SSH, no remote access

## Prerequisites

- Rust toolchain (same version as recorded in `deployments/builds/`)
- Docker
- AWS CLI (for AMI lookup only, no credentials needed)
- `nitro-cli` (install on any Amazon Linux instance, or use Docker)
- `curl`, `jq`, `sha256sum`

## Step 1: Get the build record

Check the `deployments/builds/` directory in the repo for build records (auto-committed by CI):

```bash
cat deployments/builds/nitro-*.json
```

Note the `commit`, `rust_version`, `binary_sha256`, and `cargo_lock_sha256`.
The on-chain registry contract on Base also records the group public key and verification shares.

## Step 2: Reproduce the build

```bash
# Clone at the exact commit
git clone https://github.com/jeganggs64/threshold-oprf-v2.git
cd threshold-oprf-v2
git checkout <commit-from-build-record>

# Install the same Rust version
rustup install <rust-version-from-build-record>
rustup default <rust-version>

# Verify Cargo.lock matches
sha256sum Cargo.lock
# Compare with cargo_lock_sha256 from the build record

# Build the static binary (same command CI uses)
sudo apt-get install -y musl-tools  # Ubuntu/Debian
cargo build --release --target x86_64-unknown-linux-musl -p toprf-node --features nitro

# Compare binary hash
sha256sum target/x86_64-unknown-linux-musl/release/toprf-node
# Must match binary_sha256 from the build record
```

If the hashes match, the binary is identical to what CI produced.

## Step 3: Build the Docker image and EIF

`nitro-cli` only runs on Amazon Linux with Nitro Enclave support. You need
a temporary EC2 instance (c5a.xlarge or larger with `--enclave-options Enabled=true`)
to build the EIF and get the PCR values.

```bash
# On your local machine: build the Docker image
cp target/x86_64-unknown-linux-musl/release/toprf-node image/nitro/toprf-node
docker build -t toprf-node-enclave -f image/nitro/Dockerfile image/nitro/
docker save toprf-node-enclave:latest | gzip > toprf-node-enclave.tar.gz

# Upload to an EC2 instance with Nitro support
scp toprf-node-enclave.tar.gz ec2-user@<instance-ip>:~

# On the EC2 instance:
sudo dnf install -y aws-nitro-enclaves-cli docker
sudo systemctl enable --now docker
sudo docker load < ~/toprf-node-enclave.tar.gz
sudo nitro-cli build-enclave \
    --docker-uri toprf-node-enclave:latest \
    --output-file toprf-node.eif

# Get the PCR values
sudo nitro-cli describe-eif --eif-path toprf-node.eif
```

Note the PCR0, PCR1, PCR2 values. These are deterministic. Anyone building from the same commit + Rust version gets the same values.

## Step 4: Fetch the well-known config

```bash
curl -s https://ruonlabs.com/.well-known/toprf-nodes.json | jq .
```

Compare every node's `measurements.pcr0`, `pcr1`, `pcr2` against your Step 3 values.
All nodes use the same image, so all PCRs should be identical. Check that each node has:
- `platform: "nitro"`
- `measurements.pcr0`, `pcr1`, `pcr2`: compare against your Step 3 values
- `verificationShare`: used in Step 6

## Step 5: Get live attestation from each node

```bash
# Generate a random nonce
NONCE=$(openssl rand -hex 32)

# Request attestation from each node
curl -s "http://<node-url>:3001/attestation?nonce=$NONCE" | jq .
```

The response contains a `attestation_document` (base64-encoded COSE_Sign1) signed by AWS Nitro Security Module. To verify:

1. Decode the COSE_Sign1 document
2. Verify the certificate chain against the [AWS Nitro Root CA](https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip)
3. Verify the ECDSA-P384 signature
4. Extract PCR0, PCR1, PCR2 from the document
5. Compare against the values from Step 3

If PCRs match, the node is running exactly the binary you built.

**Debug mode check:** If PCR0/1/2 are all zeros, the enclave is in debug mode. Reject it.

## Step 6: Verify DKG consistency

The verification shares in the well-known config must interpolate to the group public key via Lagrange interpolation at x=0. This proves the DKG was done correctly.

```python
# Using any secp256k1 library:
# 1. Parse each verification share as a curve point
# 2. Pick any threshold-many shares
# 3. Compute Lagrange coefficients for those node IDs at x=0
# 4. Multiply each share by its coefficient and sum
# 5. Result must equal the group public key
```

The group public key is also recorded in the on-chain registry contract (immutable after deployment).

## Step 7: Verify on-chain registry

The TOPRFRegistry contract on Base is immutable. No owner, no functions, no mutations after deployment. All data is in the constructor:

```bash
# Read the contract (Base Sepolia example)
cast call <registry-address> "groupPublicKey()(bytes)" --rpc-url https://sepolia.base.org
cast call <registry-address> "threshold()(uint16)" --rpc-url https://sepolia.base.org
cast call <registry-address> "sourceRepo()(string)" --rpc-url https://sepolia.base.org
```

Compare the on-chain group public key with the well-known config and the value from Step 6.

## What this proves

| Check | What it proves |
|-------|---------------|
| Binary hash matches | The code you reviewed is the code that runs |
| PCRs match | The enclave image is identical to your build |
| AWS signature valid | The attestation came from a real Nitro enclave (not faked) |
| PCRs non-zero | Not in debug mode |
| Shares interpolate to GPK | DKG was done correctly, key shares are consistent |
| On-chain GPK matches | The group public key is publicly committed and immutable |
| No SSH in image | The Dockerfile contains only the binary + CA certs (verify by inspecting) |

## What you're trusting

- **AWS Nitro hypervisor**: that it correctly isolates enclave memory and signs attestation documents honestly
- **The Rust compiler**: that it compiles the code correctly
- **The secp256k1 curve**: standard cryptographic assumption

You do NOT need to trust RuonLabs, the cloud provider's host OS, or the well-known endpoint (you verify everything independently).
