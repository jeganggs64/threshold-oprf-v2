#!/usr/bin/env bash
#
# Deploy TOPRF Nitro Enclave nodes across AWS regions.
#
# Provisions EC2 instances, installs Nitro CLI + Docker + socat,
# uploads the enclave image, builds the EIF, and launches the enclave
# with a socat TCP-to-vsock proxy.
#
# Works for both genesis mode (initial DKG) and join mode (resharing).
#
# Usage:
#   cp scripts/deploy-nodes.env.example scripts/deploy-nodes.env
#   # Edit deploy-nodes.env
#   bash scripts/deploy-nodes.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Load env file
ENV_FILE="${SCRIPT_DIR}/deploy-nodes.env"
if [[ ! -f "$ENV_FILE" ]]; then
    echo "Error: $ENV_FILE not found"
    echo "Copy deploy-nodes.env.example to deploy-nodes.env and fill in values"
    exit 1
fi
source "$ENV_FILE"

# Validate required vars
for var in TOPRF_REGIONS TOPRF_KEY_NAME TOPRF_IMAGE_DIR; do
    if [[ -z "${!var:-}" ]]; then
        echo "Error: $var is not set in $ENV_FILE"
        exit 1
    fi
done

# Defaults
TOPRF_INSTANCE_TYPE="${TOPRF_INSTANCE_TYPE:-c5a.xlarge}"
TOPRF_MODE="${TOPRF_MODE:-genesis}"
TOPRF_THRESHOLD="${TOPRF_THRESHOLD:-2}"
TOPRF_TOTAL="${TOPRF_TOTAL:-3}"
TOPRF_CLI_DIR="${TOPRF_CLI_DIR:-}"

# Parse regions into array
IFS=',' read -ra REGIONS <<< "$TOPRF_REGIONS"
NUM_NODES=${#REGIONS[@]}

echo "=== TOPRF Node Deployment ==="
echo "  Mode:      $TOPRF_MODE"
echo "  Regions:   ${REGIONS[*]}"
echo "  Nodes:     $NUM_NODES"
echo "  Instance:  $TOPRF_INSTANCE_TYPE"
echo "  Key:       $TOPRF_KEY_NAME"
echo "  Image dir: $TOPRF_IMAGE_DIR"
if [[ "$TOPRF_MODE" == "genesis" ]]; then
    echo "  Threshold: $TOPRF_THRESHOLD of $TOPRF_TOTAL"
fi
echo ""

# Validate artifacts exist
if [[ ! -f "$TOPRF_IMAGE_DIR/toprf-node-enclave.tar.gz" ]]; then
    echo "Error: $TOPRF_IMAGE_DIR/toprf-node-enclave.tar.gz not found"
    exit 1
fi
if [[ ! -f "$TOPRF_IMAGE_DIR/toprf-node" ]]; then
    echo "Error: $TOPRF_IMAGE_DIR/toprf-node not found"
    exit 1
fi

# ---------- Find or create security groups ----------

declare -A SG_IDS

for region in "${REGIONS[@]}"; do
    SG_NAME="toprf-v2-nitro"

    # Check if security group exists
    sg_id=$(aws ec2 describe-security-groups --region "$region" \
        --filters "Name=group-name,Values=$SG_NAME" \
        --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo "None")

    if [[ "$sg_id" == "None" || -z "$sg_id" ]]; then
        echo "[${region}] Creating security group $SG_NAME..."
        sg_id=$(aws ec2 create-security-group --region "$region" \
            --group-name "$SG_NAME" \
            --description "TOPRF Nitro Enclave nodes - SSH + HTTP" \
            --query 'GroupId' --output text)

        # Allow SSH
        aws ec2 authorize-security-group-ingress --region "$region" \
            --group-id "$sg_id" --protocol tcp --port 22 --cidr 0.0.0.0/0 > /dev/null

        # Allow node traffic
        aws ec2 authorize-security-group-ingress --region "$region" \
            --group-id "$sg_id" --protocol tcp --port 3001 --cidr 0.0.0.0/0 > /dev/null

        echo "[${region}] Created security group: $sg_id"
    else
        echo "[${region}] Using existing security group: $sg_id"
    fi

    SG_IDS[$region]=$sg_id
done

# ---------- Create or find key pair ----------

SSH_KEY_FILE="$HOME/.ssh/${TOPRF_KEY_NAME}.pem"

# Create key in the first region, import to the rest
FIRST_REGION="${REGIONS[0]}"

if [[ -f "$SSH_KEY_FILE" ]]; then
    echo "Using existing SSH key: $SSH_KEY_FILE"
else
    echo "Creating new SSH key pair: $TOPRF_KEY_NAME"
    # Generate a local key pair
    ssh-keygen -t ed25519 -f "$SSH_KEY_FILE" -N "" -q
    chmod 400 "$SSH_KEY_FILE"
    echo "  Private key: $SSH_KEY_FILE"
fi

# Ensure the key pair exists in each region
PUB_KEY_FILE="${SSH_KEY_FILE}.pub"
if [[ ! -f "$PUB_KEY_FILE" ]]; then
    ssh-keygen -y -f "$SSH_KEY_FILE" > "$PUB_KEY_FILE"
fi

for region in "${REGIONS[@]}"; do
    if aws ec2 describe-key-pairs --region "$region" --key-names "$TOPRF_KEY_NAME" > /dev/null 2>&1; then
        echo "[${region}] Key pair exists: $TOPRF_KEY_NAME"
    else
        echo "[${region}] Importing key pair: $TOPRF_KEY_NAME"
        aws ec2 import-key-pair --region "$region" \
            --key-name "$TOPRF_KEY_NAME" \
            --public-key-material fileb://"$PUB_KEY_FILE" > /dev/null
    fi
done

# ---------- Get latest Amazon Linux 2023 AMI per region ----------

declare -A AMIS

for region in "${REGIONS[@]}"; do
    ami=$(aws ec2 describe-images --region "$region" \
        --owners amazon \
        --filters "Name=name,Values=al2023-ami-2023*-x86_64" "Name=state,Values=available" \
        --query 'sort_by(Images, &CreationDate)[-1].ImageId' --output text)
    AMIS[$region]=$ami
    echo "[${region}] AMI: $ami"
done

# ---------- Provision instances ----------

declare -A INSTANCE_IDS

echo ""
echo "=== Provisioning instances ==="

for region in "${REGIONS[@]}"; do
    instance_id=$(aws ec2 run-instances --region "$region" \
        --image-id "${AMIS[$region]}" \
        --instance-type "$TOPRF_INSTANCE_TYPE" \
        --key-name "$TOPRF_KEY_NAME" \
        --security-group-ids "${SG_IDS[$region]}" \
        --associate-public-ip-address \
        --enclave-options Enabled=true \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=toprf-v2-nitro-${region}}]" \
        --query 'Instances[0].InstanceId' --output text)
    INSTANCE_IDS[$region]=$instance_id
    echo "[${region}] Instance: $instance_id"
done

# ---------- Wait for public IPs ----------

echo ""
echo "=== Waiting for public IPs ==="

declare -A NODE_IPS
declare -a IP_LIST

sleep 20  # Wait for instances to initialize

for region in "${REGIONS[@]}"; do
    ip=""
    for attempt in $(seq 1 12); do
        ip=$(aws ec2 describe-instances --region "$region" \
            --instance-ids "${INSTANCE_IDS[$region]}" \
            --query 'Reservations[0].Instances[0].PublicIpAddress' --output text 2>/dev/null || echo "None")
        if [[ "$ip" != "None" && -n "$ip" ]]; then
            break
        fi
        sleep 5
    done
    if [[ "$ip" == "None" || -z "$ip" ]]; then
        echo "Error: Failed to get public IP for ${INSTANCE_IDS[$region]} in $region"
        exit 1
    fi
    NODE_IPS[$region]=$ip
    IP_LIST+=("$ip")
    echo "[${region}] IP: $ip"
done

# ---------- Wait for SSH ----------

echo ""
echo "=== Waiting for SSH ==="

for region in "${REGIONS[@]}"; do
    ip="${NODE_IPS[$region]}"
    for attempt in $(seq 1 20); do
        if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$SSH_KEY_FILE" \
            ec2-user@"$ip" "echo OK" > /dev/null 2>&1; then
            echo "[${region}] SSH ready: $ip"
            break
        fi
        sleep 5
    done
done

# ---------- Set up and deploy on each instance ----------

setup_node() {
    local region=$1 ip=$2 node_id=$3
    local peers=""

    # Build peer list (all other nodes)
    for other_ip in "${IP_LIST[@]}"; do
        if [[ "$other_ip" != "$ip" ]]; then
            [[ -n "$peers" ]] && peers="$peers,"
            peers="${peers}http://${other_ip}:3001"
        fi
    done

    echo "[${region}] Setting up $ip (node $node_id)..."

    # Step 4: Install packages
    ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_FILE" ec2-user@"$ip" "
        sudo dnf install -y -q aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker socat 2>&1 | tail -1
        sudo systemctl enable --now docker 2>&1 | tail -1
        sudo systemctl enable --now nitro-enclaves-allocator 2>&1 | tail -1
        sudo usermod -aG docker ec2-user
        sudo usermod -aG ne ec2-user
        sudo tee /etc/nitro_enclaves/allocator.yaml > /dev/null <<AEOF
---
memory_mib: 512
cpu_count: 2
AEOF
        sudo systemctl restart nitro-enclaves-allocator 2>&1 | tail -1
    " 2>&1

    # Step 5: Upload artifacts
    scp -q -o StrictHostKeyChecking=no -i "$SSH_KEY_FILE" \
        "$TOPRF_IMAGE_DIR/toprf-node-enclave.tar.gz" \
        "$TOPRF_IMAGE_DIR/toprf-node" \
        ec2-user@"$ip":~

    # Upload CLI binaries if specified
    if [[ -n "$TOPRF_CLI_DIR" && -d "$TOPRF_CLI_DIR" ]]; then
        scp -q -o StrictHostKeyChecking=no -i "$SSH_KEY_FILE" \
            "$TOPRF_CLI_DIR"/toprf-dkg-cli \
            "$TOPRF_CLI_DIR"/toprf-reshare-cli \
            ec2-user@"$ip":~ 2>/dev/null || true
        ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_FILE" ec2-user@"$ip" \
            "chmod +x ~/toprf-dkg-cli ~/toprf-reshare-cli 2>/dev/null" || true
    fi

    # Step 6: Load image, build EIF
    if [[ "$TOPRF_MODE" == "genesis" ]]; then
        # Genesis: create per-node init.sh
        ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_FILE" ec2-user@"$ip" "
            sudo docker load < ~/toprf-node-enclave.tar.gz 2>&1 | tail -1

            cat > /tmp/init.sh <<SEOF
#!/bin/sh
exec /toprf-node \\\\
    --genesis \"$peers\" \\\\
    --node-id $node_id \\\\
    --threshold $TOPRF_THRESHOLD \\\\
    --total $TOPRF_TOTAL \\\\
    --port 3001
SEOF
            chmod +x /tmp/init.sh

            cat > /tmp/Dockerfile.genesis <<'DEOF'
FROM toprf-node-enclave:latest
COPY init.sh /init.sh
RUN chmod +x /init.sh
ENTRYPOINT [\"/init.sh\"]
CMD []
DEOF
            cd /tmp
            sudo docker build -t toprf-node-enclave:genesis -f Dockerfile.genesis . 2>&1 | tail -1
            sudo nitro-cli build-enclave --docker-uri toprf-node-enclave:genesis --output-file ~/toprf-node.eif 2>&1 | grep PCR0
        " 2>&1
    else
        # Join mode: use standard image as-is
        ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_FILE" ec2-user@"$ip" "
            sudo docker load < ~/toprf-node-enclave.tar.gz 2>&1 | tail -1
            sudo nitro-cli build-enclave --docker-uri toprf-node-enclave:latest --output-file ~/toprf-node.eif 2>&1 | grep PCR0
        " 2>&1
    fi

    # Step 7: Launch enclave + socat
    # The enclave launch steals CPUs from the parent which can kill the SSH
    # session. We ignore the SSH exit code and reconnect after a delay.
    ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_FILE" ec2-user@"$ip" "
        sudo nitro-cli run-enclave --eif-path ~/toprf-node.eif \
            --cpu-count 2 --memory 256 --enclave-cid 16 2>&1
        sleep 2

        # Inbound proxy: TCP:3001 -> vsock (clients reach the enclave)
        nohup socat TCP-LISTEN:3001,fork,reuseaddr VSOCK-CONNECT:16:3001 > ~/proxy.log 2>&1 &

        # Outbound proxies: vsock -> internet (enclave reaches external services)
        # The enclave's binary bridges TCP 127.0.0.1:<port> -> vsock CID 3:<port>
        # These vsock-proxy instances forward vsock connections to the real endpoints
        nohup vsock-proxy 8080 169.254.169.254 80 > ~/proxy-metadata.log 2>&1 &
        nohup vsock-proxy 8443 sts.googleapis.com 443 > ~/proxy-google-sts.log 2>&1 &
        nohup vsock-proxy 8444 playintegrity.googleapis.com 443 > ~/proxy-play-integrity.log 2>&1 &
        nohup vsock-proxy 8445 ruonlabs.com 443 > ~/proxy-well-known.log 2>&1 &
        nohup vsock-proxy 8446 iamcredentials.googleapis.com 443 > ~/proxy-google-iam.log 2>&1 &
    " 2>&1 || true

    # Wait for enclave to boot (~10s for well-known timeout + startup)
    echo "[${region}] Waiting for enclave to boot..."
    sleep 15

    # Reconnect and check health
    local health=""
    for attempt in $(seq 1 6); do
        health=$(curl -sf --connect-timeout 5 "http://${ip}:3001/health" 2>/dev/null || echo "")
        if [[ -n "$health" ]]; then
            break
        fi
        sleep 5
    done

    if [[ -n "$health" ]]; then
        echo "[${region}] Node $node_id deployed at $ip: $health"
    else
        # SSH back in to start socat (may not have started if SSH dropped)
        echo "[${region}] Reconnecting to start socat..."
        ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_FILE" ec2-user@"$ip" "
            pgrep socat > /dev/null || nohup socat TCP-LISTEN:3001,fork,reuseaddr VSOCK-CONNECT:16:3001 > ~/proxy.log 2>&1 &
        " 2>&1 || true
        sleep 15
        health=$(curl -sf --connect-timeout 5 "http://${ip}:3001/health" 2>/dev/null || echo "FAILED")
        echo "[${region}] Node $node_id deployed at $ip: $health"
    fi
}

echo ""
echo "=== Deploying nodes ==="

node_id=1
for region in "${REGIONS[@]}"; do
    setup_node "$region" "${NODE_IPS[$region]}" "$node_id"
    node_id=$((node_id + 1))
done

# ---------- Output ----------

echo ""
echo "========================================"
echo "  Deployment Complete"
echo "========================================"
echo ""
echo "Node IPs:"
node_id=1
for region in "${REGIONS[@]}"; do
    echo "  Node $node_id ($region): ${NODE_IPS[$region]}"
    node_id=$((node_id + 1))
done

# Build comma-separated IP list for DKG
NODE_URLS=""
for ip in "${IP_LIST[@]}"; do
    [[ -n "$NODE_URLS" ]] && NODE_URLS="$NODE_URLS,"
    NODE_URLS="${NODE_URLS}http://${ip}:3001"
done

echo ""
echo "SSH key: $SSH_KEY_FILE"
echo ""
echo "For run-dkg.env:"
echo "  TOPRF_NODE_URLS=\"$NODE_URLS\""
echo "  TOPRF_DKG_HOST=\"${IP_LIST[0]}\""
echo "  TOPRF_KEY_NAME=\"$TOPRF_KEY_NAME\""
echo ""

if [[ "$TOPRF_MODE" == "genesis" ]]; then
    echo "Next: configure scripts/run-dkg.env and run: bash scripts/run-dkg.sh"
else
    echo "Next: update well-known config with new node, then run:"
    echo "  toprf-reshare-cli --new-node http://${IP_LIST[0]}:3001"
fi
