#!/usr/bin/env bash
#
# Run DKG ceremony on deployed TOPRF nodes.
#
# Connects to the DKG host instance via SSH, uploads .env with deployer
# credentials, and runs the DKG CLI. Optionally deploys the TOPRFRegistry
# contract to Base.
#
# Usage:
#   cp scripts/run-dkg.env.example scripts/run-dkg.env
#   # Edit run-dkg.env
#   bash scripts/run-dkg.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Load env file
ENV_FILE="${SCRIPT_DIR}/run-dkg.env"
if [[ ! -f "$ENV_FILE" ]]; then
    echo "Error: $ENV_FILE not found"
    echo "Copy run-dkg.env.example to run-dkg.env and fill in values"
    exit 1
fi
source "$ENV_FILE"

# Validate required vars
for var in TOPRF_NODE_URLS TOPRF_DKG_HOST TOPRF_KEY_NAME; do
    if [[ -z "${!var:-}" ]]; then
        echo "Error: $var is not set in $ENV_FILE"
        exit 1
    fi
done

SSH_KEY_FILE="$HOME/.ssh/${TOPRF_KEY_NAME}.pem"
if [[ ! -f "$SSH_KEY_FILE" ]]; then
    echo "Error: SSH key not found: $SSH_KEY_FILE"
    echo "Run deploy-nodes.sh first to create it"
    exit 1
fi
DEPLOYER_PRIVATE_KEY="${DEPLOYER_PRIVATE_KEY:-}"
RPC_URL="${RPC_URL:-https://sepolia.base.org}"

echo "=== TOPRF DKG Ceremony ==="
echo "  Nodes: $TOPRF_NODE_URLS"
echo "  DKG host: $TOPRF_DKG_HOST"
if [[ -n "$DEPLOYER_PRIVATE_KEY" ]]; then
    echo "  Contract deployment: enabled (${RPC_URL})"
else
    echo "  Contract deployment: disabled (no DEPLOYER_PRIVATE_KEY)"
fi
echo ""

# Verify all nodes are healthy
echo "=== Checking node health ==="
IFS=',' read -ra URLS <<< "$TOPRF_NODE_URLS"
for url in "${URLS[@]}"; do
    status=$(curl -sf "$url/health" 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null || echo "unreachable")
    echo "  $url: $status"
    if [[ "$status" != "waiting_for_key" ]]; then
        echo "  WARNING: expected 'waiting_for_key', got '$status'"
    fi
done

# Upload .env to DKG host
echo ""
echo "=== Uploading credentials to DKG host ==="
ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_FILE" ec2-user@"$TOPRF_DKG_HOST" "
    cat > ~/.env <<ENVEOF
DEPLOYER_PRIVATE_KEY=$DEPLOYER_PRIVATE_KEY
RPC_URL=$RPC_URL
ENVEOF
"
echo "  .env uploaded"

# Upload contracts if deploying on-chain
if [[ -n "$DEPLOYER_PRIVATE_KEY" ]]; then
    echo ""
    echo "=== Setting up contract deployment ==="

    # Check if contracts.tar.gz exists locally
    CONTRACTS_TAR=""
    if [[ -f "$REPO_ROOT/contracts.tar.gz" ]]; then
        CONTRACTS_TAR="$REPO_ROOT/contracts.tar.gz"
    fi

    # Try to find it in CLI dir from deploy env
    DEPLOY_ENV="${SCRIPT_DIR}/deploy-nodes.env"
    if [[ -z "$CONTRACTS_TAR" && -f "$DEPLOY_ENV" ]]; then
        source "$DEPLOY_ENV"
        if [[ -n "${TOPRF_CLI_DIR:-}" && -f "${TOPRF_CLI_DIR}/../contracts/contracts.tar.gz" ]]; then
            CONTRACTS_TAR="${TOPRF_CLI_DIR}/../contracts/contracts.tar.gz"
        fi
    fi

    if [[ -n "$CONTRACTS_TAR" ]]; then
        echo "  Uploading contracts..."
        scp -q -o StrictHostKeyChecking=no -i "$SSH_KEY_FILE" \
            "$CONTRACTS_TAR" ec2-user@"$TOPRF_DKG_HOST":~

        ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_FILE" ec2-user@"$TOPRF_DKG_HOST" "
            mkdir -p ~/contracts
            tar xzf ~/contracts.tar.gz -C ~/contracts
        "
        echo "  Contracts uploaded"

        # Install foundry if not present
        echo "  Checking foundry..."
        ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_FILE" ec2-user@"$TOPRF_DKG_HOST" "
            if ! command -v forge &>/dev/null; then
                echo '  Installing foundry...'
                curl -sL https://foundry.paradigm.xyz | bash 2>&1 | tail -1
                source ~/.bashrc
                ~/.foundry/bin/foundryup 2>&1 | tail -1
            else
                echo '  Foundry already installed'
            fi
        " 2>&1
    else
        echo "  WARNING: contracts.tar.gz not found — contract deployment may be skipped"
    fi
fi

# Run DKG
echo ""
echo "=== Running DKG ceremony ==="
ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_FILE" ec2-user@"$TOPRF_DKG_HOST" "
    cd ~
    chmod +x ~/toprf-dkg-cli 2>/dev/null || true
    ./toprf-dkg-cli init --nodes '$TOPRF_NODE_URLS'
" 2>&1

# Verify nodes are ready
echo ""
echo "=== Verifying nodes after DKG ==="
for url in "${URLS[@]}"; do
    resp=$(curl -sf "$url/health" 2>/dev/null || echo '{"status":"unreachable"}')
    status=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null || echo "?")
    node_id=$(echo "$resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('node_id','?'))" 2>/dev/null || echo "?")
    echo "  $url: status=$status, node_id=$node_id"
done

# Download dkg-data.json
echo ""
echo "=== Downloading DKG data ==="
scp -q -o StrictHostKeyChecking=no -i "$SSH_KEY_FILE" \
    ec2-user@"$TOPRF_DKG_HOST":~/dkg-data.json \
    "$REPO_ROOT/dkg-data.json" 2>/dev/null || true

if [[ -f "$REPO_ROOT/dkg-data.json" ]]; then
    echo "  Saved to $REPO_ROOT/dkg-data.json"
    gpk=$(python3 -c "import json; print(json.load(open('$REPO_ROOT/dkg-data.json')).get('groupPublicKey','?'))" 2>/dev/null || echo "?")
    echo "  Group public key: $gpk"
else
    echo "  WARNING: dkg-data.json not downloaded"
fi

echo ""
echo "========================================"
echo "  DKG Complete"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Update well-known config with node URLs, PCR values, and verification shares"
echo "  2. Deploy contract if not auto-deployed: cd contracts && bash deploy.sh"
echo "  3. Test evaluations: curl -X POST http://<node-ip>:3001/partial-evaluate ..."
