#!/usr/bin/env bash
#
# Deploy the TOPRFRegistry contract.
#
# Usage:
#   cd contracts
#   cp .env.example .env   # fill in DEPLOYER_PRIVATE_KEY and RPC_URL
#   bash deploy.sh         # deploy to the configured chain
#   bash deploy.sh --verify  # deploy and verify on Basescan
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Load .env
if [[ ! -f .env ]]; then
    echo "Error: .env not found. Copy .env.example and fill in values:"
    echo "  cp .env.example .env"
    exit 1
fi
source .env

# Validate required vars
if [[ -z "${DEPLOYER_PRIVATE_KEY:-}" ]]; then
    echo "Error: DEPLOYER_PRIVATE_KEY not set in .env"
    exit 1
fi
if [[ -z "${RPC_URL:-}" ]]; then
    echo "Error: RPC_URL not set in .env"
    exit 1
fi

FORGE="${HOME}/.foundry/bin/forge"
if [[ ! -x "$FORGE" ]]; then
    echo "Error: forge not found at $FORGE. Install with: curl -L https://foundry.paradigm.xyz | bash && foundryup"
    exit 1
fi

# Build first
echo "=== Building contracts ==="
"$FORGE" build

# Run tests
echo ""
echo "=== Running tests ==="
"$FORGE" test -v
echo ""

# Check deployer balance
CAST="${HOME}/.foundry/bin/cast"
DEPLOYER_ADDRESS=$("$CAST" wallet address --private-key "$DEPLOYER_PRIVATE_KEY" 2>/dev/null)
BALANCE=$("$CAST" balance "$DEPLOYER_ADDRESS" --rpc-url "$RPC_URL" 2>/dev/null || echo "0")
echo "Deployer: $DEPLOYER_ADDRESS"
echo "Balance:  $BALANCE wei"
echo "Chain:    $RPC_URL"
echo ""

if [[ "$BALANCE" == "0" ]]; then
    echo "Warning: deployer balance is 0. The deployment will fail."
    echo "Fund the wallet with ETH on the target chain first."
    echo ""
fi

# Confirm
read -p "Deploy TOPRFRegistry to $RPC_URL? [y/N] " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Aborted."
    exit 0
fi

# Deploy
echo ""
echo "=== Deploying ==="

VERIFY_FLAGS=""
if [[ "${1:-}" == "--verify" ]]; then
    if [[ -z "${ETHERSCAN_API_KEY:-}" ]]; then
        echo "Warning: --verify requested but ETHERSCAN_API_KEY not set. Skipping verification."
    else
        VERIFY_FLAGS="--verify --etherscan-api-key $ETHERSCAN_API_KEY"
    fi
fi

"$FORGE" script script/Deploy.s.sol:DeployScript \
    --rpc-url "$RPC_URL" \
    --broadcast \
    $VERIFY_FLAGS

echo ""
echo "=== Deployment complete ==="
echo ""
echo "Next steps:"
echo "  1. Note the contract address from the output above"
echo "  2. Update the well-known endpoint with the contract address"
echo "  3. Run the DKG ceremony: toprf-dkg-cli init --registry-contract <ADDRESS> ..."
echo "  4. After finalize(), the deployer key can be discarded"
