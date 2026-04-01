#!/usr/bin/env bash
#
# End-to-end DKG integration test.
#
# Tests the complete DKG ceremony flow:
#   1. Build workspace
#   2. Start 3 DKG nodes + 3 production nodes (join mode)
#   3. Wait for all 6 nodes to be healthy
#   4. Run toprf-dkg-cli init to orchestrate the DKG and deliver shares
#   5. Wait for production nodes to show "ready" (key loaded)
#   6. Test /partial-evaluate on all 3 production nodes
#   7. Verify partial points and DLEQ proofs
#   8. Kill DKG nodes and confirm production nodes still work independently
#   9. Print pass/fail summary
#
set -euo pipefail

# Allow test attestation platform in dev/CI
export TOPRF_ALLOW_TEST_ATTESTATION=1

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"

# Binary paths (built in step 1)
DKG_NODE="$REPO_ROOT/target/release/toprf-dkg-node"
DKG_CLI="$REPO_ROOT/target/release/toprf-dkg-cli"
NODE="$REPO_ROOT/target/release/toprf-node"

# Port allocation
DKG_PORT_1=4001
DKG_PORT_2=4002
DKG_PORT_3=4003

PROD_PORT_1=3001
PROD_PORT_2=3002
PROD_PORT_3=3003

PIDS=()
DKG_PIDS=()
PASS=0
FAIL=0

# ---------- sha256 helper ----------

sha256_hex() {
    if command -v shasum > /dev/null 2>&1; then
        shasum -a 256 | cut -d' ' -f1
    else
        sha256sum | cut -d' ' -f1
    fi
}

hex_bytes_sha256() {
    printf '%s' "$1" | xxd -r -p | sha256_hex
}

# ---------- cleanup ----------

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${DKG_PIDS[@]+"${DKG_PIDS[@]}"}"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    for pid in "${PIDS[@]+"${PIDS[@]}"}"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    # Clean up node-key.json written by reshare/receive handler
    rm -f "$REPO_ROOT/node-key.json"
    rm -rf "$TMPDIR"
    echo "Temp dir removed: $TMPDIR"
}
trap cleanup EXIT

# ---------- helpers ----------

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc (expected '$expected', got '$actual')"
        FAIL=$((FAIL + 1))
    fi
}

assert_match() {
    local desc="$1" pattern="$2" actual="$3"
    if [[ "$actual" =~ $pattern ]]; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc (pattern '$pattern' did not match '$actual')"
        FAIL=$((FAIL + 1))
    fi
}

wait_for_health() {
    local url="$1" label="$2" max_wait="${3:-30}"
    local waited=0
    echo "  Waiting for $label at $url ..."
    while ! curl -sf "$url" > /dev/null 2>&1; do
        sleep 0.5
        waited=$((waited + 1))
        if [[ $waited -ge $((max_wait * 2)) ]]; then
            echo "  FATAL: $label did not become healthy within ${max_wait}s"
            exit 1
        fi
    done
    echo "  $label is ready."
}

wait_for_ready() {
    local url="$1" label="$2" max_wait="${3:-60}"
    local waited=0
    echo "  Waiting for $label to show status=ready ..."
    while true; do
        local status
        status=$(curl -sf "$url" 2>/dev/null | jq -r '.status' 2>/dev/null || echo "")
        if [[ "$status" == "ready" ]]; then
            echo "  $label is ready (key loaded)."
            return 0
        fi
        sleep 0.5
        waited=$((waited + 1))
        if [[ $waited -ge $((max_wait * 2)) ]]; then
            echo "  FATAL: $label did not become ready within ${max_wait}s"
            exit 1
        fi
    done
}

# ---------- pre-flight: ensure ports are free ----------

echo "=== Pre-flight: Checking ports are free ==="
ALL_PORTS="$DKG_PORT_1 $DKG_PORT_2 $DKG_PORT_3 $PROD_PORT_1 $PROD_PORT_2 $PROD_PORT_3"
for p in $ALL_PORTS; do
    if lsof -i ":$p" > /dev/null 2>&1; then
        echo "  FATAL: port $p is already in use. Kill the process and retry."
        lsof -i ":$p" 2>/dev/null
        exit 1
    fi
done
echo "  All ports are free."

# Clean up any leftover node-key.json from prior runs
rm -f "$REPO_ROOT/node-key.json"

# ---------- 1. Build workspace ----------

echo ""
echo "=== Step 1: Building workspace (release) ==="
cd "$REPO_ROOT"
cargo build --release 2>&1 | tail -5
echo "  Build complete."

# Verify binaries exist
for bin in "$DKG_NODE" "$DKG_CLI" "$NODE"; do
    if [[ ! -x "$bin" ]]; then
        echo "  FATAL: binary not found: $bin"
        exit 1
    fi
done
echo "  All binaries found."

# ---------- 2. Start 3 DKG nodes + 3 production nodes ----------

echo ""
echo "=== Step 2: Starting 3 DKG nodes + 3 production nodes ==="

# Start DKG nodes
for i in 1 2 3; do
    port_var="DKG_PORT_${i}"
    port="${!port_var}"
    "$DKG_NODE" --node-id "$i" --threshold 2 --total 3 --port "$port" \
        > "$TMPDIR/dkg-node-${i}.log" 2>&1 &
    DKG_PIDS+=($!)
    echo "  DKG node $i started (PID $!, port $port)"
done

# Start production nodes in --join mode (no key file)
for i in 1 2 3; do
    port_var="PROD_PORT_${i}"
    port="${!port_var}"
    "$NODE" --port "$port" --join \
        > "$TMPDIR/prod-node-${i}.log" 2>&1 &
    PIDS+=($!)
    echo "  Production node $i started (PID $!, port $port, join mode)"
done

# ---------- 3. Wait for all 6 nodes to be healthy ----------

echo ""
echo "=== Step 3: Waiting for all 6 nodes to be healthy ==="

for i in 1 2 3; do
    port_var="DKG_PORT_${i}"
    port="${!port_var}"
    wait_for_health "http://127.0.0.1:$port/health" "DKG node $i"
done

for i in 1 2 3; do
    port_var="PROD_PORT_${i}"
    port="${!port_var}"
    wait_for_health "http://127.0.0.1:$port/health" "Production node $i"
done

# Verify production nodes are in waiting_for_key state
echo ""
echo "--- Verifying production nodes are in waiting_for_key state ---"
for i in 1 2 3; do
    port_var="PROD_PORT_${i}"
    port="${!port_var}"
    HEALTH_RESP=$(curl -sf "http://127.0.0.1:$port/health")
    HEALTH_STATUS=$(printf '%s' "$HEALTH_RESP" | jq -r '.status')
    assert_eq "production node $i starts with status 'waiting_for_key'" "waiting_for_key" "$HEALTH_STATUS"
done

# ---------- 4. Run DKG CLI init ----------

echo ""
echo "=== Step 4: Running toprf-dkg-cli init ==="

DKG_URLS="http://127.0.0.1:$DKG_PORT_1,http://127.0.0.1:$DKG_PORT_2,http://127.0.0.1:$DKG_PORT_3"
PROD_URLS="http://127.0.0.1:$PROD_PORT_1,http://127.0.0.1:$PROD_PORT_2,http://127.0.0.1:$PROD_PORT_3"

"$DKG_CLI" init \
    --dkg-nodes "$DKG_URLS" \
    --production-nodes "$PROD_URLS" \
    > "$TMPDIR/dkg-cli.log" 2>&1

DKG_CLI_EXIT=$?
echo "  DKG CLI exit code: $DKG_CLI_EXIT"
assert_eq "DKG CLI exits with 0" "0" "$DKG_CLI_EXIT"

if [[ $DKG_CLI_EXIT -ne 0 ]]; then
    echo "  DKG CLI output:"
    cat "$TMPDIR/dkg-cli.log"
    echo ""
    echo "  FATAL: DKG CLI failed, cannot continue"
    exit 1
fi

echo "  DKG CLI output (last 10 lines):"
tail -10 "$TMPDIR/dkg-cli.log" | sed 's/^/    /'

# ---------- 5. Wait for production nodes to show "ready" ----------

echo ""
echo "=== Step 5: Waiting for production nodes to be ready (key loaded) ==="

for i in 1 2 3; do
    port_var="PROD_PORT_${i}"
    port="${!port_var}"
    wait_for_ready "http://127.0.0.1:$port/health" "Production node $i"
done

# Verify health status
echo ""
echo "--- Verifying production nodes are now ready ---"
for i in 1 2 3; do
    port_var="PROD_PORT_${i}"
    port="${!port_var}"
    HEALTH_RESP=$(curl -sf "http://127.0.0.1:$port/health")
    HEALTH_STATUS=$(printf '%s' "$HEALTH_RESP" | jq -r '.status')
    assert_eq "production node $i health status is 'ready'" "ready" "$HEALTH_STATUS"

    NODE_ID_FIELD=$(printf '%s' "$HEALTH_RESP" | jq -r '.node_id')
    assert_eq "production node $i health node_id is $i" "$i" "$NODE_ID_FIELD"
done

# ---------- 6. Test /partial-evaluate on all 3 production nodes ----------

echo ""
echo "=== Step 6: Testing /partial-evaluate on each production node ==="

# secp256k1 generator point (compressed)
BLINDED_POINT="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
CDH=$(hex_bytes_sha256 "$BLINDED_POINT")
echo "  Blinded point: $BLINDED_POINT"
echo "  client_data_hash: $CDH"

for i in 1 2 3; do
    echo ""
    echo "--- Test 6.$i: POST /partial-evaluate on production node $i ---"
    port_var="PROD_PORT_${i}"
    port="${!port_var}"

    PE_HTTP_CODE=$(curl -s -o "$TMPDIR/pe_resp_${i}.json" -w "%{http_code}" \
        -X POST "http://127.0.0.1:$port/partial-evaluate" \
        -H "Content-Type: application/json" \
        -d "{\"blinded_point\": \"$BLINDED_POINT\", \"attestation\": {\"platform\": \"test\", \"client_data_hash\": \"$CDH\"}}")

    if [[ "$PE_HTTP_CODE" != "200" ]]; then
        echo "  DEBUG: /partial-evaluate on production node $i returned HTTP $PE_HTTP_CODE"
        echo "  DEBUG: response body: $(cat "$TMPDIR/pe_resp_${i}.json" 2>/dev/null)"
        echo "  DEBUG: production node $i log (last 20 lines):"
        tail -20 "$TMPDIR/prod-node-${i}.log" 2>/dev/null || echo "(no log)"
    fi
    assert_eq "production node $i /partial-evaluate returns 200" "200" "$PE_HTTP_CODE"

    if [[ -f "$TMPDIR/pe_resp_${i}.json" && "$PE_HTTP_CODE" == "200" ]]; then
        PE_RESP=$(cat "$TMPDIR/pe_resp_${i}.json")

        # node_id
        PE_NODE_ID=$(printf '%s' "$PE_RESP" | jq -r '.node_id')
        assert_eq "production node $i response node_id is $i" "$i" "$PE_NODE_ID"

        # partial_point: valid compressed secp256k1 point (02 or 03 prefix + 64 hex chars)
        PARTIAL_POINT=$(printf '%s' "$PE_RESP" | jq -r '.partial_point')
        assert_match "production node $i partial_point is valid compressed point" \
            '^(02|03)[0-9a-f]{64}$' "$PARTIAL_POINT"

        # dleq_proof.challenge: 64 hex chars
        CHALLENGE=$(printf '%s' "$PE_RESP" | jq -r '.dleq_proof.challenge')
        assert_match "production node $i dleq_proof.challenge is 64 hex" \
            '^[0-9a-f]{64}$' "$CHALLENGE"

        # dleq_proof.response: 64 hex chars
        RESPONSE=$(printf '%s' "$PE_RESP" | jq -r '.dleq_proof.response')
        assert_match "production node $i dleq_proof.response is 64 hex" \
            '^[0-9a-f]{64}$' "$RESPONSE"
    else
        echo "  FAIL: no valid response from production node $i /partial-evaluate"
        FAIL=$((FAIL + 1))
    fi
done

# ---------- 7. Verify all 3 partial points are distinct ----------

echo ""
echo "=== Step 7: Verifying partial points are distinct ==="

if [[ -f "$TMPDIR/pe_resp_1.json" && -f "$TMPDIR/pe_resp_2.json" && -f "$TMPDIR/pe_resp_3.json" ]]; then
    PP1=$(jq -r '.partial_point' "$TMPDIR/pe_resp_1.json")
    PP2=$(jq -r '.partial_point' "$TMPDIR/pe_resp_2.json")
    PP3=$(jq -r '.partial_point' "$TMPDIR/pe_resp_3.json")

    # Each node's partial evaluation should be different (different key shares)
    if [[ "$PP1" != "$PP2" ]]; then
        echo "  PASS: partial_point from node 1 differs from node 2"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: partial_point from node 1 is same as node 2 ($PP1)"
        FAIL=$((FAIL + 1))
    fi

    if [[ "$PP2" != "$PP3" ]]; then
        echo "  PASS: partial_point from node 2 differs from node 3"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: partial_point from node 2 is same as node 3 ($PP2)"
        FAIL=$((FAIL + 1))
    fi

    if [[ "$PP1" != "$PP3" ]]; then
        echo "  PASS: partial_point from node 1 differs from node 3"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: partial_point from node 1 is same as node 3 ($PP1)"
        FAIL=$((FAIL + 1))
    fi
else
    echo "  SKIP: cannot verify distinctness, not all partial eval responses available"
fi

# ---------- 8. Kill DKG nodes ----------

echo ""
echo "=== Step 8: Killing DKG nodes (ceremony complete) ==="

for pid in "${DKG_PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
done
DKG_PIDS=()
echo "  All DKG nodes stopped."

# ---------- 9. Verify production nodes still work after DKG nodes are gone ----------

echo ""
echo "=== Step 9: Testing production nodes still work after DKG shutdown ==="

# Use a different blinded point to avoid rate limit issues
BLINDED_POINT_2="02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
CDH_2=$(hex_bytes_sha256 "$BLINDED_POINT_2")
echo "  Blinded point 2: $BLINDED_POINT_2"
echo "  client_data_hash 2: $CDH_2"

for i in 1 2 3; do
    echo ""
    echo "--- Test 9.$i: POST /partial-evaluate on production node $i (DKG nodes gone) ---"
    port_var="PROD_PORT_${i}"
    port="${!port_var}"

    PE2_HTTP_CODE=$(curl -s -o "$TMPDIR/pe2_resp_${i}.json" -w "%{http_code}" \
        -X POST "http://127.0.0.1:$port/partial-evaluate" \
        -H "Content-Type: application/json" \
        -d "{\"blinded_point\": \"$BLINDED_POINT_2\", \"attestation\": {\"platform\": \"test\", \"client_data_hash\": \"$CDH_2\"}}")

    assert_eq "production node $i still works after DKG shutdown (HTTP 200)" "200" "$PE2_HTTP_CODE"

    if [[ "$PE2_HTTP_CODE" == "200" ]]; then
        PE2_RESP=$(cat "$TMPDIR/pe2_resp_${i}.json")

        PP=$(printf '%s' "$PE2_RESP" | jq -r '.partial_point')
        assert_match "production node $i partial_point (post-DKG) is valid compressed point" \
            '^(02|03)[0-9a-f]{64}$' "$PP"
    fi
done

# ---------- 10. Summary ----------

echo ""
echo "========================================"
echo "  DKG Integration Test Results"
echo "========================================"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "========================================"

if [[ $FAIL -gt 0 ]]; then
    echo "  RESULT: FAIL"
    echo ""
    echo "--- DKG CLI output ---"
    cat "$TMPDIR/dkg-cli.log" 2>/dev/null || echo "(no log)"
    echo ""
    for i in 1 2 3; do
        echo "--- DKG node $i log (last 10 lines) ---"
        tail -10 "$TMPDIR/dkg-node-${i}.log" 2>/dev/null || echo "(no log)"
    done
    echo ""
    for i in 1 2 3; do
        echo "--- Production node $i log (last 10 lines) ---"
        tail -10 "$TMPDIR/prod-node-${i}.log" 2>/dev/null || echo "(no log)"
    done
    exit 1
else
    echo "  RESULT: PASS"
    exit 0
fi
