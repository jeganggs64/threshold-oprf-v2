#!/usr/bin/env bash
#
# End-to-end DKG integration test.
#
# Tests the complete DKG ceremony flow with merged genesis mode:
#   1. Build workspace
#   2. Start 3 production nodes with --genesis flag (they serve both DKG and
#      evaluation endpoints)
#   3. Wait for all 3 to be healthy (status: waiting_for_key)
#   4. Run toprf-dkg-cli init --nodes <3 URLs> (new unified flag)
#   5. Wait for nodes to show "ready" (DKG completed, key sealed)
#   6. Test /partial-evaluate on all 3 nodes
#   7. Verify partial points and DLEQ proofs
#   8. Test with a second blinded point (nodes still work after DKG)
#   9. Print pass/fail summary
#
set -euo pipefail

# Allow test attestation platform in dev/CI
export TOPRF_ALLOW_TEST_ATTESTATION=1

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"

# Binary paths (built in step 1)
DKG_CLI="$REPO_ROOT/target/release/toprf-dkg-cli"
NODE="$REPO_ROOT/target/release/toprf-node"

# Port allocation
PORT1=3001
PORT2=3002
PORT3=3003

PIDS=()
PASS=0
FAIL=0

# ---------- sha256 helper ----------

sha256_hex() {
    if command -v sha256sum > /dev/null 2>&1; then
        sha256sum | cut -d' ' -f1
    else
        shasum -a 256 | cut -d' ' -f1
    fi
}

hex_bytes_sha256() {
    printf '%s' "$1" | xxd -r -p | sha256_hex
}

# ---------- cleanup ----------

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for pid in "${PIDS[@]+"${PIDS[@]}"}"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    # Clean up node-key.json files written to data dirs
    rm -f "$TMPDIR/node1/node-key.json"
    rm -f "$TMPDIR/node2/node-key.json"
    rm -f "$TMPDIR/node3/node-key.json"
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
for p in $PORT1 $PORT2 $PORT3; do
    if lsof -i ":$p" > /dev/null 2>&1; then
        echo "  FATAL: port $p is already in use. Kill the process and retry."
        lsof -i ":$p" 2>/dev/null
        exit 1
    fi
done
echo "  All ports are free."

# ---------- 1. Build workspace ----------

echo ""
echo "=== Step 1: Building workspace (release) ==="
cd "$REPO_ROOT"
cargo build --release 2>&1 | tail -5
echo "  Build complete."

# Verify binaries exist
for bin in "$DKG_CLI" "$NODE"; do
    if [[ ! -x "$bin" ]]; then
        echo "  FATAL: binary not found: $bin"
        exit 1
    fi
done
echo "  All binaries found."

# ---------- 2. Start 3 production nodes with --genesis ----------

echo ""
echo "=== Step 2: Starting 3 production nodes with --genesis ==="

# Create per-node data directories
mkdir -p "$TMPDIR/node1" "$TMPDIR/node2" "$TMPDIR/node3"

# Node 1: peers are node 2 and node 3
"$NODE" \
    --genesis "http://127.0.0.1:$PORT2,http://127.0.0.1:$PORT3" \
    --node-id 1 --threshold 2 --total 3 \
    --port "$PORT1" --data-dir "$TMPDIR/node1" \
    > "$TMPDIR/node1.log" 2>&1 &
PIDS+=($!)
echo "  Node 1 started (PID $!, port $PORT1)"

# Node 2: peers are node 1 and node 3
"$NODE" \
    --genesis "http://127.0.0.1:$PORT1,http://127.0.0.1:$PORT3" \
    --node-id 2 --threshold 2 --total 3 \
    --port "$PORT2" --data-dir "$TMPDIR/node2" \
    > "$TMPDIR/node2.log" 2>&1 &
PIDS+=($!)
echo "  Node 2 started (PID $!, port $PORT2)"

# Node 3: peers are node 1 and node 2
"$NODE" \
    --genesis "http://127.0.0.1:$PORT1,http://127.0.0.1:$PORT2" \
    --node-id 3 --threshold 2 --total 3 \
    --port "$PORT3" --data-dir "$TMPDIR/node3" \
    > "$TMPDIR/node3.log" 2>&1 &
PIDS+=($!)
echo "  Node 3 started (PID $!, port $PORT3)"

# ---------- 3. Wait for all 3 nodes to be healthy ----------

echo ""
echo "=== Step 3: Waiting for all 3 nodes to be healthy ==="

wait_for_health "http://127.0.0.1:$PORT1/health" "Node 1"
wait_for_health "http://127.0.0.1:$PORT2/health" "Node 2"
wait_for_health "http://127.0.0.1:$PORT3/health" "Node 3"

# Verify nodes are in waiting_for_key state
echo ""
echo "--- Verifying nodes are in waiting_for_key state ---"
for i in 1 2 3; do
    port_var="PORT${i}"
    port="${!port_var}"
    HEALTH_RESP=$(curl -sf "http://127.0.0.1:$port/health")
    HEALTH_STATUS=$(printf '%s' "$HEALTH_RESP" | jq -r '.status')
    assert_eq "node $i starts with status 'waiting_for_key'" "waiting_for_key" "$HEALTH_STATUS"
done

# ---------- 4. Run DKG CLI init ----------

echo ""
echo "=== Step 4: Running toprf-dkg-cli init ==="

NODE_URLS="http://127.0.0.1:$PORT1,http://127.0.0.1:$PORT2,http://127.0.0.1:$PORT3"

"$DKG_CLI" init \
    --nodes "$NODE_URLS" \
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

# ---------- 5. Wait for nodes to show "ready" ----------

echo ""
echo "=== Step 5: Waiting for nodes to be ready (key sealed) ==="

wait_for_ready "http://127.0.0.1:$PORT1/health" "Node 1"
wait_for_ready "http://127.0.0.1:$PORT2/health" "Node 2"
wait_for_ready "http://127.0.0.1:$PORT3/health" "Node 3"

# Verify health status
echo ""
echo "--- Verifying nodes are now ready ---"
for i in 1 2 3; do
    port_var="PORT${i}"
    port="${!port_var}"
    HEALTH_RESP=$(curl -sf "http://127.0.0.1:$port/health")
    HEALTH_STATUS=$(printf '%s' "$HEALTH_RESP" | jq -r '.status')
    assert_eq "node $i health status is 'ready'" "ready" "$HEALTH_STATUS"

    NODE_ID_FIELD=$(printf '%s' "$HEALTH_RESP" | jq -r '.node_id')
    assert_eq "node $i health node_id is $i" "$i" "$NODE_ID_FIELD"
done

# ---------- 6. Test /partial-evaluate on all 3 nodes ----------

echo ""
echo "=== Step 6: Testing /partial-evaluate on each node ==="

# secp256k1 generator point (compressed)
BLINDED_POINT="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
CDH=$(hex_bytes_sha256 "$BLINDED_POINT")
echo "  Blinded point: $BLINDED_POINT"
echo "  client_data_hash: $CDH"

for i in 1 2 3; do
    echo ""
    echo "--- Test 6.$i: POST /partial-evaluate on node $i ---"
    port_var="PORT${i}"
    port="${!port_var}"

    PE_HTTP_CODE=$(curl -s -o "$TMPDIR/pe_resp_${i}.json" -w "%{http_code}" \
        -X POST "http://127.0.0.1:$port/partial-evaluate" \
        -H "Content-Type: application/json" \
        -d "{\"blinded_point\": \"$BLINDED_POINT\", \"attestation\": {\"platform\": \"test\", \"client_data_hash\": \"$CDH\"}}")

    if [[ "$PE_HTTP_CODE" != "200" ]]; then
        echo "  DEBUG: /partial-evaluate on node $i returned HTTP $PE_HTTP_CODE"
        echo "  DEBUG: response body: $(cat "$TMPDIR/pe_resp_${i}.json" 2>/dev/null)"
        echo "  DEBUG: node $i log (last 20 lines):"
        tail -20 "$TMPDIR/node${i}.log" 2>/dev/null || echo "(no log)"
    fi
    assert_eq "node $i /partial-evaluate returns 200" "200" "$PE_HTTP_CODE"

    if [[ -f "$TMPDIR/pe_resp_${i}.json" && "$PE_HTTP_CODE" == "200" ]]; then
        PE_RESP=$(cat "$TMPDIR/pe_resp_${i}.json")

        # node_id
        PE_NODE_ID=$(printf '%s' "$PE_RESP" | jq -r '.node_id')
        assert_eq "node $i response node_id is $i" "$i" "$PE_NODE_ID"

        # partial_point: valid compressed secp256k1 point (02 or 03 prefix + 64 hex chars)
        PARTIAL_POINT=$(printf '%s' "$PE_RESP" | jq -r '.partial_point')
        assert_match "node $i partial_point is valid compressed point" \
            '^(02|03)[0-9a-f]{64}$' "$PARTIAL_POINT"

        # dleq_proof.challenge: 64 hex chars
        CHALLENGE=$(printf '%s' "$PE_RESP" | jq -r '.dleq_proof.challenge')
        assert_match "node $i dleq_proof.challenge is 64 hex" \
            '^[0-9a-f]{64}$' "$CHALLENGE"

        # dleq_proof.response: 64 hex chars
        RESPONSE=$(printf '%s' "$PE_RESP" | jq -r '.dleq_proof.response')
        assert_match "node $i dleq_proof.response is 64 hex" \
            '^[0-9a-f]{64}$' "$RESPONSE"
    else
        echo "  FAIL: no valid response from node $i /partial-evaluate"
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

# ---------- 8. Test with a second blinded point ----------

echo ""
echo "=== Step 8: Testing nodes still work with a second blinded point ==="

# Use a different blinded point to avoid rate limit issues
BLINDED_POINT_2="02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
CDH_2=$(hex_bytes_sha256 "$BLINDED_POINT_2")
echo "  Blinded point 2: $BLINDED_POINT_2"
echo "  client_data_hash 2: $CDH_2"

for i in 1 2 3; do
    echo ""
    echo "--- Test 8.$i: POST /partial-evaluate on node $i (second blinded point) ---"
    port_var="PORT${i}"
    port="${!port_var}"

    PE2_HTTP_CODE=$(curl -s -o "$TMPDIR/pe2_resp_${i}.json" -w "%{http_code}" \
        -X POST "http://127.0.0.1:$port/partial-evaluate" \
        -H "Content-Type: application/json" \
        -d "{\"blinded_point\": \"$BLINDED_POINT_2\", \"attestation\": {\"platform\": \"test\", \"client_data_hash\": \"$CDH_2\"}}")

    assert_eq "node $i still works with second blinded point (HTTP 200)" "200" "$PE2_HTTP_CODE"

    if [[ "$PE2_HTTP_CODE" == "200" ]]; then
        PE2_RESP=$(cat "$TMPDIR/pe2_resp_${i}.json")

        PP=$(printf '%s' "$PE2_RESP" | jq -r '.partial_point')
        assert_match "node $i partial_point (second point) is valid compressed point" \
            '^(02|03)[0-9a-f]{64}$' "$PP"
    fi
done

# ---------- 9. Summary ----------

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
        echo "--- Node $i log (last 10 lines) ---"
        tail -10 "$TMPDIR/node${i}.log" 2>/dev/null || echo "(no log)"
    done
    exit 1
else
    echo "  RESULT: PASS"
    exit 0
fi
