#!/usr/bin/env bash
#
# Integration test for threshold-OPRF system.
#
# Builds the workspace, starts 3 nodes in genesis mode, runs DKG,
# and tests /health, /partial-evaluate, rate limiting, and /attestation.
#
set -euo pipefail

# Allow test attestation platform in dev/CI
export TOPRF_ALLOW_TEST_ATTESTATION=1

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"

# Binary paths (built in step 1)
NODE="$REPO_ROOT/target/release/toprf-node"
DKG_CLI="$REPO_ROOT/target/release/toprf-dkg-cli"

NODE1_PORT=7101
NODE2_PORT=7102
NODE3_PORT=7103

PIDS=()
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
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
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

# ---------- 1. Build workspace ----------

echo "=== Step 1: Building workspace (release) ==="
cd "$REPO_ROOT"
cargo build --release 2>&1 | tail -5
echo "  Build complete."

for bin in "$NODE" "$DKG_CLI"; do
    if [[ ! -x "$bin" ]]; then
        echo "  FATAL: binary not found: $bin"
        exit 1
    fi
done

# ---------- 2. Start 3 nodes in genesis mode ----------

echo ""
echo "=== Step 2: Starting 3 nodes in genesis mode ==="

mkdir -p "$TMPDIR/node1" "$TMPDIR/node2" "$TMPDIR/node3"

"$NODE" --tcp \
    --genesis "http://127.0.0.1:$NODE2_PORT,http://127.0.0.1:$NODE3_PORT" \
    --node-id 1 --threshold 2 --total 3 \
    --port $NODE1_PORT --data-dir "$TMPDIR/node1" \
    > "$TMPDIR/node1.log" 2>&1 &
PIDS+=($!)
echo "  Node 1 started (PID $!, port $NODE1_PORT)"

"$NODE" --tcp \
    --genesis "http://127.0.0.1:$NODE1_PORT,http://127.0.0.1:$NODE3_PORT" \
    --node-id 2 --threshold 2 --total 3 \
    --port $NODE2_PORT --data-dir "$TMPDIR/node2" \
    > "$TMPDIR/node2.log" 2>&1 &
PIDS+=($!)
echo "  Node 2 started (PID $!, port $NODE2_PORT)"

"$NODE" --tcp \
    --genesis "http://127.0.0.1:$NODE1_PORT,http://127.0.0.1:$NODE2_PORT" \
    --node-id 3 --threshold 2 --total 3 \
    --port $NODE3_PORT --data-dir "$TMPDIR/node3" \
    > "$TMPDIR/node3.log" 2>&1 &
PIDS+=($!)
echo "  Node 3 started (PID $!, port $NODE3_PORT)"

wait_for_health "http://127.0.0.1:$NODE1_PORT/health" "Node 1"
wait_for_health "http://127.0.0.1:$NODE2_PORT/health" "Node 2"
wait_for_health "http://127.0.0.1:$NODE3_PORT/health" "Node 3"

# ---------- 3. Run DKG ----------

echo ""
echo "=== Step 3: Running DKG ceremony ==="

"$DKG_CLI" init --nodes \
    "http://127.0.0.1:$NODE1_PORT,http://127.0.0.1:$NODE2_PORT,http://127.0.0.1:$NODE3_PORT" \
    > "$TMPDIR/dkg.log" 2>&1

GROUP_PUBLIC_KEY=$(grep "Group public key:" "$TMPDIR/dkg.log" | awk '{print $NF}')
echo "  DKG complete. Group public key: $GROUP_PUBLIC_KEY"

# ---------- 4. Test health ----------

echo ""
echo "=== Step 4: Testing /health ==="

for i in 1 2 3; do
    port_var="NODE${i}_PORT"
    port="${!port_var}"
    HEALTH_RESP=$(curl -sf "http://127.0.0.1:$port/health")
    HEALTH_STATUS=$(printf '%s' "$HEALTH_RESP" | jq -r '.status')
    assert_eq "node $i health status is 'ready'" "ready" "$HEALTH_STATUS"

    NODE_ID_FIELD=$(printf '%s' "$HEALTH_RESP" | jq -r '.node_id')
    assert_eq "node $i health node_id is $i" "$i" "$NODE_ID_FIELD"

    HAS_COORD=$(printf '%s' "$HEALTH_RESP" | jq 'has("coordinator")')
    assert_eq "node $i health has no 'coordinator' field" "false" "$HAS_COORD"
done

# ---------- 5. Test /partial-evaluate on each node ----------

echo ""
echo "=== Step 5: Testing /partial-evaluate on each node ==="

BLINDED_POINT_1="0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
CDH_1=$(hex_bytes_sha256 "$BLINDED_POINT_1")
echo "  Blinded point 1: $BLINDED_POINT_1"
echo "  client_data_hash 1: $CDH_1"

for i in 1 2 3; do
    echo ""
    echo "--- Test 5.$i: POST /partial-evaluate on node $i ---"
    port_var="NODE${i}_PORT"
    port="${!port_var}"

    PE_HTTP_CODE=$(curl -s -o "$TMPDIR/pe_resp_${i}.json" -w "%{http_code}" \
        -X POST "http://127.0.0.1:$port/partial-evaluate" \
        -H "Content-Type: application/json" \
        -d "{\"blinded_point\": \"$BLINDED_POINT_1\", \"attestation\": {\"platform\": \"test\", \"client_data_hash\": \"$CDH_1\"}}")

    if [[ "$PE_HTTP_CODE" != "200" ]]; then
        echo "  DEBUG: /partial-evaluate on node $i returned HTTP $PE_HTTP_CODE"
        echo "  DEBUG: response body: $(cat "$TMPDIR/pe_resp_${i}.json" 2>/dev/null)"
        echo "  DEBUG: node $i log (last 20 lines):"
        tail -20 "$TMPDIR/node${i}.log" 2>/dev/null || echo "(no log)"
    fi
    assert_eq "node $i /partial-evaluate returns 200" "200" "$PE_HTTP_CODE"

    if [[ -f "$TMPDIR/pe_resp_${i}.json" && "$PE_HTTP_CODE" == "200" ]]; then
        PE_RESP=$(cat "$TMPDIR/pe_resp_${i}.json")

        PE_NODE_ID=$(printf '%s' "$PE_RESP" | jq -r '.node_id')
        assert_eq "node $i response node_id is $i" "$i" "$PE_NODE_ID"

        PARTIAL_POINT=$(printf '%s' "$PE_RESP" | jq -r '.partial_point')
        assert_match "node $i partial_point is valid compressed point" \
            '^(02|03)[0-9a-f]{64}$' "$PARTIAL_POINT"

        CHALLENGE=$(printf '%s' "$PE_RESP" | jq -r '.dleq_proof.challenge')
        assert_match "node $i dleq_proof.challenge is 64 hex" \
            '^[0-9a-f]{64}$' "$CHALLENGE"

        RESPONSE=$(printf '%s' "$PE_RESP" | jq -r '.dleq_proof.response')
        assert_match "node $i dleq_proof.response is 64 hex" \
            '^[0-9a-f]{64}$' "$RESPONSE"
    else
        echo "  FAIL: no valid response from node $i /partial-evaluate"
        FAIL=$((FAIL + 1))
    fi
done

# ---------- 6. Test rate limiting ----------

echo ""
echo "=== Step 6: Testing rate limiting ==="

echo "  Exhausting rate limit on node 1 (4 more requests, 5 total allowed)..."
for _n in 1 2 3 4; do
    curl -s -o /dev/null \
        -X POST "http://127.0.0.1:$NODE1_PORT/partial-evaluate" \
        -H "Content-Type: application/json" \
        -d "{\"blinded_point\": \"$BLINDED_POINT_1\", \"attestation\": {\"platform\": \"test\", \"client_data_hash\": \"$CDH_1\"}}"
done

echo "  Sending 6th request to node 1 (same device hash) — expecting 429 ..."
RATE_HTTP_CODE=$(curl -s -o "$TMPDIR/rate_resp.json" -w "%{http_code}" \
    -X POST "http://127.0.0.1:$NODE1_PORT/partial-evaluate" \
    -H "Content-Type: application/json" \
    -d "{\"blinded_point\": \"$BLINDED_POINT_1\", \"attestation\": {\"platform\": \"test\", \"client_data_hash\": \"$CDH_1\"}}")

assert_eq "6th same-device request to node 1 returns 429" "429" "$RATE_HTTP_CODE"

# ---------- 7. Test different blinded point ----------

echo ""
echo "=== Step 7: Testing partial evaluations from different nodes ==="

BLINDED_POINT_2="02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
CDH_2=$(hex_bytes_sha256 "$BLINDED_POINT_2")
echo "  Blinded point 2: $BLINDED_POINT_2"
echo "  client_data_hash 2: $CDH_2"

PE2_CODE=$(curl -s -o "$TMPDIR/pe2_resp.json" -w "%{http_code}" \
    -X POST "http://127.0.0.1:$NODE2_PORT/partial-evaluate" \
    -H "Content-Type: application/json" \
    -d "{\"blinded_point\": \"$BLINDED_POINT_2\", \"attestation\": {\"platform\": \"test\", \"client_data_hash\": \"$CDH_2\"}}")
assert_eq "node 2 /partial-evaluate with point 2 returns 200" "200" "$PE2_CODE"

PE3_CODE=$(curl -s -o "$TMPDIR/pe3_resp.json" -w "%{http_code}" \
    -X POST "http://127.0.0.1:$NODE3_PORT/partial-evaluate" \
    -H "Content-Type: application/json" \
    -d "{\"blinded_point\": \"$BLINDED_POINT_2\", \"attestation\": {\"platform\": \"test\", \"client_data_hash\": \"$CDH_2\"}}")
assert_eq "node 3 /partial-evaluate with point 2 returns 200" "200" "$PE3_CODE"

if [[ "$PE2_CODE" == "200" ]]; then
    PP2=$(jq -r '.partial_point' "$TMPDIR/pe2_resp.json")
    assert_match "node 2 partial_point for point 2 is valid compressed point" \
        '^(02|03)[0-9a-f]{64}$' "$PP2"
fi
if [[ "$PE3_CODE" == "200" ]]; then
    PP3=$(jq -r '.partial_point' "$TMPDIR/pe3_resp.json")
    assert_match "node 3 partial_point for point 2 is valid compressed point" \
        '^(02|03)[0-9a-f]{64}$' "$PP3"
fi

# ---------- 8. Test /attestation endpoint ----------

echo ""
echo "=== Step 8: Testing /attestation endpoint ==="

# Attestation endpoint is only available with --features nitro or snp.
# In dev/test builds (no feature flag), the route is not registered -> 404.
TEST_NONCE=$(head -c 32 /dev/urandom | xxd -p -c 64)
ATT_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:$NODE1_PORT/attestation?nonce=$TEST_NONCE")
assert_eq "GET /attestation?nonce=... returns 404 (no TEE feature enabled)" "404" "$ATT_CODE"

# ---------- 9. Summary ----------

echo ""
echo "========================================"
echo "  Integration Test Results"
echo "========================================"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "========================================"

if [[ $FAIL -gt 0 ]]; then
    echo "  RESULT: FAIL"
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
