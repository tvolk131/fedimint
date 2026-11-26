#!/usr/bin/env bash
set -euo pipefail

# Local 4-guardian Fedimint + LDK gateway PoC on Mutinynet for federated BOLT12.
#
# Usage:
#   ./scripts/dev/mutinynet-bolt12.sh start
#   ./scripts/dev/mutinynet-bolt12.sh status
#   ./scripts/dev/mutinynet-bolt12.sh stop
#   ./scripts/dev/mutinynet-bolt12.sh clean

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DATA_DIR="${FM_BOLT12_MUTINYNET_DIR:-/tmp/fm-bolt12-mutinynet}"
ESPLORA_URL="${FM_ESPLORA_URL:-https://mutinynet.com/api}"
POOL_TARGET="${FM_BOLT12_POOL_TARGET:-8}"
POOL_BATCH="${FM_BOLT12_POOL_BATCH:-4}"
GUARDIAN_PASSWORD="${FM_BOLT12_GUARDIAN_PASSWORD:-guardianpass}"
GATEWAY_PASSWORD="theresnosecondbest"
GATEWAY_PASSWORD_HASH='$2y$10$Q/UTDeO84VGG1mRncxw.Nubqyi/HsNRJ40k0TSexFy9eVess1yi/u'

GATEWAY_PORT=18275
GATEWAY_METRICS_PORT=18276
GATEWAY_LDK_PORT=19735
GATEWAY_URL="http://127.0.0.1:${GATEWAY_PORT}"

detect_bin_dir() {
    if [[ -n "${FM_BOLT12_BIN_DIR:-}" ]]; then
        echo "$FM_BOLT12_BIN_DIR"
        return
    fi
    if [[ -x "$REPO_ROOT/target/release/fedimintd" ]]; then
        echo "$REPO_ROOT/target/release"
    else
        echo "$REPO_ROOT/target/debug"
    fi
}

BIN_DIR="$(detect_bin_dir)"
FEDIMINTD="$BIN_DIR/fedimintd"
FEDIMINT_CLI="$BIN_DIR/fedimint-cli"
GATEWAYD="$BIN_DIR/gatewayd"
GATEWAY_CLI="$BIN_DIR/gateway-cli"

require_tools() {
    for bin in "$FEDIMINTD" "$FEDIMINT_CLI" "$GATEWAYD" "$GATEWAY_CLI"; do
        if [[ ! -x "$bin" ]]; then
            echo "Missing binary: $bin" >&2
            echo "Build first with:" >&2
            echo "  cargo build --bin fedimintd --bin fedimint-cli --bin gatewayd --bin gateway-cli" >&2
            exit 1
        fi
    done
    for tool in curl python3; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "Missing required tool: $tool" >&2
            exit 1
        fi
    done
}

pid_alive() {
    local pidfile="$1"
    [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null
}

wait_for_cmd() {
    local desc="$1"
    local timeout_secs="$2"
    shift 2
    local deadline=$((SECONDS + timeout_secs))
    while (( SECONDS < deadline )); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "Timed out waiting for: $desc" >&2
    return 1
}

start_guardian() {
    local i="$1"
    local p2p_port=$((18173 + i * 10))
    local api_port=$((18174 + i * 10))
    local ui_port=$((18175 + i * 10))
    local metrics_port=$((18176 + i * 10))
    local gdir="$DATA_DIR/guardian-$i"
    local pidfile="$DATA_DIR/pids/guardian-$i.pid"

    mkdir -p "$gdir" "$DATA_DIR/logs" "$DATA_DIR/pids"
    if pid_alive "$pidfile"; then
        echo "Guardian $i already running (pid $(cat "$pidfile"))"
        return
    fi

    FM_ENABLE_FEDERATED_BOLT12=1 \
    FM_BOLT12_POOL_TARGET="$POOL_TARGET" \
    FM_BOLT12_POOL_BATCH="$POOL_BATCH" \
    RUST_LOG="${RUST_LOG:-info,fedimint_lnv2_server=info}" \
        "$FEDIMINTD" \
        --data-dir "$gdir" \
        --bitcoin-network signet \
        --esplora-url "$ESPLORA_URL" \
        --enable-iroh false \
        --bind-p2p "127.0.0.1:${p2p_port}" \
        --p2p-url "fedimint://127.0.0.1:${p2p_port}" \
        --bind-api "127.0.0.1:${api_port}" \
        --api-url "ws://127.0.0.1:${api_port}" \
        --bind-ui "127.0.0.1:${ui_port}" \
        --bind-metrics "127.0.0.1:${metrics_port}" \
        --password-api "$GUARDIAN_PASSWORD" \
        >"$DATA_DIR/logs/guardian-$i.log" 2>&1 &
    echo $! >"$pidfile"
    echo "Started guardian $i (pid $!, api ws://127.0.0.1:${api_port}, metrics http://127.0.0.1:${metrics_port}/metrics)"
}

run_dkg_if_needed() {
    if [[ -s "$DATA_DIR/guardian-0/invite-code" ]]; then
        echo "Federation already initialized (invite-code present)"
        return
    fi

    echo "Waiting for guardians to accept setup RPCs..."
    for i in 0 1 2 3; do
        local api_port=$((18174 + i * 10))
        wait_for_cmd "guardian $i setup endpoint" 60 \
            "$FEDIMINT_CLI" --password "$GUARDIAN_PASSWORD" admin setup "ws://127.0.0.1:${api_port}" status
    done

    declare -a CODES
    echo "Setting local parameters..."
    CODES[0]="$("$FEDIMINT_CLI" --password "$GUARDIAN_PASSWORD" admin setup "ws://127.0.0.1:18174" \
        set-local-params "Guardian 0" --federation-name "Mutinynet BOLT12 PoC" --federation-size 4 \
        | python3 -c 'import json, sys; print(json.load(sys.stdin))')"

    for i in 1 2 3; do
        local api_port=$((18174 + i * 10))
        CODES[$i]="$("$FEDIMINT_CLI" --password "$GUARDIAN_PASSWORD" admin setup "ws://127.0.0.1:${api_port}" \
            set-local-params "Guardian $i" \
            | python3 -c 'import json, sys; print(json.load(sys.stdin))')"
    done

    echo "Exchanging peer setup codes..."
    for i in 0 1 2 3; do
        local api_port=$((18174 + i * 10))
        for j in 0 1 2 3; do
            if [[ "$i" != "$j" ]]; then
                "$FEDIMINT_CLI" --password "$GUARDIAN_PASSWORD" admin setup "ws://127.0.0.1:${api_port}" \
                    add-peer "${CODES[$j]}" >/dev/null
            fi
        done
    done

    echo "Running DKG across 4 guardians..."
    local dkg_pids=()
    for i in 0 1 2 3; do
        local api_port=$((18174 + i * 10))
        "$FEDIMINT_CLI" --password "$GUARDIAN_PASSWORD" admin setup "ws://127.0.0.1:${api_port}" start-dkg >/dev/null &
        dkg_pids+=($!)
    done
    for p in "${dkg_pids[@]}"; do
        wait "$p"
    done

    echo "Waiting for invite-code after DKG..."
    wait_for_cmd "guardian-0 invite-code" 90 test -s "$DATA_DIR/guardian-0/invite-code"
    echo "DKG complete."
}

start_gateway() {
    local gwdir="$DATA_DIR/gateway"
    local pidfile="$DATA_DIR/pids/gateway.pid"
    mkdir -p "$gwdir" "$DATA_DIR/logs" "$DATA_DIR/pids"

    if pid_alive "$pidfile"; then
        echo "Gateway already running (pid $(cat "$pidfile"))"
        return
    fi

    RUST_LOG="${RUST_LOG:-info,fedimint_gateway_server=info,fedimint_gwv2_client=info}" \
        "$GATEWAYD" \
        --data-dir "$gwdir" \
        --listen "127.0.0.1:${GATEWAY_PORT}" \
        --api-addr "$GATEWAY_URL" \
        --metrics-listen "127.0.0.1:${GATEWAY_METRICS_PORT}" \
        --network signet \
        --esplora-url "$ESPLORA_URL" \
        --bcrypt-password-hash "$GATEWAY_PASSWORD_HASH" \
        --skip-setup \
        ldk \
        --ldk-lightning-port "$GATEWAY_LDK_PORT" \
        --ldk-alias "fm-bolt12-poc" \
        >"$DATA_DIR/logs/gateway.log" 2>&1 &
    echo $! >"$pidfile"
    echo "Started LDK gateway (pid $!, api $GATEWAY_URL, metrics http://127.0.0.1:${GATEWAY_METRICS_PORT}/metrics)"

    wait_for_cmd "gatewayd Running state (LDK synced)" 120 bash -c \
        "\"$GATEWAY_CLI\" -a \"$GATEWAY_URL\" --rpcpassword \"$GATEWAY_PASSWORD\" info 2>/dev/null | grep -q '\"gateway_state\": \"Running\"'"
}

bootstrap_client_and_gateway() {
    local invite_code
    invite_code="$(tr -d '\n\r ' <"$DATA_DIR/guardian-0/invite-code")"
    local client_dir="$DATA_DIR/client"
    mkdir -p "$client_dir"

    if [[ ! -d "$client_dir/client.db" ]]; then
        echo "Joining local fedimint-cli wallet..."
        "$FEDIMINT_CLI" --data-dir "$client_dir" join "$invite_code" >/dev/null
    fi

    local fed_id
    fed_id="$("$FEDIMINT_CLI" --data-dir "$client_dir" dev decode invite-code "$invite_code" \
        | python3 -c 'import json, sys; print(json.load(sys.stdin)["federation_id"])')"
    local connected
    connected="$("$GATEWAY_CLI" -a "$GATEWAY_URL" --rpcpassword "$GATEWAY_PASSWORD" info \
        | python3 -c "import json, sys; feds = json.load(sys.stdin).get('federations', []); print(1 if any(f.get('federation_id') == '$fed_id' for f in feds) else 0)")"
    if [[ "$connected" == "0" ]]; then
        echo "Connecting LDK gateway to federation ($fed_id)..."
        "$GATEWAY_CLI" -a "$GATEWAY_URL" --rpcpassword "$GATEWAY_PASSWORD" connect-fed "$invite_code" >/dev/null
    fi

    echo "Waiting for gateway BOLT12 ingress..."
    local gateway_key=""
    local deadline=$((SECONDS + 60))
    while (( SECONDS < deadline )); do
        gateway_key="$("$FEDIMINT_CLI" --data-dir "$client_dir" module lnv2 bolt12 gateways \
            --gateway "$GATEWAY_URL" --include-unapproved 2>/dev/null \
            | python3 -c 'import json, sys; d = json.load(sys.stdin); print(d[0]["gateway_key"] if d else "")' 2>/dev/null || true)"
        if [[ -n "$gateway_key" ]]; then
            break
        fi
        sleep 2
    done
    if [[ -z "$gateway_key" ]]; then
        echo "Failed to fetch gateway BOLT12 ingress from $GATEWAY_URL" >&2
        exit 1
    fi

    echo "Vetting and quorum-approving gateway ($gateway_key) across all 4 guardians..."
    for i in 0 1 2 3; do
        "$FEDIMINT_CLI" --data-dir "$client_dir" --our-id "$i" --password "$GUARDIAN_PASSWORD" \
            module lnv2 gateways add "$GATEWAY_URL" >/dev/null 2>&1 || true
        "$FEDIMINT_CLI" --data-dir "$client_dir" --our-id "$i" --password "$GUARDIAN_PASSWORD" \
            module lnv2 bolt12 approve-gateway "$gateway_key" >/dev/null 2>&1 || true
    done

    echo "Waiting for BOLT12 gateway approval quorum..."
    wait_for_cmd "BOLT12 gateway quorum approval" 60 bash -c \
        "\"$FEDIMINT_CLI\" --data-dir \"$client_dir\" module lnv2 bolt12 gateway-approved \"$gateway_key\" | grep -q '\"approved\": true'"

    echo "Waiting for MPC preimage pool to populate (target=$POOL_TARGET, batch=$POOL_BATCH)..."
    local pool_deadline=$((SECONDS + 120))
    local pool_avail=0
    while (( SECONDS < pool_deadline )); do
        pool_avail="$("$FEDIMINT_CLI" --data-dir "$client_dir" module lnv2 bolt12 status 2>/dev/null \
            | python3 -c 'import json, sys; print(json.load(sys.stdin).get("pool_available", 0))' 2>/dev/null || echo 0)"
        if (( pool_avail > 0 )); then
            echo "MPC pool populated: ${pool_avail}/${POOL_TARGET} preimages ready!"
            break
        fi
        sleep 3
    done
}

cmd_start() {
    require_tools
    mkdir -p "$DATA_DIR/logs" "$DATA_DIR/pids"
    for i in 0 1 2 3; do
        start_guardian "$i"
    done
    run_dkg_if_needed
    start_gateway
    bootstrap_client_and_gateway
    echo ""
    cmd_status
    print_next_steps
}

cmd_status() {
    local client_dir="$DATA_DIR/client"
    echo "=== Processes ($DATA_DIR) ==="
    for name in guardian-0 guardian-1 guardian-2 guardian-3 gateway; do
        local pf="$DATA_DIR/pids/${name}.pid"
        if pid_alive "$pf"; then
            echo "  $name: RUNNING (pid $(cat "$pf"))"
        else
            echo "  $name: STOPPED"
        fi
    done

    if [[ -d "$client_dir/client.db" ]]; then
        echo ""
        echo "=== BOLT12 Federation Status ==="
        "$FEDIMINT_CLI" --data-dir "$client_dir" module lnv2 bolt12 status || true
        echo ""
        echo "=== Approved BOLT12 Gateways ==="
        "$FEDIMINT_CLI" --data-dir "$client_dir" module lnv2 bolt12 gateways || true
    fi

    if pid_alive "$DATA_DIR/pids/gateway.pid"; then
        echo ""
        echo "=== Gateway LDK Info & Balances ==="
        "$GATEWAY_CLI" -a "$GATEWAY_URL" --rpcpassword "$GATEWAY_PASSWORD" info \
            | python3 -c 'import json, sys; d = json.load(sys.stdin); print(json.dumps({"gateway_state": d.get("gateway_state"), "lightning_info": d.get("lightning_info")}, indent=2))' || true
        "$GATEWAY_CLI" -a "$GATEWAY_URL" --rpcpassword "$GATEWAY_PASSWORD" onchain address || true
        "$GATEWAY_CLI" -a "$GATEWAY_URL" --rpcpassword "$GATEWAY_PASSWORD" get-balances || true
    fi

    echo ""
    echo "=== Guardian 0 BOLT12 Metrics (http://127.0.0.1:18176/metrics) ==="
    curl -fsS "http://127.0.0.1:18176/metrics" 2>/dev/null | grep -E "^fm_lnv2_bolt12_" || echo "  (unavailable)"

    echo ""
    echo "=== Gateway BOLT12 Metrics (http://127.0.0.1:${GATEWAY_METRICS_PORT}/metrics) ==="
    curl -fsS "http://127.0.0.1:${GATEWAY_METRICS_PORT}/metrics" 2>/dev/null | grep -E "^fm_gateway_bolt12_" || echo "  (unavailable)"
}

print_next_steps() {
    local client_dir="$DATA_DIR/client"
    cat <<EOF

=== Next Steps for Live External Mutinynet Payment ===
1. Fund the gateway's LDK on-chain address above via https://faucet.mutinynet.com
2. Open a Mutinynet channel with inbound liquidity (or connect to a Mutinynet peer):
     $GATEWAY_CLI -a $GATEWAY_URL --rpcpassword $GATEWAY_PASSWORD lightning open-channel \\
       --pubkey <PEER_PUBKEY> --host <PEER_HOST:PORT> --channel-size-sats 100000 --push-amount-sats 50000
3. Peg in a few hundred sats to the local wallet to pay the 100-sat offer registration + stock fees:
     $FEDIMINT_CLI --data-dir $client_dir module wallet deposit-address
4. Create a reusable federated BOLT12 offer (with MPC pool fallback):
     $FEDIMINT_CLI --data-dir $client_dir module lnv2 bolt12 create-offer \\
       --description "Fedimint BOLT12 Mutinynet PoC" --stock 4 --allow-pool
5. Pay the returned lno1... offer from an external Mutinynet BOLT12 wallet (e.g. Core Lightning)
   while fedimint-cli is offline, then run:
     $FEDIMINT_CLI --data-dir $client_dir dev wait 5
     $FEDIMINT_CLI --data-dir $client_dir info
EOF
}

cmd_stop() {
    for name in gateway guardian-0 guardian-1 guardian-2 guardian-3; do
        local pf="$DATA_DIR/pids/${name}.pid"
        if pid_alive "$pf"; then
            local pid
            pid="$(cat "$pf")"
            echo "Stopping $name (pid $pid)..."
            kill "$pid" 2>/dev/null || true
        fi
        rm -f "$pf"
    done
    sleep 1
    echo "Stopped."
}

cmd_clean() {
    cmd_stop
    rm -rf "$DATA_DIR"
    echo "Removed $DATA_DIR"
}

case "${1:-}" in
    start) cmd_start ;;
    status) cmd_status ;;
    stop) cmd_stop ;;
    clean) cmd_clean ;;
    *)
        echo "Usage: $0 {start|status|stop|clean}" >&2
        exit 1
        ;;
esac
