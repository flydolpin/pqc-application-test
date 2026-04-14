#!/bin/bash
# PQC Full Benchmark Matrix: KEM x SIG combinations
# Usage: pqc_full_bench.sh [--iterations <N>] [--outdir <path>]
#
# Tests all combinations of KEM and signature algorithms:
#   KEM:  mlkem512, mlkem768, mlkem1024
#   SIG:  rsa2048, mldsa44, mldsa65, mldsa87
#
# Example:
#   pqc_full_bench.sh --iterations 10 --outdir /tmp/results

ITERATIONS=5
OUTDIR="/tmp/pqc_results"
PORT=4433

while [[ $# -gt 0 ]]; do
    case $1 in
        --iterations) ITERATIONS="$2"; shift 2 ;;
        --outdir) OUTDIR="$2"; shift 2 ;;
        *) shift ;;
    esac
done

mkdir -p "$OUTDIR"

# KEM algorithms to test
KEMS=("mlkem512" "mlkem768" "mlkem1024")
# Limit ML-KEM-1024 iterations due to oqs-provider memory issue
KEM_ITERS=("20" "20" "5")

# Signature algorithms for certificate generation
SIGS=("rsa2048" "mldsa44" "mldsa65" "mldsa87")

CSV_FILE="$OUTDIR/full_matrix_results.csv"
echo "kem_alg,sig_alg,iterations,success_rate,mean_ns,stdev_ns,median_ns,min_ns,max_ns,avg_bytes_sent,avg_bytes_received" > "$CSV_FILE"

echo "============================================"
echo "  PQC TLS Full Benchmark Matrix"
echo "  KEMs: ${KEMS[*]}"
echo "  SIGs: ${SIGS[*]}"
echo "  Iterations: $ITERATIONS (max per KEM)"
echo "  Output: $CSV_FILE"
echo "============================================"
echo ""

total=0
pass=0
fail=0

for sig_idx in "${!SIGS[@]}"; do
    SIG="${SIGS[$sig_idx]}"
    echo "=== Generating ${SIG} certificates ==="

    CERT_DIR="$OUTDIR/certs_${SIG}"
    /opt/pqc/scripts/gen_certs.sh --sig-alg "$SIG" --out-dir "$CERT_DIR" 2>&1 | tail -3
    if [[ $? -ne 0 ]]; then
        echo "ERROR: Failed to generate ${SIG} certificates, skipping..."
        continue
    fi
    echo ""

    for kem_idx in "${!KEMS[@]}"; do
        KEM="${KEMS[$kem_idx]}"
        ITERS="${KEM_ITERS[$kem_idx]}"
        [[ $ITERATIONS -lt $ITERS ]] && ITERS=$ITERATIONS

        total=$((total + 1))
        echo "--- KEM=$KEM  SIG=$SIG  Iterations=$ITERS ---"

        # Start server
        pqc_tls_server --port $PORT \
            --cert "$CERT_DIR/server.crt" \
            --key "$CERT_DIR/server.key" \
            --max-conn $((ITERS + 5)) &>/tmp/pqc_server.log &
        SERVER_PID=$!
        sleep 0.5

        # Run benchmark
        RESULT=$(pqc_bench_tls \
            --kem "$KEM" \
            --host 127.0.0.1 \
            --port $PORT \
            --iterations "$ITERS" \
            --no-verify \
            --format csv 2>&1)

        # Extract data line (skip header)
        DATA=$(echo "$RESULT" | tail -1)

        if echo "$DATA" | grep -q ",1.0000,"; then
            echo "  PASS: $DATA"
            echo "${KEM},${SIG},${DATA}" >> "$CSV_FILE"
            pass=$((pass + 1))
        else
            echo "  FAIL: $DATA"
            fail=$((fail + 1))
        fi

        # Stop server
        kill $SERVER_PID 2>/dev/null
        wait $SERVER_PID 2>/dev/null
        sleep 0.3
    done
    echo ""
done

echo "============================================"
echo "  Results Summary"
echo "============================================"
echo "Total: $total  Pass: $pass  Fail: $fail"
echo ""
echo "CSV output: $CSV_FILE"
column -t -s',' "$CSV_FILE" 2>/dev/null || cat "$CSV_FILE"
