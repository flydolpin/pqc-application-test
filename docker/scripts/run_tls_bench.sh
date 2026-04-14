#!/bin/bash
# Run full TLS benchmark suite
# Usage: run_tls_bench.sh [config_file]

CONFIG="${1:-/opt/pqc/configs/benchmark_tls.toml}"
CERT_DIR="/opt/certs"

# Generate certificates if not present
if [ ! -f "$CERT_DIR/server.crt" ]; then
    echo "Generating PQC certificates..."
    /opt/scripts/gen_certs.sh ML-DSA-65 "$CERT_DIR"
fi

echo "=== Running TLS Benchmark ==="
echo "Config: $CONFIG"

pqc_bench_tls --config "$CONFIG" --ca-cert "$CERT_DIR/CA.crt"
