#!/bin/bash
# Generate PQC certificates for TLS testing
# Usage: gen_certs.sh <sig_algorithm> <output_dir>

SIG_ALG="${1:-ML-DSA-65}"
OUT_DIR="${2:-/opt/certs}"

mkdir -p "$OUT_DIR"

echo "Generating certificates with signature algorithm: $SIG_ALG"

# Generate CA key and certificate
openssl req -x509 -new -newkey "$SIG_ALG" \
    -keyout "$OUT_DIR/CA.key" \
    -out "$OUT_DIR/CA.crt" \
    -nodes -subj "/CN=PQC Test CA" -days 365 \
    -provider oqsprovider -provider default 2>/dev/null

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to generate CA certificate with $SIG_ALG"
    echo "Trying with default algorithm..."
    openssl req -x509 -new -newkey rsa:2048 \
        -keyout "$OUT_DIR/CA.key" \
        -out "$OUT_DIR/CA.crt" \
        -nodes -subj "/CN=PQC Test CA" -days 365
fi

# Generate server key
openssl genpkey -algorithm "$SIG_ALG" \
    -out "$OUT_DIR/server.key" \
    -provider oqsprovider -provider default 2>/dev/null

if [ $? -ne 0 ]; then
    echo "Trying server key with default algorithm..."
    openssl genpkey -algorithm rsa:2048 -out "$OUT_DIR/server.key"
fi

# Generate CSR
openssl req -new -key "$OUT_DIR/server.key" \
    -out "$OUT_DIR/server.csr" \
    -subj "/CN=localhost"

# Issue server certificate
openssl x509 -req -in "$OUT_DIR/server.csr" \
    -out "$OUT_DIR/server.crt" \
    -CA "$OUT_DIR/CA.crt" -CAkey "$OUT_DIR/CA.key" \
    -CAcreateserial -days 365

echo "Certificates generated in $OUT_DIR:"
ls -la "$OUT_DIR"
