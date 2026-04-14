#!/bin/bash
# Generate certificates for PQC TLS testing
# Usage: gen_certs.sh [--sig-alg <algorithm>] [--out-dir <path>]
#
# Examples:
#   gen_certs.sh                                    # RSA 2048 (default)
#   gen_certs.sh --sig-alg mldsa65                  # ML-DSA-65 PQC cert
#   gen_certs.sh --sig-alg mldsa44 --out-dir /tmp/certs

SIG_ALG="RSA"
USE_OQS=""
OUT_DIR="/opt/certs"

while [[ $# -gt 0 ]]; do
    case $1 in
        --sig-alg)
            SIG_ALG="$2"
            shift 2
            ;;
        --out-dir)
            OUT_DIR="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

mkdir -p "$OUT_DIR"

# Check if PQC algorithm (not RSA)
case "$SIG_ALG" in
    RSA|rsa|rsa:*) ;;
    *)
        USE_OQS="-provider oqsprovider -provider default"
        ;;
esac

echo "=== Certificate Generation ==="
echo "Signature algorithm: $SIG_ALG"
echo "Output directory: $OUT_DIR"
echo "OQS providers: ${USE_OQS:-none (classic)}"
echo ""

# Map algorithm names to OpenSSL identifiers
case "$SIG_ALG" in
    RSA|rsa)       SIG_KEY="RSA"; SIG_BITS="2048"; SIG_NAME="rsaEncryption" ;;
    rsa:2048)      SIG_KEY="RSA"; SIG_BITS="2048"; SIG_NAME="rsaEncryption" ;;
    rsa:4096)      SIG_KEY="RSA"; SIG_BITS="4096"; SIG_NAME="rsaEncryption" ;;
    mldsa44)       SIG_KEY="mldsa44";     SIG_BITS=""; SIG_NAME="mldsa44" ;;
    mldsa65)       SIG_KEY="mldsa65";     SIG_BITS=""; SIG_NAME="mldsa65" ;;
    mldsa87)       SIG_KEY="mldsa87";     SIG_BITS=""; SIG_NAME="mldsa87" ;;
    dilithium2)    SIG_KEY="Dilithium2";  SIG_BITS=""; SIG_NAME="dilithium2" ;;
    dilithium3)    SIG_KEY="Dilithium3";  SIG_BITS=""; SIG_NAME="dilithium3" ;;
    dilithium5)    SIG_KEY="Dilithium5";  SIG_BITS=""; SIG_NAME="dilithium5" ;;
    falcon512)     SIG_KEY="Falcon-512";  SIG_BITS=""; SIG_NAME="falcon512" ;;
    falcon1024)    SIG_KEY="Falcon-1024"; SIG_BITS=""; SIG_NAME="falcon1024" ;;
    sphincssha2128f) SIG_KEY="SPHINCS+-SHA2-128f-simple"; SIG_BITS=""; SIG_NAME="sphincssha2128f" ;;
    *)
        echo "Warning: Unknown algorithm '$SIG_ALG', attempting as-is"
        SIG_KEY="$SIG_ALG"; SIG_BITS=""; SIG_NAME="$SIG_ALG"
        ;;
esac

echo "--- Generating CA key and certificate ---"
if [[ "$SIG_KEY" == "RSA" ]]; then
    openssl genpkey -algorithm RSA \
        -pkeyopt rsa_keygen_bits:"$SIG_BITS" \
        -out "$OUT_DIR/ca.key" 2>&1 | head -1
else
    openssl genpkey -algorithm "$SIG_KEY" \
        -provider oqsprovider -provider default \
        -out "$OUT_DIR/ca.key" 2>&1 | head -1
fi

if [[ $? -ne 0 ]]; then
    echo "ERROR: Failed to generate CA key"
    exit 1
fi

openssl req -new -x509 -key "$OUT_DIR/ca.key" \
    -out "$OUT_DIR/ca.crt" \
    -days 365 \
    -subj "/CN=PQC Test CA/O=PQC Benchmark" \
    $USE_OQS 2>&1 | head -1

if [[ $? -ne 0 ]]; then
    echo "ERROR: Failed to generate CA certificate"
    exit 1
fi

echo "CA certificate generated."
echo ""

echo "--- Generating server key and CSR ---"
if [[ "$SIG_KEY" == "RSA" ]]; then
    openssl genpkey -algorithm RSA \
        -pkeyopt rsa_keygen_bits:"$SIG_BITS" \
        -out "$OUT_DIR/server.key" 2>&1 | head -1
else
    openssl genpkey -algorithm "$SIG_KEY" \
        -provider oqsprovider -provider default \
        -out "$OUT_DIR/server.key" 2>&1 | head -1
fi

if [[ $? -ne 0 ]]; then
    echo "ERROR: Failed to generate server key"
    exit 1
fi

# Create SAN extension config
cat > "$OUT_DIR/san.cnf" <<EOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment, keyAgreement
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, DNS:pqc-server, DNS:pqc-bench, IP:127.0.0.1
EOF

openssl req -new -key "$OUT_DIR/server.key" \
    -out "$OUT_DIR/server.csr" \
    -subj "/CN=pqc-server/O=PQC Benchmark" \
    $USE_OQS 2>&1 | head -1

if [[ $? -ne 0 ]]; then
    echo "ERROR: Failed to generate server CSR"
    exit 1
fi

echo "--- Signing server certificate with CA ---"
openssl x509 -req -in "$OUT_DIR/server.csr" \
    -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" \
    -CAcreateserial \
    -days 365 \
    -extfile "$OUT_DIR/san.cnf" -extensions v3_req \
    -out "$OUT_DIR/server.crt" \
    $USE_OQS 2>&1 | head -1

if [[ $? -ne 0 ]]; then
    echo "ERROR: Failed to sign server certificate"
    exit 1
fi

echo "Server certificate generated."
echo ""

# Verify and display certificate info
echo "--- Certificate verification ---"
openssl verify -CAfile "$OUT_DIR/ca.crt" "$OUT_DIR/server.crt" 2>&1

echo ""
echo "--- Server certificate details ---"
openssl x509 -in "$OUT_DIR/server.crt" -noout -subject -issuer -dates 2>&1
SIG_ALGO=$(openssl x509 -in "$OUT_DIR/server.crt" -noout -text 2>/dev/null | grep "Signature Algorithm" | head -1)
echo "Signature Algorithm: $SIG_ALGO"

echo ""
echo "=== Certificate generation complete ==="
echo "Files in $OUT_DIR:"
ls -la "$OUT_DIR"/*.key "$OUT_DIR"/*.crt "$OUT_DIR"/*.csr 2>/dev/null

# Cleanup CSR and temp files
rm -f "$OUT_DIR/server.csr" "$OUT_DIR/san.cnf" "$OUT_DIR/ca.srl"
