#!/usr/bin/env bash
# Generate TLS certificates for IoT Security Radar
# Creates a root CA, intermediate CA, and wildcard *.local server cert.
# All filenames match those expected by docker-compose.yml / ELK configs.
#
# Usage: bash tls/generate-certs.sh
# Run once before: docker compose up -d

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$SCRIPT_DIR"

PASSPHRASE="abcd1234"
DAYS=3650
COUNTRY="PL"
ORG="IoTSecurityRadar"

echo "==> Generating TLS certificates in $OUT"
echo "    Passphrase: $PASSPHRASE (matches logstash / filebeat configs)"
echo ""

# -----------------------------------------------------------------------
# 1. Root CA
# -----------------------------------------------------------------------
echo "[1/5] Root CA key + self-signed cert"
openssl genrsa -aes256 -passout pass:"$PASSPHRASE" \
    -out "$OUT/root-ca.key.pem" 4096

openssl req -new -x509 -days $DAYS \
    -key "$OUT/root-ca.key.pem" -passin pass:"$PASSPHRASE" \
    -out "$OUT/root-ca.cert.pem" \
    -subj "/C=$COUNTRY/O=$ORG/CN=Root CA"

# -----------------------------------------------------------------------
# 2. Intermediate CA
# -----------------------------------------------------------------------
echo "[2/5] Intermediate CA key + cert signed by root"
openssl genrsa -aes256 -passout pass:"$PASSPHRASE" \
    -out "$OUT/intermediate-ca.key.pem" 4096

openssl req -new \
    -key "$OUT/intermediate-ca.key.pem" -passin pass:"$PASSPHRASE" \
    -out "$OUT/intermediate-ca.csr.pem" \
    -subj "/C=$COUNTRY/O=$ORG/CN=Intermediate CA"

openssl x509 -req -days $DAYS -CA "$OUT/root-ca.cert.pem" \
    -CAkey "$OUT/root-ca.key.pem" -passin pass:"$PASSPHRASE" \
    -CAcreateserial \
    -in "$OUT/intermediate-ca.csr.pem" \
    -out "$OUT/intermediate-ca.cert.pem"

# -----------------------------------------------------------------------
# 3. CA chain (root + intermediate concatenated)
# -----------------------------------------------------------------------
echo "[3/5] CA chain (root + intermediate)"
cat "$OUT/intermediate-ca.cert.pem" "$OUT/root-ca.cert.pem" \
    > "$OUT/ca-chain.cert.pem"

# -----------------------------------------------------------------------
# 4. Wildcard *.local server cert
# -----------------------------------------------------------------------
echo "[4/5] Wildcard *.local server key + cert"
openssl genrsa -aes256 -passout pass:"$PASSPHRASE" \
    -out "$OUT/wildcard.local.flex.key.pem" 2048

openssl req -new \
    -key "$OUT/wildcard.local.flex.key.pem" -passin pass:"$PASSPHRASE" \
    -out "$OUT/wildcard.local.flex.csr.pem" \
    -subj "/C=$COUNTRY/O=$ORG/CN=*.local"

# SAN extension
cat > "$OUT/san.cnf" <<EOF
[req]
req_extensions = v3_req
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = *.local
DNS.2 = localhost
IP.1  = 127.0.0.1
EOF

openssl x509 -req -days $DAYS \
    -CA "$OUT/intermediate-ca.cert.pem" \
    -CAkey "$OUT/intermediate-ca.key.pem" -passin pass:"$PASSPHRASE" \
    -CAcreateserial \
    -in "$OUT/wildcard.local.flex.csr.pem" \
    -out "$OUT/wildcard.local.flex.cert.pem" \
    -extfile "$OUT/san.cnf" -extensions v3_req

# -----------------------------------------------------------------------
# 5. Unencrypted key (Filebeat / Logstash need this)
# -----------------------------------------------------------------------
echo "[5/5] Unencrypted key copy (wildcard.local.flex.key.nopass.pem)"
openssl rsa -in "$OUT/wildcard.local.flex.key.pem" \
    -passin pass:"$PASSPHRASE" \
    -out "$OUT/wildcard.local.flex.key.nopass.pem"

# -----------------------------------------------------------------------
# Clean up temp files
# -----------------------------------------------------------------------
rm -f "$OUT"/*.csr.pem "$OUT"/*.srl "$OUT/san.cnf"

echo ""
echo "Done! Files generated:"
ls -1 "$OUT"/*.pem
echo ""
echo "Next: docker compose up -d"
