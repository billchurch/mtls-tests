#!/bin/sh
set -eu

CERT_DIR="${CERT_DIR:-/work/certs}"
CONF_DIR="${CONF_DIR:-/work/configs}"

echo "=== Generating test PKI ==="

# ---- 1. Root CA ----
echo "--- Root CA ---"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$CERT_DIR/root-ca-key.pem" \
  -out    "$CERT_DIR/root-ca.pem" \
  -days   3650 \
  -subj   "/C=US/O=U.S. Government/OU=Test PKI/CN=Test Federal Root CA" \
  -config "$CONF_DIR/openssl-ca.cnf" \
  -extensions v3_root_ca

openssl x509 -in "$CERT_DIR/root-ca.pem" -noout -subject -issuer
echo ""

# ---- 2. Intermediate CA ----
echo "--- Intermediate CA ---"
openssl req -newkey rsa:2048 -nodes \
  -keyout "$CERT_DIR/intermediate-ca-key.pem" \
  -out    "$CERT_DIR/intermediate-ca.csr" \
  -subj   "/C=US/O=U.S. Government/OU=Test PKI/CN=Test PIV Authentication CA"

openssl x509 -req \
  -in      "$CERT_DIR/intermediate-ca.csr" \
  -CA      "$CERT_DIR/root-ca.pem" \
  -CAkey   "$CERT_DIR/root-ca-key.pem" \
  -CAcreateserial \
  -out     "$CERT_DIR/intermediate-ca.pem" \
  -days    1825 \
  -extfile "$CONF_DIR/openssl-ca.cnf" \
  -extensions v3_intermediate_ca

openssl x509 -in "$CERT_DIR/intermediate-ca.pem" -noout -subject -issuer
echo ""

# ---- 3. Server certificate (signed by Root CA) ----
echo "--- Server certificate ---"
openssl req -newkey rsa:2048 -nodes \
  -keyout "$CERT_DIR/server-key.pem" \
  -out    "$CERT_DIR/server.csr" \
  -config "$CONF_DIR/openssl-server.cnf"

openssl x509 -req \
  -in      "$CERT_DIR/server.csr" \
  -CA      "$CERT_DIR/root-ca.pem" \
  -CAkey   "$CERT_DIR/root-ca-key.pem" \
  -CAcreateserial \
  -out     "$CERT_DIR/server.pem" \
  -days    365 \
  -extfile "$CONF_DIR/openssl-server.cnf" \
  -extensions v3_server

openssl x509 -in "$CERT_DIR/server.pem" -noout -subject -ext subjectAltName
echo ""

# ---- 4. PIV client certificate (signed by Intermediate CA) ----
echo "--- PIV client certificate ---"
openssl req -newkey rsa:2048 -nodes \
  -keyout "$CERT_DIR/client-key.pem" \
  -out    "$CERT_DIR/client.csr" \
  -config "$CONF_DIR/openssl-piv.cnf"

openssl x509 -req \
  -in      "$CERT_DIR/client.csr" \
  -CA      "$CERT_DIR/intermediate-ca.pem" \
  -CAkey   "$CERT_DIR/intermediate-ca-key.pem" \
  -CAcreateserial \
  -out     "$CERT_DIR/client.pem" \
  -days    365 \
  -extfile "$CONF_DIR/openssl-piv.cnf" \
  -extensions v3_piv_auth

openssl x509 -in "$CERT_DIR/client.pem" -noout -subject -ext subjectAltName
echo ""

# ---- 5. CA chain bundles ----
echo "--- Building CA chain files ---"

# Server needs the client's full CA chain to verify the client cert
cat "$CERT_DIR/intermediate-ca.pem" "$CERT_DIR/root-ca.pem" \
  > "$CERT_DIR/client-ca-chain.pem"

# Client needs the server's CA chain to verify the server cert
cp "$CERT_DIR/root-ca.pem" "$CERT_DIR/server-ca-chain.pem"

echo "  client-ca-chain.pem = intermediate + root (for server -CAfile)"
echo "  server-ca-chain.pem = root             (for client -CAfile)"
echo ""

# ---- 6. Verification ----
echo "--- Verifying certificates ---"
echo -n "  Server cert:  "
openssl verify -CAfile "$CERT_DIR/root-ca.pem" "$CERT_DIR/server.pem"

echo -n "  Client cert:  "
openssl verify -CAfile "$CERT_DIR/client-ca-chain.pem" "$CERT_DIR/client.pem"

echo ""
echo "--- Client cert summary ---"
openssl x509 -in "$CERT_DIR/client.pem" -noout \
  -subject -issuer -ext keyUsage,extendedKeyUsage,certificatePolicies,subjectAltName,authorityInfoAccess,crlDistributionPoints

echo ""
echo "=== PKI generation complete ==="
