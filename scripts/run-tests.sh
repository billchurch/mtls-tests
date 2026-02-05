#!/bin/sh
set -eu

CERT_DIR=/work/certs
PCAP_DIR=/work/pcaps
BASE_PORT=4433

echo ""
echo "========================================="
echo "  mTLS handshake capture — TLS 1.0–1.3"
echo "========================================="
echo ""

PORT=$BASE_PORT
for test_case in "tls10:-tls1" "tls11:-tls1_1" "tls12:-tls1_2" "tls13:-tls1_3"; do
  LABEL="${test_case%%:*}"
  FLAG="${test_case#*:}"
  PCAP_FILE="$PCAP_DIR/${LABEL}-mtls.pcap"

  echo "--- Test: $LABEL ($FLAG) on port $PORT ---"

  # 1. Start packet capture on loopback
  tcpdump -i lo -w "$PCAP_FILE" -s 0 port "$PORT" &
  TCPDUMP_PID=$!

  # 2. Start TLS server — use a FIFO to keep stdin open
  FIFO="/tmp/server-fifo-$$"
  mkfifo "$FIFO"
  cat "$FIFO" | openssl s_server \
    -cert    "$CERT_DIR/server.pem" \
    -key     "$CERT_DIR/server-key.pem" \
    -CAfile  "$CERT_DIR/client-ca-chain.pem" \
    -Verify  1 \
    -accept  "$PORT" \
    "$FLAG" &
  SERVER_PID=$!

  sleep 0.5

  # 3. Connect with client cert, complete handshake, then quit
  { sleep 1; echo "Q"; } | openssl s_client \
    -cert    "$CERT_DIR/client.pem" \
    -key     "$CERT_DIR/client-key.pem" \
    -CAfile  "$CERT_DIR/server-ca-chain.pem" \
    -connect "127.0.0.1:$PORT" \
    "$FLAG" 2>&1 || true

  sleep 0.3

  # 4. Tear down — close the FIFO to let server exit, then force-kill
  echo "Q" > "$FIFO" 2>/dev/null || true
  rm -f "$FIFO"
  kill "$SERVER_PID" 2>/dev/null || true
  # Kill any openssl processes still bound to this port
  pkill -9 -f "accept.*$PORT" 2>/dev/null || true
  kill "$TCPDUMP_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  wait "$TCPDUMP_PID" 2>/dev/null || true

  # 5. Report
  if [ -s "$PCAP_FILE" ]; then
    BYTES=$(wc -c < "$PCAP_FILE")
    echo "  ✓ Captured $PCAP_FILE ($BYTES bytes)"
  else
    echo "  ✗ FAILED — pcap is empty or missing"
  fi
  echo ""

  # Use a different port for each test to avoid port conflicts
  PORT=$((PORT + 1))
done

echo "========================================="
echo "  All captures complete"
echo "========================================="
echo ""
echo "Pcap files:"
ls -lh "$PCAP_DIR"/*.pcap 2>/dev/null || echo "  (none)"
echo ""
