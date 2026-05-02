# mTLS Handshake Visibility Tests

Captures packet traces of mTLS handshakes across TLS 1.0–1.3 to demonstrate what client identity information is visible to a passive network observer at each protocol version.

The client certificate mimics a **US Government PIV authentication certificate** (FIPS 201), complete with FPKI policy OIDs, UUID-based Subject Alternative Names, and realistic CA hierarchy — the kind of credential where on-wire exposure has real privacy implications.

## Quick Start

```sh
docker build -t mtls-tests .
docker run --rm -v "$(pwd)/pcaps:/work/pcaps" mtls-tests
```

Four pcap files land in `pcaps/`:

```
pcaps/tls10-mtls.pcap
pcaps/tls11-mtls.pcap
pcaps/tls12-mtls.pcap
pcaps/tls13-mtls.pcap
```

Open them in Wireshark or inspect with tcpdump:

```sh
tcpdump -r pcaps/tls12-mtls.pcap -A | grep DOE.JOHN    # visible
tcpdump -r pcaps/tls13-mtls.pcap -A | grep DOE.JOHN    # not visible
```

## What It Shows

| TLS Version | Client Cert Visible? | Why |
|---|---|---|
| 1.0 | Yes — cleartext | Certificate message sent before encryption begins |
| 1.1 | Yes — cleartext | Same as 1.0 |
| 1.2 | Yes — cleartext | Certificate message precedes ChangeCipherSpec |
| 1.3 | No — encrypted | Client certificate sent inside encrypted handshake tunnel |

In TLS 1.0–1.2, a passive observer on the network can see the **full client certificate** in the handshake: subject DN (`DOE.JOHN.1234567890`), issuer chain, certificate policy OIDs, Subject Alternative Names (UUID, email), Authority Information Access URIs, and CRL Distribution Points.

TLS 1.3 encrypts all of this. The client certificate is sent after the handshake keys are established, so a passive observer sees nothing beyond the initial ClientHello.

## Test PKI

The container generates a throwaway PKI at startup:

```
Test Federal Root CA (self-signed)
├── Test PIV Authentication CA (intermediate, pathlen:0)
│   └── DOE.JOHN.1234567890 (client — PIV auth cert)
└── localhost (server)
```

### PIV Client Certificate Extensions

The client cert includes the fields that make PIV certificates identifiable on the wire:

- **Subject:** `C=US, O=U.S. Government, OU=Department of Test, CN=DOE.JOHN.1234567890`
- **Key Usage:** `digitalSignature` (critical)
- **Extended Key Usage:** `clientAuth`
- **Certificate Policies:** `2.16.840.1.101.3.2.1.3.13` (id-fpki-common-authentication)
- **SAN:** `URI:urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6`, `email:john.doe@test.gov`
- **AIA:** OCSP and CA Issuers URIs (test.gov endpoints)
- **CRL DP:** `http://pki.test.gov/crl/PIVAuthCA.crl`

## Regenerating Certificates

The test PKI is generated fresh each time the container runs. If you want to inspect or reuse the certificates outside the container, you can extract them.

### Via Docker

Mount the `certs/` directory and run only the cert generation script:

```sh
docker build -t mtls-tests .
docker run --rm \
  -v "$(pwd)/certs:/work/certs" \
  mtls-tests \
  sh -c "./scripts/gen-certs.sh"
```

The generated files will appear in `certs/` on the host:

```
certs/
  root-ca.pem              # Root CA certificate
  root-ca-key.pem          # Root CA private key
  intermediate-ca.pem      # Intermediate CA certificate
  intermediate-ca-key.pem  # Intermediate CA private key
  server.pem               # Server certificate (SAN: localhost, 127.0.0.1)
  server-key.pem           # Server private key
  client.pem               # PIV client certificate
  client-key.pem           # Client private key
  client-ca-chain.pem      # Intermediate + Root (used by server to verify client)
  server-ca-chain.pem      # Root CA (used by client to verify server)
```

### Locally (without Docker)

Requires OpenSSL 3.x:

```sh
mkdir -p certs
CERT_DIR=certs CONF_DIR=configs sh scripts/gen-certs.sh
```

> **Note:** The script uses `/work/certs` and `/work/configs` as default paths (matching the container layout). Set `CERT_DIR` and `CONF_DIR` environment variables to override, or edit the variables at the top of `scripts/gen-certs.sh`.

## Analysis

For a detailed comparison of what is visible on the wire at each TLS version, see [docs/handshake-comparison.md](docs/handshake-comparison.md).

For a visual walkthrough of the mTLS handshake, see the presentation:
- [mtls-handshake-analysis.pdf](mtls-handshake-analysis.pdf) — PDF format

## How It Works

1. **`scripts/gen-certs.sh`** generates all certificates using `openssl req` and `openssl x509 -req`. No CA database needed — serial numbers are auto-generated.

2. **`scripts/run-tests.sh`** loops over TLS 1.0–1.3, and for each version:
   - Starts `tcpdump` on the loopback interface
   - Starts `openssl s_server` requiring client certificates (`-Verify 1`)
   - Connects with `openssl s_client` presenting the PIV cert
   - Captures the full handshake to a pcap file

3. **`scripts/gen-diagrams.py`** runs `tshark` against each pcap to extract the TLS handshake message sequence, then generates [docs/handshake-comparison.md](docs/handshake-comparison.md) — a Markdown file with Mermaid sequence diagrams showing where client identity is exposed (TLS 1.0–1.2) vs encrypted (TLS 1.3).

4. TLS 1.0/1.1 are disabled by default in OpenSSL 3.x. The container overrides `/etc/ssl/openssl.cnf` to re-enable the legacy provider and set `MinProtocol = TLSv1` with `SECLEVEL=0`.

## Repo Layout

```
Dockerfile               # Alpine 3.21 + openssl + tcpdump
.dockerignore
configs/
  openssl-ca.cnf         # Root CA and Intermediate CA extensions
  openssl-server.cnf     # Server cert (SAN: localhost, 127.0.0.1)
  openssl-piv.cnf        # PIV client cert extensions
  openssl-legacy.cnf     # TLS 1.0/1.1 enablement for OpenSSL 3.x
scripts/
  gen-certs.sh           # PKI generation
  run-tests.sh           # Test runner with pcap capture
  gen-diagrams.py        # Generates Mermaid sequence diagrams from pcaps
docs/
  handshake-comparison.md  # Mermaid diagrams and analysis (generated)
certs/                   # Generated certificates (not checked in)
pcaps/                   # Output directory (not checked in)
```

## Requirements

- Docker

That's it. Everything runs inside the container.
