#!/usr/bin/env python3
"""Generate Mermaid sequence diagrams from mTLS pcap captures.

Runs tshark against each pcap to extract TLS handshake message sequences,
then produces a Markdown file with Mermaid diagrams highlighting where
client identity is visible (TLS 1.0-1.2) vs encrypted (TLS 1.3).
"""

import os
import subprocess
import sys

PCAP_DIR = "/work/pcaps"
DOCS_DIR = "/work/docs"
OUTPUT_FILE = os.path.join(DOCS_DIR, "handshake-comparison.md")

# TLS handshake type codes (RFC 5246 / 8446)
HS_TYPES = {
    "0": "HelloRequest",
    "1": "ClientHello",
    "2": "ServerHello",
    "4": "NewSessionTicket",
    "8": "EncryptedExtensions",
    "11": "Certificate",
    "12": "ServerKeyExchange",
    "13": "CertificateRequest",
    "14": "ServerHelloDone",
    "15": "CertificateVerify",
    "16": "ClientKeyExchange",
    "20": "Finished",
}

# TLS record content types
CT_HANDSHAKE = "22"
CT_CCS = "20"
CT_APP_DATA = "23"

PCAP_FILES = [
    ("TLS 1.0", "tls10-mtls.pcap"),
    ("TLS 1.1", "tls11-mtls.pcap"),
    ("TLS 1.2", "tls12-mtls.pcap"),
    ("TLS 1.3", "tls13-mtls.pcap"),
]


def run_tshark(pcap_path):
    """Extract TLS handshake fields from a pcap file."""
    cmd = [
        "tshark", "-r", pcap_path, "-T", "fields", "-E", "separator=|",
        "-e", "frame.number",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "tls.handshake.type",
        "-e", "tls.record.content_type",
        "-e", "tls.record.opaque_type",
        "-e", "x509sat.uTF8String",
        "-e", "x509ce.uniformResourceIdentifier",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  tshark error: {result.stderr.strip()}", file=sys.stderr)
        return []
    return result.stdout.strip().split("\n")


def extract_cipher_suite(pcap_path):
    """Extract the negotiated cipher suite from the ServerHello."""
    cmd = [
        "tshark", "-r", pcap_path, "-T", "fields",
        "-e", "tls.handshake.ciphersuite",
        "-Y", "tls.handshake.type == 2",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return "unknown"
    line = result.stdout.strip()
    if not line:
        return "unknown"
    # tshark outputs hex like 0x0035 or the name — take first line
    return line.split("\n")[0].strip()


def extract_cipher_name(pcap_path):
    """Extract the cipher suite name from tshark's decoded output."""
    cmd = [
        "tshark", "-r", pcap_path, "-V",
        "-Y", "tls.handshake.type == 2",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    for line in result.stdout.split("\n"):
        if "Cipher Suite:" in line:
            return line.split("Cipher Suite:")[-1].strip()
    return extract_cipher_suite(pcap_path)


def parse_records(lines, server_port):
    """Parse tshark output into an ordered list of handshake events.

    Returns a list of dicts:
      { "direction": "C->S" or "S->C",
        "hs_types": [list of handshake type codes],
        "content_type": str,
        "opaque_type": str,
        "x509_cn": str or None,
        "x509_uris": str or None }
    """
    records = []
    for line in lines:
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) < 9:
            continue

        frame_num = parts[0]
        ip_src = parts[1]
        src_port = parts[2]
        dst_port = parts[3]
        hs_types_raw = parts[4]
        content_type = parts[5]
        opaque_type = parts[6]
        x509_cn = parts[7]
        x509_uris = parts[8]

        # Determine direction based on port numbers
        if dst_port == str(server_port):
            direction = "C->S"
        elif src_port == str(server_port):
            direction = "S->C"
        else:
            continue

        # Parse handshake types (may be comma-separated for coalesced records)
        hs_types = []
        if hs_types_raw:
            hs_types = [t.strip() for t in hs_types_raw.split(",")]

        records.append({
            "direction": direction,
            "hs_types": hs_types,
            "content_type": content_type,
            "opaque_type": opaque_type,
            "x509_cn": x509_cn if x509_cn else None,
            "x509_uris": x509_uris if x509_uris else None,
        })

    return records


def build_message_sequence(records):
    """Collapse consecutive same-direction records into message groups.

    Returns a list of:
      { "direction": "C->S" or "S->C",
        "labels": [human-readable message names],
        "has_client_cert": bool,
        "has_ccs": bool,
        "is_app_data": bool,
        "x509_cn": str or None,
        "x509_uris": str or None }
    """
    groups = []
    current = None

    for rec in records:
        labels = []
        has_ccs = False
        is_app_data = False

        # Check for ChangeCipherSpec
        if CT_CCS in (rec["content_type"] or "").split(","):
            has_ccs = True

        # Check for Application Data (TLS 1.3 encrypted records)
        if CT_APP_DATA in (rec["opaque_type"] or "").split(","):
            is_app_data = True

        for ht in rec["hs_types"]:
            name = HS_TYPES.get(ht, f"Unknown({ht})")
            labels.append(name)

        has_client_cert = False
        if rec["direction"] == "C->S" and "11" in rec["hs_types"]:
            has_client_cert = True

        entry = {
            "direction": rec["direction"],
            "labels": labels,
            "has_client_cert": has_client_cert,
            "has_ccs": has_ccs,
            "is_app_data": is_app_data,
            "x509_cn": rec["x509_cn"],
            "x509_uris": rec["x509_uris"],
        }

        # Merge into current group if same direction
        if current and current["direction"] == entry["direction"]:
            current["labels"].extend(entry["labels"])
            current["has_client_cert"] = current["has_client_cert"] or entry["has_client_cert"]
            current["has_ccs"] = current["has_ccs"] or entry["has_ccs"]
            current["is_app_data"] = current["is_app_data"] or entry["is_app_data"]
            if entry["x509_cn"]:
                current["x509_cn"] = entry["x509_cn"]
            if entry["x509_uris"]:
                current["x509_uris"] = entry["x509_uris"]
        else:
            if current:
                groups.append(current)
            current = entry

    if current:
        groups.append(current)

    return groups


def format_arrow(direction):
    if direction == "C->S":
        return "C->>S"
    return "S->>C"


def dedupe_labels(labels):
    """Remove consecutive duplicate labels while preserving order."""
    seen = []
    for label in labels:
        if not seen or seen[-1] != label:
            seen.append(label)
    return seen


def generate_mermaid_tls12(tls_version, groups, cipher_name, client_cn):
    """Generate a Mermaid diagram for TLS 1.0-1.2 (client cert in cleartext)."""
    lines = []
    lines.append("```mermaid")
    lines.append("sequenceDiagram")
    lines.append(f"    participant C as Client ({client_cn})")
    lines.append("    participant S as Server (localhost)")
    lines.append("")

    client_cert_emitted = False

    for group in groups:
        labels = dedupe_labels(group["labels"])
        has_ccs = group["has_ccs"]

        if not labels and not has_ccs and group["is_app_data"]:
            labels = ["Application Data"]

        if not labels and not has_ccs:
            continue

        arrow = format_arrow(group["direction"])

        if group["has_client_cert"] and not client_cert_emitted:
            # Separate cert-related messages from CCS
            cert_labels = [l for l in labels if l != "ChangeCipherSpec"]
            cert_msg = ", ".join(cert_labels)

            # Red block around the client certificate message only
            lines.append("    rect rgb(96, 96, 96)")
            lines.append(f"        Note over C,S: CLIENT IDENTITY VISIBLE IN CLEARTEXT")
            lines.append(f"        {arrow}: {cert_msg}")

            # Add annotation for visible fields
            cert_fields = [f"CN={client_cn}"]
            if group["x509_uris"]:
                for uri in group["x509_uris"].split(","):
                    uri = uri.strip()
                    if uri:
                        cert_fields.append(uri)
            lines.append(f"        Note right of S: {cert_fields[0]}")
            if len(cert_fields) > 1:
                for field in cert_fields[1:]:
                    lines.append(f"        Note right of S: {field}")
            lines.append("    end")
            client_cert_emitted = True

            # CCS comes after the red block (encryption starts here)
            if has_ccs:
                lines.append(f"    {arrow}: ChangeCipherSpec, Finished")
        else:
            if has_ccs:
                labels.append("ChangeCipherSpec")
            msg = ", ".join(labels)
            if msg:
                lines.append(f"    {arrow}: {msg}")

    lines.append("```")
    return "\n".join(lines)


def generate_mermaid_tls13(tls_version, groups, cipher_name, client_cn, known_cn):
    """Generate a Mermaid diagram for TLS 1.3 (client cert encrypted)."""
    # Use the known CN from TLS 1.2 capture — TLS 1.3 hides it, which is the point
    display_cn = known_cn or client_cn
    lines = []
    lines.append("```mermaid")
    lines.append("sequenceDiagram")
    lines.append(f"    participant C as Client ({display_cn})")
    lines.append("    participant S as Server (localhost)")
    lines.append("")

    # In TLS 1.3 the handshake after ServerHello is encrypted.
    # We split into: pre-encryption (ClientHello, ServerHello) and
    # post-encryption (everything else appears as Application Data).
    server_hello_seen = False
    encrypted_block_open = False

    for group in groups:
        labels = dedupe_labels(group["labels"])
        if group["has_ccs"]:
            labels.append("ChangeCipherSpec")

        if not labels and group["is_app_data"]:
            labels = ["Application Data"]

        if not labels:
            continue

        arrow = format_arrow(group["direction"])
        msg = ", ".join(labels)

        # Detect ServerHello
        if "ServerHello" in labels:
            server_hello_seen = True
            lines.append(f"    {arrow}: {msg}")
            # Open encrypted block after ServerHello
            lines.append("")
            lines.append("    rect rgb(96, 96, 96))")
            lines.append(f"        Note over C,S: ENCRYPTED TUNNEL — client identity hidden")
            encrypted_block_open = True
            continue

        if encrypted_block_open:
            # Inside the encrypted section
            if group["is_app_data"] or server_hello_seen:
                lines.append(f"        {arrow}: {msg}")
            else:
                lines.append(f"        {arrow}: {msg}")
        else:
            lines.append(f"    {arrow}: {msg}")

    if encrypted_block_open:
        lines.append("    end")

    lines.append("```")
    return "\n".join(lines)


def extract_client_identity(pcap_path):
    """Extract client certificate identity fields from the pcap."""
    # Get client cert subject
    cmd = [
        "tshark", "-r", pcap_path, "-T", "fields",
        "-e", "x509sat.uTF8String",
        "-e", "x509sat.printableString",
        "-e", "x509ce.uniformResourceIdentifier",
        "-e", "x509ce.rfc822Name",
        "-Y", "tls.handshake.type == 11",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    cn = None
    uris = []
    emails = []
    all_strings = []

    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 1 and parts[0]:
            # UTF8Strings — may contain CN components
            for s in parts[0].split(","):
                s = s.strip()
                if s:
                    all_strings.append(s)
        if len(parts) >= 2 and parts[1]:
            for s in parts[1].split(","):
                s = s.strip()
                if s:
                    all_strings.append(s)
        if len(parts) >= 3 and parts[2]:
            for u in parts[2].split(","):
                u = u.strip()
                if u:
                    uris.append(u)
        if len(parts) >= 4 and parts[3]:
            for e in parts[3].split(","):
                e = e.strip()
                if e:
                    emails.append(e)

    # Try to find the PIV-style CN
    for s in all_strings:
        if "DOE" in s.upper() or "." in s and any(c.isdigit() for c in s):
            cn = s
            break

    if not cn and all_strings:
        cn = all_strings[0]
    if not cn:
        cn = "Unknown Client"

    return cn, uris, emails


def generate_analysis(pcap_results):
    """Generate the summary analysis section."""
    lines = []
    lines.append("## Summary: Client Identity Visibility by TLS Version")
    lines.append("")
    lines.append("| TLS Version | Client Certificate | Subject DN | SAN (UUID/email) | Policy OIDs | CRL/OCSP URIs | Cipher Suite |")
    lines.append("|-------------|-------------------|------------|------------------|-------------|---------------|--------------|")

    for tls_ver, cipher, cn, uris, emails, is_13 in pcap_results:
        if is_13:
            lines.append(f"| {tls_ver} | Encrypted | Encrypted | Encrypted | Encrypted | Encrypted | {cipher} |")
        else:
            san = "Visible"
            if emails or any("urn:uuid" in u for u in uris):
                san = "Visible"
            lines.append(f"| {tls_ver} | **Cleartext** | **Visible** | **Visible** | **Visible** | **Visible** | {cipher} |")

    lines.append("")
    return "\n".join(lines)


def main():
    os.makedirs(DOCS_DIR, exist_ok=True)

    doc_lines = []
    doc_lines.append("# mTLS Handshake Comparison: TLS 1.0 - 1.3")
    doc_lines.append("")
    doc_lines.append("Sequence diagrams generated from live mTLS handshake packet captures.")
    doc_lines.append("Each diagram shows the actual message exchange observed on the wire,")
    doc_lines.append("highlighting where client identity information is exposed to passive observers.")
    doc_lines.append("")

    pcap_results = []
    known_client_cn = None  # Captured from TLS 1.0-1.2 where cert is visible

    for tls_version, pcap_name in PCAP_FILES:
        pcap_path = os.path.join(PCAP_DIR, pcap_name)
        print(f"Processing {pcap_name}...")

        if not os.path.exists(pcap_path):
            print(f"  Skipping — {pcap_path} not found")
            doc_lines.append(f"## {tls_version}")
            doc_lines.append("")
            doc_lines.append(f"*Pcap not found: {pcap_name}*")
            doc_lines.append("")
            continue

        # Determine the server port from the pcap filename
        port_map = {
            "tls10-mtls.pcap": 4433,
            "tls11-mtls.pcap": 4434,
            "tls12-mtls.pcap": 4435,
            "tls13-mtls.pcap": 4436,
        }
        server_port = port_map.get(pcap_name, 4433)

        # Extract data
        raw_lines = run_tshark(pcap_path)
        cipher_name = extract_cipher_name(pcap_path)
        cn, uris, emails = extract_client_identity(pcap_path)
        is_tls13 = tls_version == "TLS 1.3"

        print(f"  Client CN: {cn}")
        print(f"  Cipher: {cipher_name}")
        print(f"  URIs: {uris}")
        print(f"  Records: {len(raw_lines)}")

        # Parse and build message sequence
        records = parse_records(raw_lines, server_port)
        groups = build_message_sequence(records)

        # Generate diagram
        doc_lines.append(f"## {tls_version}")
        doc_lines.append("")
        doc_lines.append(f"**Cipher suite:** `{cipher_name}`")
        doc_lines.append("")

        if is_tls13:
            diagram = generate_mermaid_tls13(tls_version, groups, cipher_name, cn, known_client_cn)
            doc_lines.append(diagram)
            doc_lines.append("")
            doc_lines.append(f"In TLS 1.3, the client Certificate message is sent inside the encrypted")
            doc_lines.append(f"tunnel established after the ServerHello. A passive observer sees only")
            doc_lines.append(f"opaque Application Data records — the client's identity (CN, SAN, policy")
            doc_lines.append(f"OIDs, CRL/OCSP URIs) is never exposed on the wire.")
        else:
            if cn != "Unknown Client":
                known_client_cn = cn
            diagram = generate_mermaid_tls12(tls_version, groups, cipher_name, cn)
            doc_lines.append(diagram)
            doc_lines.append("")
            doc_lines.append(f"In {tls_version}, the client Certificate message is sent in **cleartext**")
            doc_lines.append(f"before the ChangeCipherSpec. A passive observer can extract:")
            doc_lines.append(f"")
            doc_lines.append(f"- **Subject DN:** CN={cn}")
            if uris:
                doc_lines.append(f"- **SAN URIs:** {', '.join(uris)}")
            if emails:
                doc_lines.append(f"- **SAN email:** {', '.join(emails)}")
            doc_lines.append(f"- **Certificate policies** (FPKI OIDs)")
            doc_lines.append(f"- **CRL Distribution Points / OCSP URIs**")
            doc_lines.append(f"- **Issuer chain** (full CA hierarchy)")

        doc_lines.append("")
        doc_lines.append("---")
        doc_lines.append("")

        pcap_results.append((tls_version, cipher_name, cn, uris, emails, is_tls13))

    # Summary table
    if pcap_results:
        doc_lines.append(generate_analysis(pcap_results))

    # Narrative
    doc_lines.append("## Why TLS 1.3 Is Different")
    doc_lines.append("")
    doc_lines.append("In TLS 1.0-1.2, the handshake follows a pattern where the client sends its")
    doc_lines.append("Certificate message in cleartext, before encryption is established:")
    doc_lines.append("")
    doc_lines.append("1. ClientHello / ServerHello negotiate parameters")
    doc_lines.append("2. Server sends its certificate and requests the client's")
    doc_lines.append("3. **Client sends its certificate in the clear**")
    doc_lines.append("4. ChangeCipherSpec enables encryption")
    doc_lines.append("5. Finished messages verify the handshake")
    doc_lines.append("")
    doc_lines.append("TLS 1.3 restructures the handshake so that encryption begins immediately")
    doc_lines.append("after the ServerHello (using keys derived from the key share exchange):")
    doc_lines.append("")
    doc_lines.append("1. ClientHello / ServerHello exchange key shares")
    doc_lines.append("2. **Encryption starts** — all subsequent messages are encrypted")
    doc_lines.append("3. Server sends EncryptedExtensions, Certificate, CertificateVerify, Finished")
    doc_lines.append("4. **Client sends Certificate, CertificateVerify, Finished (all encrypted)**")
    doc_lines.append("")
    doc_lines.append("This means a passive network observer monitoring TLS 1.3 mTLS traffic")
    doc_lines.append("cannot determine the client's identity, organizational affiliation,")
    doc_lines.append("or certificate policy — information that is fully visible in earlier versions.")
    doc_lines.append("")

    # Write output
    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(doc_lines))

    print(f"\nDiagram written to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
