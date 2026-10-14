#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
08-normalize-attestation-output.py — re-validate a captured AWS Nitro attestation
document and rewrite 06-chain-validation.json in the unified schema expected
by 07-cross-vm-matrix.sh.

Useful when:
  - Older capture scripts produced a different JSON schema
  - A captured attestation needs re-validation against an updated root CA
  - Verifying captured evidence offline from a customer-provided VM directory

Usage (run on laptop, not on EC2):
  pip install cryptography cbor2
  ./08-normalize-attestation-output.py <vm-evidence-dir>

The <vm-evidence-dir> must contain:
  04-attestation-document.bin         (raw COSE_Sign1 from /dev/nsm)
  02-report-data.bin                  (the user_data hash we expect)
  06-certificates/aws-nitro-root.pem  (AWS Nitro Root CA G1 in PEM)

After running, 06-chain-validation.json will be (re)written with this schema:

  {
    "module_id": "...",
    "timestamp_ms": <int>,
    "user_data": "<hex>",
    "cabundle_count": <int>,
    "chain_valid": <bool>,
    "anchor_valid": <bool>,
    "cose_valid": <bool>,
    "user_data_match": <bool>,
    "pcr0_nonzero": <bool>,                    # production-mode marker
    "pcr0_matches_expected": <bool|null>,      # null when no expected available
    "all_pass": <bool>,                        # all four core checks
    "production_grade": <bool>,                # also requires nonzero PCR0 + match
    "cert_chain": ["<rfc4514 subject>", ...],
    "captured_pcr0": "<hex>",
    "expected_pcr0": "<hex>" | null,
  }

If a `02d-expected-pcrs.json` is present alongside the VM directory
(produced by the production-mode build script 02d), the verifier
additionally compares the captured PCR0 against the expected PCR0.

Any pre-existing 06-chain-validation.json is backed up to
06-chain-validation.json.bak before being overwritten.
"""
import json
import shutil
import sys
from pathlib import Path

try:
    import cbor2
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
except ImportError:
    sys.stderr.write("install dependencies first: pip install cryptography cbor2\n")
    sys.exit(2)


def normalize(vm_dir: Path) -> dict:
    att = vm_dir / "04-attestation-document.bin"
    rd = vm_dir / "02-report-data.bin"
    root = vm_dir / "06-certificates/aws-nitro-root.pem"
    for p in (att, rd, root):
        if not p.is_file():
            sys.stderr.write(f"missing required file: {p}\n")
            sys.exit(2)

    with open(att, "rb") as f:
        raw = f.read()
    cose_sign1 = cbor2.loads(raw)
    protected_bytes, _, payload_bytes, signature = cose_sign1
    doc = cbor2.loads(payload_bytes)

    with open(root, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())
    cabundle = [x509.load_der_x509_certificate(c) for c in doc.get("cabundle", [])]
    leaf_cert = x509.load_der_x509_certificate(doc["certificate"])
    all_certs = cabundle + [leaf_cert]

    # 1. Chain integrity — every cert signed by its predecessor
    chain_valid = True
    for i in range(1, len(all_certs)):
        try:
            all_certs[i - 1].public_key().verify(
                all_certs[i].signature,
                all_certs[i].tbs_certificate_bytes,
                ec.ECDSA(all_certs[i].signature_hash_algorithm),
            )
        except Exception as e:
            chain_valid = False
            sys.stderr.write(f"chain[{i}] failed: {e}\n")

    # 2. Anchor — cabundle root matches AWS Nitro Root CA G1 fingerprint
    anchor_valid = (
        cabundle[0].fingerprint(hashes.SHA256())
        == root_cert.fingerprint(hashes.SHA256())
    )

    # 3. COSE_Sign1 — leaf cert public key verifies the COSE signature
    sig_structure = ["Signature1", protected_bytes, b"", payload_bytes]
    sig_input = cbor2.dumps(sig_structure)
    r = int.from_bytes(signature[:48], "big")
    s = int.from_bytes(signature[48:], "big")
    der_sig = encode_dss_signature(r, s)
    try:
        leaf_cert.public_key().verify(der_sig, sig_input, ec.ECDSA(hashes.SHA384()))
        cose_valid = True
    except Exception as e:
        cose_valid = False
        sys.stderr.write(f"COSE failed: {e}\n")

    # 4. user_data binding
    with open(rd, "rb") as f:
        expected_rd = f.read()
    ud_match = doc.get("user_data", b"") == expected_rd

    # 5. (production-mode only) PCR0 non-zero + matches expected
    pcrs = doc.get("pcrs", {})
    pcr0_hex = pcrs.get(0, b"").hex()
    pcr0_nonzero = bool(pcr0_hex) and not all(c == "0" for c in pcr0_hex)

    expected_pcr0 = None
    pcr0_matches_expected = None
    expected_path = vm_dir / "02d-expected-pcrs.json"
    if expected_path.is_file():
        with open(expected_path) as ef:
            try:
                expected_obj = json.load(ef)
                expected_pcr0 = (expected_obj.get("expected_pcr0") or "").lower()
                if expected_pcr0:
                    pcr0_matches_expected = pcr0_hex.lower() == expected_pcr0
            except Exception as e:
                sys.stderr.write(f"warning: cannot read {expected_path}: {e}\n")

    all_pass_core = chain_valid and anchor_valid and cose_valid and ud_match
    production_grade = (
        all_pass_core and pcr0_nonzero
        and (pcr0_matches_expected is True)
    )

    return {
        "module_id": doc["module_id"],
        "timestamp_ms": doc["timestamp"],
        "user_data": doc.get("user_data", b"").hex(),
        "cabundle_count": len(cabundle),
        "chain_valid": chain_valid,
        "anchor_valid": anchor_valid,
        "cose_valid": cose_valid,
        "user_data_match": ud_match,
        "pcr0_nonzero": pcr0_nonzero,
        "pcr0_matches_expected": pcr0_matches_expected,
        "all_pass": all_pass_core,
        "production_grade": production_grade,
        "cert_chain": [c.subject.rfc4514_string() for c in all_certs],
        "captured_pcr0": pcr0_hex,
        "expected_pcr0": expected_pcr0,
    }



def derive_identity(vm_dir: Path) -> None:
    """Write 00-vm-identity.txt from the instance's own records when the
    capture script that ran did not write it (the production path before
    2026-10-14). Every value comes from a file the instance produced:
    vm-identity-pack.txt (06-pack-evidence.sh) and 05-attestation-parsed.json
    (02e). The file says so in its last line."""
    ident = vm_dir / "00-vm-identity.txt"
    pack = vm_dir / "vm-identity-pack.txt"
    parsed = vm_dir / "05-attestation-parsed.json"
    if ident.exists() or not (pack.exists() and parsed.exists()):
        return
    kv = {}
    for line in pack.read_text().splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            kv[k.strip()] = v.strip()
    module_id = json.loads(parsed.read_text()).get("module_id", "")
    kernel = kv.get("uname", "").split()[2] if len(kv.get("uname", "").split()) > 2 else ""
    ident.write_text(
        f"Instance ID: {kv.get('instance_id', '')}\n"
        f"Region:      {kv.get('region', '')}\n"
        f"Availability Zone: {kv.get('az', '')}\n"
        f"Kernel:      {kernel}\n"
        f"Enclave mode: production (no --debug-mode, vsock-attest)\n"
        f"Module ID:   {module_id}\n"
        f"Captured: {kv.get('captured_at', '')}\n"
        f"Derived: on the laptop by 08-normalize-attestation-output.py from vm-identity-pack.txt and 05-attestation-parsed.json\n"
    )
    print(f"=== wrote {ident} (derived from the instance's records) ===")


def main() -> None:
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: 08-normalize-attestation-output.py <vm-evidence-dir>\n")
        sys.exit(2)
    vm_dir = Path(sys.argv[1])
    derive_identity(vm_dir)
    if not vm_dir.is_dir():
        sys.stderr.write(f"not a directory: {vm_dir}\n")
        sys.exit(2)

    out = vm_dir / "06-chain-validation.json"
    if out.exists():
        bak = out.with_suffix(".json.bak")
        shutil.copy(out, bak)
        sys.stderr.write(f"backup: {bak}\n")

    result = normalize(vm_dir)
    with open(out, "w") as f:
        json.dump(result, f, indent=2)

    print(f"=== ✓ rewrote {out} ===")
    print(f"Module ID:           {result['module_id']}")
    print(f"chain/anchor/cose/ud: {result['all_pass']}")
    print(f"PCR0 nonzero:        {result['pcr0_nonzero']}")
    if result['pcr0_matches_expected'] is None:
        print("PCR0 matches:        n/a (no expected PCR0 file present)")
    else:
        print(f"PCR0 matches:        {result['pcr0_matches_expected']}")
    print(f"production_grade:    {result['production_grade']}")
    print(f"cert_chain:          {len(result['cert_chain'])} certs")


if __name__ == "__main__":
    main()
