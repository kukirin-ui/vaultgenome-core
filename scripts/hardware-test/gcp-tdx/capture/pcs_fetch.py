# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fetch the public Intel PCS artifacts a TDX quote's verification needs,
into the evidence directory: the PCK certificate chain the quote carries
(split out), the TCB info for its FMSPC, the QE identity, the Intel SGX
Root CA and its CRL, and the PCK CRL — everything Intel publishes, nothing
secret. Run after the guest capture."""
import base64, json, re, struct, sys, urllib.request, urllib.parse, pathlib
from datetime import datetime, timezone

PCS = "https://api.trustedservices.intel.com"

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "vault-genome-tdx-capture"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.status, dict(r.headers), r.read()

def main(evidence):
    ev = pathlib.Path(evidence)
    quote = (ev / "q1.quote.bin").read_bytes()
    # Quote v4: header 48, TD report body 584, u32 signature data length, signature data.
    siglen = struct.unpack_from("<I", quote, 48 + 584)[0]
    sig = quote[48 + 584 + 4: 48 + 584 + 4 + siglen]
    # signature 64 | attestation key 64 | cert data type u16 | cert data size u32 | cert data
    cdt = struct.unpack_from("<H", sig, 128)[0]
    cds = struct.unpack_from("<I", sig, 130)[0]
    cert_data = sig[134:134 + cds]
    notes = {"signature_data_len": siglen, "qe_cert_data_type": cdt, "qe_cert_data_size": cds}
    pem_chain = None
    if cdt == 6:
        # QE report certification data: QE report 384 | QE report sig 64 | auth data (u16 len + bytes) | cert data type u16 | size u32 | data
        qe_auth_len = struct.unpack_from("<H", cert_data, 448)[0]
        inner_off = 450 + qe_auth_len
        inner_type = struct.unpack_from("<H", cert_data, inner_off)[0]
        inner_size = struct.unpack_from("<I", cert_data, inner_off + 2)[0]
        inner = cert_data[inner_off + 6: inner_off + 6 + inner_size]
        notes.update({"qe_auth_data_len": qe_auth_len, "inner_cert_data_type": inner_type, "inner_cert_data_size": inner_size})
        if inner_type == 5:
            pem_chain = inner
    elif cdt == 5:
        pem_chain = cert_data
    if pem_chain is None:
        raise SystemExit(f"quote carries certification data of type {cdt}; expected a PCK certificate chain (type 5 inside 6)")
    (ev / "pck-chain.pem").write_bytes(pem_chain.rstrip(b"\x00"))
    certs = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem_chain, re.S)
    notes["pck_chain_certificates"] = len(certs)
    (ev / "pck-leaf.pem").write_bytes(certs[0] + b"\n")
    # FMSPC from the PCK leaf: OID 1.2.840.113741.1.13.1.4, 6 bytes.
    import subprocess
    der = subprocess.run(["openssl", "x509", "-in", str(ev / "pck-leaf.pem"), "-outform", "DER"], capture_output=True, check=True).stdout
    oid = bytes.fromhex("06 0a 2a 86 48 86 f8 4d 01 0d 01 04".replace(" ", ""))
    i = der.find(oid)
    if i < 0:
        raise SystemExit("no FMSPC extension in the PCK leaf")
    fmspc = der[i + len(oid) + 2: i + len(oid) + 2 + 6].hex()
    notes["fmspc"] = fmspc
    subj = subprocess.run(["openssl", "x509", "-in", str(ev / "pck-leaf.pem"), "-noout", "-subject", "-issuer", "-dates"], capture_output=True, text=True, check=True).stdout
    (ev / "pck-leaf.txt").write_text(subj)
    urls = {
        "tcb-info.json": f"{PCS}/tdx/certification/v4/tcb?fmspc={fmspc}",
        "qe-identity.json": f"{PCS}/tdx/certification/v4/qe/identity",
        # The Intel SGX Root CA's CRL is published on the certificates host
        # under this name (it is the CRL distribution point every Intel SGX
        # certificate names); the root certificate itself comes with every
        # PCS response's issuer chain and with the quote's PCK chain.
        "intel-sgx-root-ca.crl.der": "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der",
        "pck-crl-platform.pem": f"{PCS}/sgx/certification/v4/pckcrl?ca=platform&encoding=pem",
    }
    headers_kept = {}
    for name, url in urls.items():
        status, headers, body = fetch(url)
        (ev / name).write_bytes(body)
        keep = {k: v for k, v in headers.items() if k.lower().endswith("issuer-chain") or k.lower() in ("request-id", "date")}
        headers_kept[name] = {"status": status, "url": url, "headers": keep}
        for k, v in headers.items():
            if k.lower().endswith("issuer-chain"):
                (ev / (name + ".issuer-chain.pem")).write_bytes(urllib.parse.unquote(v).encode())
    # The root certificate, from the TCB info's issuer chain (last cert).
    chain = (ev / "tcb-info.json.issuer-chain.pem").read_bytes()
    chain_certs = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", chain, re.S)
    (ev / "intel-sgx-root-ca.pem").write_bytes(chain_certs[-1] + b"\n")
    notes["issuer_chain_certificates"] = len(chain_certs)
    notes["pcs"] = headers_kept
    notes["fetched_at"] = datetime.now(timezone.utc).isoformat()
    (ev / "pcs.json").write_text(json.dumps(notes, indent=2) + "\n")
    print(json.dumps({k: v for k, v in notes.items() if k != "pcs"}, indent=2))

if __name__ == "__main__":
    main(sys.argv[1])
