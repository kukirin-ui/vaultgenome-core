# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Collect the H100's attestation evidence for a nonce through NVIDIA's
local verifier package (NVML), send it to NVIDIA's Remote Attestation
Service, and write everything down: the raw evidence (attestation report
and certificate chain), the EAT tokens NRAS returned, the JWKS they verify
under, and a decoded copy of the claims — no verification here; the
verifier in internal/shared/tee does that, offline, from these files.

Runs with the local GPU verifier's own interpreter, which has NVML and
requests: /usr/local/lib/local_gpu_verifier/.venv/bin/python nras_attest.py
<nonce-hex-64> <out-dir>
"""
import base64
import json
import sys
import time

import requests
from verifier import cc_admin

NRAS = "https://nras.attestation.nvidia.com/v3/attest/gpu"
JWKS = "https://nras.attestation.nvidia.com/.well-known/jwks.json"


def b64url_json(part: str) -> dict:
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def main(nonce: str, out: str) -> int:
    evidence = cc_admin.collect_gpu_evidence_remote(nonce)
    if not evidence:
        print("no GPU evidence collected", file=sys.stderr)
        return 1
    with open(f"{out}/gpu-evidence.json", "w") as f:
        json.dump({"nonce": nonce, "arch": "HOPPER", "evidence_list": evidence}, f, indent=1)
    for i, e in enumerate(evidence):
        with open(f"{out}/gpu{i}-attestation-report.bin", "wb") as f:
            f.write(base64.b64decode(e["evidence"]))
        with open(f"{out}/gpu{i}-cert-chain.pem", "wb") as f:
            f.write(base64.b64decode(e["certificate"]))
    payload = {"nonce": nonce, "evidence_list": [{"evidence": e["evidence"], "certificate": e["certificate"]} for e in evidence],
               "arch": "HOPPER", "claims_version": "2.0"}
    t0 = time.time()
    r = requests.post(NRAS, headers={"Content-Type": "application/json"}, data=json.dumps(payload), timeout=60)
    elapsed = time.time() - t0
    with open(f"{out}/nras-response.json", "w") as f:
        f.write(r.text)
    print(f"NRAS {NRAS}: HTTP {r.status_code} in {elapsed:.2f}s")
    if r.status_code != 200:
        return 1
    token = r.json()
    overall = token[0][1]
    detached = token[1]
    decoded = {"overall": {"header": b64url_json(overall.split(".")[0]), "claims": b64url_json(overall.split(".")[1])},
               "detached": {k: {"header": b64url_json(v.split(".")[0]), "claims": b64url_json(v.split(".")[1])} for k, v in detached.items()}}
    with open(f"{out}/nras-claims-decoded.json", "w") as f:
        json.dump(decoded, f, indent=1)
    jwks = requests.get(JWKS, timeout=30)
    with open(f"{out}/nras-jwks.json", "w") as f:
        f.write(jwks.text)
    c = decoded["overall"]["claims"]
    print("overall:", {k: c.get(k) for k in ("iss", "x-nvidia-ver", "x-nvidia-overall-att-result", "eat_nonce", "exp")})
    for k, v in decoded["detached"].items():
        cl = v["claims"]
        print(k, {kk: cl.get(kk) for kk in ("measres", "x-nvidia-gpu-attestation-report-nonce-match", "x-nvidia-gpu-driver-version",
                                            "x-nvidia-gpu-vbios-version", "hwmodel", "secboot", "dbgstat", "x-nvidia-gpu-arch-check")})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
