# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The GPU attestation command the azure-cgpu producer runs: collect the
H100's evidence for the nonce (64 hex characters, the last argument)
through NVIDIA's local verifier package (NVML), send it to NVIDIA's Remote
Attestation Service, and print on stdout — nothing else — one JSON object:
NRAS's response (the signed tokens) under "nras", and under "gpu_evidence"
what NRAS was given, per GPU: the SPDM attestation report and the
certificate chain, base64, so the verifier can evaluate the report itself
(ADR 0021). Errors go to stderr with a non-zero exit.

Runs with the local GPU verifier's interpreter, which has NVML and
requests: /usr/local/lib/local_gpu_verifier/.venv/bin/python gpu-token.py <nonce-hex>
"""
import json
import sys

# NVIDIA's verifier package logs to stdout. Only NRAS's response may go
# there, so stdout is swapped for stderr before the package is imported
# (its log handlers bind the stream at import) and restored for the
# response alone.
_stdout = sys.stdout
sys.stdout = sys.stderr

import requests  # noqa: E402
from verifier import cc_admin  # noqa: E402

NRAS = "https://nras.attestation.nvidia.com/v3/attest/gpu"


def main(nonce: str) -> int:
    if len(nonce) != 64 or any(c not in "0123456789abcdefABCDEF" for c in nonce):
        print("nonce must be 64 hex characters", file=sys.stderr)
        return 2
    evidence = cc_admin.collect_gpu_evidence_remote(nonce.lower())
    if not evidence:
        print("no GPU evidence collected (driver not loaded, or the GPU is not in confidential-computing mode)", file=sys.stderr)
        return 1
    payload = {"nonce": nonce.lower(), "arch": "HOPPER", "claims_version": "2.0",
               "evidence_list": [{"evidence": e["evidence"], "certificate": e["certificate"]} for e in evidence]}
    r = requests.post(NRAS, headers={"Content-Type": "application/json"}, data=json.dumps(payload), timeout=90)
    if r.status_code != 200:
        print(f"NRAS: HTTP {r.status_code}: {r.text[:300]}", file=sys.stderr)
        return 1
    _stdout.write(json.dumps({"nras": json.loads(r.text), "gpu_evidence": payload["evidence_list"]}))
    _stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else ""))
