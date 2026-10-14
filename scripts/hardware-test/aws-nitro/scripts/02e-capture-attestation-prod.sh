#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 02e-capture-attestation-prod.sh — production-mode attestation capture.
#
# Production-mode enclaves do NOT expose console (--debug-mode is off),
# so the attestation must travel back to the parent over vsock instead.
#
# This script:
#   1. Verifies 02d-build-enclave-image-prod.sh has produced the .eif.
#   2. Starts the parent-side vsock listener (scripts/vsock-receive.py)
#      in the background.
#   3. Launches the enclave with `nitro-cli run-enclave` WITHOUT --debug-mode.
#   4. Waits for the listener to receive + write the attestation document.
#   5. Terminates the enclave cleanly.
#   6. Confirms the captured PCR0 in the attestation MATCHES the
#      EXPECTED PCR0 captured by 02d (proving running enclave content
#      equals the built .eif).
#
# Output files (in $EVIDENCE_DIR):
#   04-attestation-document.bin       — raw COSE_Sign1 (received via vsock)
#   04-attestation-document.b64       — base64 transport encoding
#   04-enclave-launch.json            — nitro-cli run-enclave output
#   04-enclaves-state.json            — describe-enclaves snapshot mid-run
#   05-attestation-parsed.json        — parsed module_id/pcr0/user_data/etc.
#   06-pcr-binding-check.json         — PCR0 expected vs got + PASS/FAIL
#
# Run from your home dir (~) so paths resolve.

set -euo pipefail

PROD_DIR="$HOME/vg/enclave-build-prod"
EVIDENCE_DIR="$HOME/vg/attestation-validation/$(hostname)"
EIF="$PROD_DIR/vault-genome-attest-prod.eif"
EXPECTED_PCRS_JSON="$PROD_DIR/02d-expected-pcrs.json"

[ -f "$EIF" ] || { echo "ERROR: $EIF not found. Run 02d-build-enclave-image-prod.sh first."; exit 1; }
[ -f "$EXPECTED_PCRS_JSON" ] || { echo "ERROR: $EXPECTED_PCRS_JSON not found."; exit 1; }

mkdir -p "$EVIDENCE_DIR"
cd "$EVIDENCE_DIR"

# Reuse report-data + manifest from the unified build dir
cp "$HOME/vg/enclave-build/02-report-data.bin" 02-report-data.bin
cp "$HOME/vg/enclave-build/02-report-data.hex" 02-report-data.hex
cp "$HOME/vg/enclave-build/01-vaultgenome-enclave-build-manifest.json" 01-vaultgenome-enclave-build-manifest.json
cp "$EXPECTED_PCRS_JSON" 02d-expected-pcrs.json

KIT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LISTENER="$KIT_DIR/scripts/vsock-receive.py"
[ -f "$LISTENER" ] || { echo "ERROR: $LISTENER not found."; exit 1; }

echo "=== verifying nitro-cli + python AF_VSOCK ==="
nitro-cli --version
python3 -c 'import socket; assert hasattr(socket,"AF_VSOCK"), "AF_VSOCK missing"; print("AF_VSOCK OK")'

# Make sure no stale enclave is running
echo
echo "=== ensuring no enclaves are currently running ==="
sudo nitro-cli describe-enclaves > 03-enclaves-state-pre.json
NUM_PRE=$(jq 'length' 03-enclaves-state-pre.json)
if [ "$NUM_PRE" -gt 0 ]; then
  echo "Found $NUM_PRE running enclave(s); terminating first."
  jq -r '.[].EnclaveID' 03-enclaves-state-pre.json | while read -r EID; do
    sudo nitro-cli terminate-enclave --enclave-id "$EID"
  done
fi

# Start the listener in the background BEFORE launching the enclave.
echo
echo "=== starting parent vsock listener ==="
python3 "$LISTENER" 04-attestation-document.bin --port 5005 --timeout 180 \
  > vsock-receive.log 2>&1 &
LISTENER_PID=$!
echo "listener PID: $LISTENER_PID"
sleep 1

if ! kill -0 "$LISTENER_PID" 2>/dev/null; then
  echo "ERROR: listener exited prematurely. Log:"; cat vsock-receive.log
  exit 1
fi

echo
echo "=== launching enclave (production-mode, NO --debug-mode) ==="
sudo nitro-cli run-enclave \
  --eif-path "$EIF" \
  --memory 4096 --cpu-count 2 --enclave-cid 16 \
  > 04-enclave-launch.json 2>&1
cat 04-enclave-launch.json

ENCLAVE_ID=$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
echo "Enclave ID: $ENCLAVE_ID"

sleep 2
sudo nitro-cli describe-enclaves > 03-enclaves-state.json   # the running enclave, PCRs included
echo "enclave state captured: $(jq -r '.[0].State // "none"' 03-enclaves-state.json)"

echo
echo "=== waiting for listener to receive attestation (≤180s) ==="
if ! wait "$LISTENER_PID"; then
  echo "ERROR: listener exited non-zero. Log:"; cat vsock-receive.log
  sudo nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID" || true
  exit 1
fi
cat vsock-receive.log

echo
echo "=== terminating enclave ==="
# vsock-attest exits once the document is delivered, so by now the enclave
# has usually ended on its own and terminate-enclave reports E39 (no
# enclave process to connect to). That is the expected end of a
# production-mode capture, not a failure: the running state captured
# above (03-enclaves-state.json, PCRs included) and the received document
# are the record. The state after is recorded too.
sudo nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID" > 03-enclave-terminate.json 2>&1 \
  || echo "terminate-enclave: the enclave had already exited (vsock-attest exits after sending); see 03-enclave-terminate.json"
sudo nitro-cli describe-enclaves > 03-enclaves-state-post.json
echo "enclaves after: $(jq 'length' 03-enclaves-state-post.json)"

ls -la 04-attestation-document.bin
ATT_SIZE=$(stat -c '%s' 04-attestation-document.bin 2>/dev/null || stat -f '%z' 04-attestation-document.bin)
echo "attestation document: $ATT_SIZE bytes"

# Base64 transport-encode for portability
base64 -w 76 04-attestation-document.bin > 04-attestation-document.b64 2>/dev/null \
  || base64 04-attestation-document.bin > 04-attestation-document.b64

echo
echo "=== parsing attestation + PCR binding check ==="
python3 - <<'PYEOF'
import cbor2
import json

with open("04-attestation-document.bin", "rb") as f:
    raw = f.read()
_, _, payload, _ = cbor2.loads(raw)
doc = cbor2.loads(payload)

pcrs = doc.get("pcrs", {})
pcr0 = pcrs.get(0, b"").hex()
pcr1 = pcrs.get(1, b"").hex()
pcr2 = pcrs.get(2, b"").hex()

with open("02d-expected-pcrs.json") as f:
    expected = json.load(f)

# Lowercase compare to be safe
exp0 = (expected.get("expected_pcr0") or "").lower()
exp1 = (expected.get("expected_pcr1") or "").lower()
exp2 = (expected.get("expected_pcr2") or "").lower()

zeros_pcr0 = all(c == "0" for c in pcr0)
zeros_pcr1 = all(c == "0" for c in pcr1)
zeros_pcr2 = all(c == "0" for c in pcr2)

result = {
  "module_id": doc.get("module_id"),
  "timestamp_ms": doc.get("timestamp"),
  "user_data": doc.get("user_data", b"").hex(),
  "captured_pcr0": pcr0,
  "captured_pcr1": pcr1,
  "captured_pcr2": pcr2,
  "expected_pcr0": exp0,
  "expected_pcr1": exp1,
  "expected_pcr2": exp2,
  "pcr0_nonzero": not zeros_pcr0,
  "pcr1_nonzero": not zeros_pcr1,
  "pcr2_nonzero": not zeros_pcr2,
  "pcr0_matches_expected": pcr0.lower() == exp0,
  "pcr1_matches_expected": pcr1.lower() == exp1,
  "pcr2_matches_expected": pcr2.lower() == exp2,
}
result["all_pcr_checks_pass"] = (
  result["pcr0_nonzero"] and result["pcr1_nonzero"] and result["pcr2_nonzero"]
  and result["pcr0_matches_expected"]
  and result["pcr1_matches_expected"]
  and result["pcr2_matches_expected"]
)

with open("06-pcr-binding-check.json", "w") as f:
  json.dump(result, f, indent=2)
with open("05-attestation-parsed.json", "w") as f:
  json.dump({
    "module_id": result["module_id"],
    "digest": doc.get("digest"),
    "timestamp_ms": result["timestamp_ms"],
    "pcr0": pcr0,
    "pcr1": pcr1,
    "pcr2": pcr2,
    "user_data": result["user_data"],
    "cabundle_count": len(doc.get("cabundle", [])),
    "production_mode": True,
  }, f, indent=2)

print(f"Module ID:            {result['module_id']}")
print(f"PCR0 captured:        {pcr0}")
print(f"PCR0 expected:        {exp0}")
print(f"PCR0 nonzero:         {'✓' if result['pcr0_nonzero'] else '✗'}")
print(f"PCR0 matches expected: {'✓' if result['pcr0_matches_expected'] else '✗'}")
print(f"PCR1 nonzero:         {'✓' if result['pcr1_nonzero'] else '✗'}")
print(f"PCR1 matches expected: {'✓' if result['pcr1_matches_expected'] else '✗'}")
print(f"PCR2 nonzero:         {'✓' if result['pcr2_nonzero'] else '✗'}")
print(f"PCR2 matches expected: {'✓' if result['pcr2_matches_expected'] else '✗'}")
print(f"All PCR checks pass:  {result['all_pcr_checks_pass']}")
PYEOF

echo
echo "=== VM identity (IMDSv2) ==="
# 07-cross-vm-matrix.sh reads these lines; the debug path wrote them in
# 02-capture-attestation.sh, the production path writes its own.
TOKEN=$(curl -fsS -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
md() { curl -fsS -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/$1"; }
cat > 00-vm-identity.txt <<EOF
Instance ID: $(md instance-id)
Region:      $(md placement/region)
Availability Zone: $(md placement/availability-zone)
Machine type: $(md instance-type)
Kernel:      $(uname -r)
Enclave mode: production (no --debug-mode, vsock-attest)
Module ID:   $(jq -r '.module_id' 05-attestation-parsed.json)
Captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
cat 00-vm-identity.txt

echo
echo "=== ✓ production-mode attestation captured ==="
echo "Next: ./scripts/02c-fetch-nitro-root-ca.sh, then 08-normalize-attestation-output.py on the laptop"
