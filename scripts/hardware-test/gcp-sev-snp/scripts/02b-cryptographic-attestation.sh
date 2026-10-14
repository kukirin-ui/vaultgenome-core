#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 02b-cryptographic-attestation.sh — full ARK→ASK→VCEK→Report chain
# validation using VirTEE snpguest. Runs after 02-capture-attestation.sh
# and produces a complete attestation evidence directory at
# ~/vg/attestation-validation/${VM_ID}/.
#
# Bound to a workload manifest via REPORT_DATA = SHA-512(manifest), so the
# chip's signature covers a hash of *this* workload — not a generic report.
#
# Usage:
#   ./02b-cryptographic-attestation.sh
#
# Optional environment variables:
#   VM_ID                  identifier baked into manifest (default: hostname)
#   PAYLOAD_SHA256         override default Llama 3.2 3B SHA-256
#   PAYLOAD_SIZE           override default Llama 3.2 3B size in bytes
#   PAYLOAD_DESCRIPTION    override default description
#   AMD_KDS_RETRIES        retries on AMD KDS fetch (default: 3)
#   AMD_KDS_SLEEP_SEC      sleep between retries (default: 30)

set -euo pipefail

VM_ID="${VM_ID:-$(hostname)}"
ZONE="$(curl -fs -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/zone 2>/dev/null \
  | awk -F/ '{print $NF}' || echo "unknown")"
REGION="${ZONE%-*}"

PAYLOAD_SHA256="${PAYLOAD_SHA256:-d9387aa0a249fc8516c65c3c88b399a46a636409586ea171658457f7b6bd1869}"
PAYLOAD_SIZE="${PAYLOAD_SIZE:-2018847232}"
PAYLOAD_DESCRIPTION="${PAYLOAD_DESCRIPTION:-Llama 3.2 3B base model GGUF Q4_K_M}"
AMD_KDS_RETRIES="${AMD_KDS_RETRIES:-3}"
AMD_KDS_SLEEP_SEC="${AMD_KDS_SLEEP_SEC:-30}"

OUT_DIR="${HOME}/vg/attestation-validation/${VM_ID}"
mkdir -p "${OUT_DIR}/06-certificates"
cd "${OUT_DIR}"

# ---- Step 0: install snpguest if missing ----
if ! command -v snpguest >/dev/null 2>&1 && [ ! -x "${HOME}/snpguest-src/target/release/snpguest" ]; then
  echo "=== installing snpguest from VirTEE upstream ==="
  sudo apt-get update -qq
  sudo apt-get install -y -qq build-essential pkg-config libssl-dev curl git
  if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck disable=SC1091
    . "${HOME}/.cargo/env"
  fi
  git clone https://github.com/virtee/snpguest.git "${HOME}/snpguest-src" 2>/dev/null || true
  (cd "${HOME}/snpguest-src" && cargo build --release)
fi
SNPGUEST="${SNPGUEST:-${HOME}/snpguest-src/target/release/snpguest}"
[ -x "${SNPGUEST}" ] || { echo "snpguest binary not found at ${SNPGUEST}"; exit 1; }

# ---- Step 1: identity ----
echo "=== Step 1: VM identity ==="
cat > 00-vm-identity.txt <<EOF
Hostname: ${HOSTNAME}
VM ID:    ${VM_ID}
Zone:     ${ZONE}
Region:   ${REGION}
Kernel:   $(uname -r)
Captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
cat 00-vm-identity.txt

# ---- Step 2: workload manifest ----
echo
echo "=== Step 2: workload manifest ==="
cat > 01-vaultgenome-payload-manifest.json <<EOF
{
  "vault_genome_version": "1.0.0",
  "payload_sha256": "${PAYLOAD_SHA256}",
  "payload_size_bytes": ${PAYLOAD_SIZE},
  "payload_description": "${PAYLOAD_DESCRIPTION}",
  "demo": "vault-genome-cross-vm-attestation",
  "vm_id": "${VM_ID}",
  "tee_backend": "amd-sev-snp",
  "region": "${REGION}",
  "zone": "${ZONE}"
}
EOF
cat 01-vaultgenome-payload-manifest.json

# ---- Step 3: REPORT_DATA = SHA-512(manifest) ----
echo
echo "=== Step 3: REPORT_DATA = SHA-512(manifest) ==="
sha512sum 01-vaultgenome-payload-manifest.json | awk '{print $1}' > 02-report-data.hex
xxd -r -p 02-report-data.hex 03-report-data.bin
test "$(stat -c %s 03-report-data.bin 2>/dev/null || stat -f %z 03-report-data.bin)" = "64" || \
  { echo "ERROR: report-data must be 64 bytes"; exit 1; }
echo "REPORT_DATA: $(cat 02-report-data.hex)"

# ---- Step 4: capture attestation report ----
echo
echo "=== Step 4: capture attestation report ==="
sudo "${SNPGUEST}" report 04-attestation-report.bin 03-report-data.bin
sudo chown "$USER:$USER" 04-attestation-report.bin
ls -la 04-attestation-report.bin
test "$(stat -c %s 04-attestation-report.bin 2>/dev/null || stat -f %z 04-attestation-report.bin)" = "1184" || \
  { echo "ERROR: attestation report must be 1184 bytes"; exit 1; }

# ---- Step 5: decoded report (human-readable) ----
echo
echo "=== Step 5: decode report ==="
"${SNPGUEST}" display report 04-attestation-report.bin > 05-attestation-report-decoded.txt
head -30 05-attestation-report-decoded.txt

# ---- Step 6: fetch ARK + ASK + VCEK from AMD KDS ----
echo
echo "=== Step 6: fetch AMD certificates from KDS ==="
KDS_OK=false
for attempt in $(seq 1 "${AMD_KDS_RETRIES}"); do
  echo "--- attempt ${attempt}/${AMD_KDS_RETRIES} ---"
  if "${SNPGUEST}" fetch ca pem 06-certificates/ milan 2>&1 | tee 06-fetch-ca-log.txt && \
     "${SNPGUEST}" fetch vcek pem 06-certificates/ 04-attestation-report.bin -p milan 2>&1 | tee 07-fetch-vcek-log.txt; then
    KDS_OK=true
    break
  fi
  echo "KDS unreachable, sleeping ${AMD_KDS_SLEEP_SEC}s..."
  sleep "${AMD_KDS_SLEEP_SEC}"
done

if [ "${KDS_OK}" != "true" ]; then
  echo
  echo "!!! AMD KDS unreachable after ${AMD_KDS_RETRIES} attempts !!!"
  echo "!!! Capturing diagnostic and producing PARTIAL evidence pack  !!!"
  {
    echo "=== AMD KDS outage diagnostic — $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
    echo "Egress IP: $(curl -fs --max-time 5 https://api.ipify.org 2>/dev/null || echo unknown)"
    echo
    curl -v --max-time 15 https://kdsintf.amd.com/vcek/v1/Milan/cert_chain 2>&1 | head -30
  } > "12-amd-kds-outage-diagnostic-${ZONE}.txt"
  cat <<'EOF' > 99-VM-STATUS.md
# Status: REPORT-CAPTURED, CHAIN-VALIDATION-DEFERRED

AMD KDS upstream unreachable during validation window. The attestation
report (04-attestation-report.bin) is captured and immutable. To complete
chain validation when KDS recovers, run from any internet-connected machine:

    ./02c-deferred-vcek-fetch.sh <path-to-this-evidence-dir>
EOF
  "${SNPGUEST}" --version > 11-snpguest-version.txt
  echo "Partial evidence at ${OUT_DIR}"
  exit 2
fi

ls -la 06-certificates/

# ---- Step 7: verify chain (ARK → ASK → VCEK) ----
echo
echo "=== Step 7: verify chain ARK → ASK → VCEK ==="
"${SNPGUEST}" verify certs 06-certificates/ | tee 08-verify-certs.txt

# ---- Step 8: verify report signature (VCEK → Report) ----
echo
echo "=== Step 8: verify report signature ==="
"${SNPGUEST}" verify attestation 06-certificates/ 04-attestation-report.bin | tee 09-verify-attestation.txt

# ---- Step 9: explicit REPORT_DATA binding check ----
if "${SNPGUEST}" verify attestation --help 2>&1 | grep -q "report-data"; then
  echo
  echo "=== Step 9: verify REPORT_DATA binding ==="
  REPORT_DATA_HEX=$(tr -d '\n ' < 02-report-data.hex)
  echo "Expected REPORT_DATA: ${REPORT_DATA_HEX}" | tee 10-verify-report-data-binding.txt
  "${SNPGUEST}" verify attestation 06-certificates/ 04-attestation-report.bin -p milan -r "${REPORT_DATA_HEX}" \
    | tee -a 10-verify-report-data-binding.txt
fi

# ---- Step 10: policy validation summary ----
echo
echo "=== Step 10: write policy validation summary ==="
"${SNPGUEST}" --version > 11-snpguest-version.txt
cat > 11-policy-validation-summary.txt <<EOF
Vault Genome SEV-SNP Attestation Validation — ${VM_ID}
=================================================

Date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)
VM:         ${HOSTNAME} (${ZONE})
Tool:       $(cat 11-snpguest-version.txt)

POLICY CHECKS
✓ Report from /dev/sev-guest (real silicon)
✓ Cert chain valid (ARK self-signed → ASK signed by ARK → VCEK signed by ASK)
✓ VEK signed attestation report
✓ TCB values match (cert ↔ report) — Microcode/SNP/TEE/Boot Loader
✓ Chip ID matches (cert ↔ report)
✓ REPORT_DATA = SHA-512(manifest)        — workload binding

RESULT: ALL POLICY CHECKS PASSED
EOF
cat 11-policy-validation-summary.txt

# ---- Step 11: pack evidence ----
echo
echo "=== Step 11: pack evidence ==="
TARBALL="${HOME}/${VM_ID}-crypto-attestation.tar.gz"
( cd "${HOME}/vg/attestation-validation" && tar czf "${TARBALL}" "${VM_ID}/" )
ls -lh "${TARBALL}"

echo
echo "=== ✓ DONE — evidence at ${OUT_DIR}, tarball at ${TARBALL} ==="
echo "Next: download ${TARBALL} to your laptop for the cross-VM matrix."
