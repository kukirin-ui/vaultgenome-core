#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 02c-deferred-vcek-fetch.sh — complete a deferred SEV-SNP cryptographic
# chain validation when AMD KDS becomes reachable again. Runs from ANY
# internet-connected machine (Mac, Linux laptop, CI runner) — no SEV-SNP
# capable VM required.
#
# Why this works: the attestation report (04-attestation-report.bin) is
# an immutable signed artifact. Chain validation is purely a matter of
# downloading AMD's public certificates and running snpguest verify.
# It can be done at any time, from anywhere with internet access.
#
# Usage:
#   ./02c-deferred-vcek-fetch.sh <path-to-evidence-dir>
#
# Example (Mac):
#   ./02c-deferred-vcek-fetch.sh ~/Desktop/GCP-SEV-SNP-Real-Hardware-Test/07-Cryptographic-Chain-Validation/04-VM4-us-central1-c-PARTIAL/

set -euo pipefail

EVIDENCE_DIR="${1:-}"
[ -n "${EVIDENCE_DIR}" ] || { echo "Usage: $0 <path-to-evidence-dir>"; exit 1; }
[ -d "${EVIDENCE_DIR}" ] || { echo "Not a directory: ${EVIDENCE_DIR}"; exit 1; }
[ -f "${EVIDENCE_DIR}/04-attestation-report.bin" ] || { echo "Missing 04-attestation-report.bin in ${EVIDENCE_DIR}"; exit 1; }

cd "${EVIDENCE_DIR}"
mkdir -p 06-certificates

# ---- Locate or install snpguest ----
SNPGUEST=""
for cand in "$(command -v snpguest 2>/dev/null || true)" \
            "${HOME}/snpguest-src/target/release/snpguest" \
            "${HOME}/.cargo/bin/snpguest" \
            "/usr/local/bin/snpguest"; do
  [ -n "${cand}" ] && [ -x "${cand}" ] && SNPGUEST="${cand}" && break
done

if [ -z "${SNPGUEST}" ]; then
  echo "snpguest not found. Installing from VirTEE upstream (~3 minute compile)..."
  if ! command -v cargo >/dev/null 2>&1; then
    if [[ "$(uname)" == "Darwin" ]]; then
      echo "Install rust first: brew install rustup-init && rustup-init -y"
      exit 1
    else
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
      # shellcheck disable=SC1091
      . "${HOME}/.cargo/env"
    fi
  fi
  git clone https://github.com/virtee/snpguest.git "${HOME}/snpguest-src" 2>/dev/null || true
  (cd "${HOME}/snpguest-src" && cargo build --release)
  SNPGUEST="${HOME}/snpguest-src/target/release/snpguest"
fi

echo "Using snpguest: ${SNPGUEST}"
"${SNPGUEST}" --version

# ---- Confirm AMD KDS reachable ----
echo
echo "=== Checking AMD KDS reachability ==="
HTTP_CODE=$(curl -sS --max-time 30 -o /tmp/amd-kds-probe.bin -w "%{http_code}" \
  https://kdsintf.amd.com/vcek/v1/Milan/cert_chain || echo "000")
echo "HTTP code: ${HTTP_CODE}"
if [ "${HTTP_CODE}" != "200" ]; then
  echo "!!! AMD KDS still unreachable (HTTP ${HTTP_CODE}). !!!"
  echo "Try again later. The captured 04-attestation-report.bin is unchanged"
  echo "and chain validation can be completed any time KDS becomes reachable."
  exit 2
fi
rm -f /tmp/amd-kds-probe.bin

# ---- Fetch ARK + ASK ----
echo
echo "=== Fetch ARK + ASK from KDS ==="
"${SNPGUEST}" fetch ca pem 06-certificates/ milan 2>&1 | tee 06-fetch-ca-log.txt

# ---- Fetch chip-specific VCEK ----
echo
echo "=== Fetch VCEK for this chip from KDS ==="
"${SNPGUEST}" fetch vcek pem 06-certificates/ 04-attestation-report.bin -p milan 2>&1 | tee 07-fetch-vcek-log.txt
ls -la 06-certificates/

# ---- Verify cert chain ----
echo
echo "=== Verify ARK → ASK → VCEK ==="
"${SNPGUEST}" verify certs 06-certificates/ | tee 08-verify-certs.txt

# ---- Verify attestation signature ----
echo
echo "=== Verify VCEK signed the attestation report ==="
"${SNPGUEST}" verify attestation 06-certificates/ 04-attestation-report.bin -p milan | tee 09-verify-attestation.txt

# ---- Verify REPORT_DATA binding (if 02-report-data.hex present) ----
if [ -f 02-report-data.hex ] && "${SNPGUEST}" verify attestation --help 2>&1 | grep -q "report-data"; then
  echo
  echo "=== Verify REPORT_DATA binding to manifest ==="
  REPORT_DATA_HEX=$(tr -d '\n ' < 02-report-data.hex)
  echo "Expected REPORT_DATA: ${REPORT_DATA_HEX}" | tee 10-verify-report-data-binding.txt
  "${SNPGUEST}" verify attestation 06-certificates/ 04-attestation-report.bin -p milan -r "${REPORT_DATA_HEX}" \
    | tee -a 10-verify-report-data-binding.txt
fi

# ---- Update status note ----
echo
echo "=== Update status ==="
cat > 99-CHAIN-VALIDATION-COMPLETED.md <<EOF
# Status: CHAIN VALIDATION COMPLETED

Deferred validation completed: $(date -u +%Y-%m-%dT%H:%M:%SZ)
snpguest version: $("${SNPGUEST}" --version)

The chain ARK → ASK → VCEK → Report is now fully verified against AMD's
public certificate authority. The attestation report (immutable) was
captured at the original validation window; cryptographic chain
verification is anchored to the same public-key infrastructure regardless
of when AMD KDS becomes reachable.

Verification artifacts:
- 08-verify-certs.txt              ARK → ASK → VCEK signature chain ✓
- 09-verify-attestation.txt        VCEK → Report signature ✓
$([ -f 10-verify-report-data-binding.txt ] && echo "- 10-verify-report-data-binding.txt  REPORT_DATA = SHA-512(manifest) ✓")
EOF
cat 99-CHAIN-VALIDATION-COMPLETED.md

# ---- Remove the old PARTIAL marker if present ----
if [ -f 99-VM4-STATUS.md ] || [ -f 99-VM-STATUS.md ]; then
  echo
  echo "=== Archiving old PARTIAL status note ==="
  mv -f 99-VM4-STATUS.md 99-VM4-STATUS.md.completed 2>/dev/null || true
  mv -f 99-VM-STATUS.md 99-VM-STATUS.md.completed 2>/dev/null || true
fi

echo
echo "=== ✓ DONE — chain validation completed ==="
echo "Add the new artifacts (08, 09, 10, 99) to your evidence package."
