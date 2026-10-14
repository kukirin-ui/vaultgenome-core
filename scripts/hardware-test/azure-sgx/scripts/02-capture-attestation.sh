#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 02-capture-attestation.sh — generate an Intel SGX quote on this Azure
# DCsv3 VM. Uses Open Enclave SDK's oeutil to launch a tiny test enclave
# and produce an evidence (quote) buffer. Writes the raw quote to
# ~/vg/evidence/sgx-quote.bin.
#
# This is the RAW capture — for the full Intel SGX Quote → PCK → SGX
# Root CA chain validation plus REPORT_DATA workload binding, run
# 02b-cryptographic-attestation.sh. For the Microsoft MAA JWT
# (Azure-specific 2nd verifier), run 02f-capture-maa-jwt.sh.

set -euo pipefail

cd ~/vg
mkdir -p evidence

# Locate oeutil (Open Enclave's evidence/quote tool)
OEUTIL=""
for cand in /opt/openenclave/bin/oeutil /usr/local/bin/oeutil "$(command -v oeutil 2>/dev/null)"; do
  if [ -x "${cand}" ]; then OEUTIL="${cand}"; break; fi
done

if [ -z "${OEUTIL}" ]; then
  echo "WARNING: oeutil not found. Falling back to a minimal quote-via-aesmd path."
  echo "         If this VM was bootstrapped without Open Enclave, install with:"
  echo "         sudo apt-get install open-enclave"
  echo
  echo "Attempting quote via /dev/sgx_enclave smoke test instead..."
  if [ -c /dev/sgx_enclave ] && [ -c /dev/sgx_provision ]; then
    {
      echo "=== SGX device smoke test ==="
      echo "/dev/sgx_enclave:    $(stat -c '%A %u:%g %s bytes' /dev/sgx_enclave)"
      echo "/dev/sgx_provision:  $(stat -c '%A %u:%g %s bytes' /dev/sgx_provision)"
      echo "captured_at:         $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } | tee evidence/sgx-device-smoke.txt
    echo
    echo "Quote generation requires oeutil. See 02b-cryptographic-attestation.sh"
    echo "which will retry with a full enclave path."
    exit 0
  fi
  echo "ERROR: Cannot find SGX devices either. Aborting."
  exit 1
fi

echo "=== using oeutil at ${OEUTIL} ==="
"${OEUTIL}" --help >/dev/null 2>&1 || true

echo
echo "=== generate SGX evidence (quote + claims) via oeutil ==="
# `oeutil generate-evidence` produces a binary evidence buffer
# containing the quote + custom claims. The flag "-f sgx_ecdsa" requests
# DCAP/ECDSA quote (vs deprecated EPID).
if "${OEUTIL}" generate-evidence -f sgx_ecdsa --out-file evidence/sgx-quote.bin 2>&1 | tee evidence/sgx-quote-generation.txt; then
  echo "✓ quote generated"
else
  echo "ERROR: oeutil generate-evidence failed. See evidence/sgx-quote-generation.txt"
  echo "       Common causes: aesmd not running, /dev/sgx_provision permissions,"
  echo "                      missing az-dcap-client for collateral."
  exit 1
fi

echo
echo "=== file metadata ==="
ls -lh evidence/sgx-quote.bin
echo "size in bytes: $(stat -c %s evidence/sgx-quote.bin)"
echo "sha256: $(sha256sum evidence/sgx-quote.bin | awk '{print $1}')"

echo
echo "=== first 96 bytes (quote header preview) ==="
xxd -l 96 evidence/sgx-quote.bin | tee evidence/sgx-quote.hex

echo
echo "=== capture kernel SGX log too ==="
journalctl -k --no-pager 2>/dev/null | grep -iE "sgx|enclave" | head -20 \
  > evidence/kernel-sgx.txt
cat evidence/kernel-sgx.txt

echo
echo "=== done. raw quote captured ==="
echo "Next:"
echo "  ./scripts/02b-cryptographic-attestation.sh  # Intel chain validation"
echo "  ./scripts/02f-capture-maa-jwt.sh            # Microsoft MAA JWT"
echo "  ./scripts/03-demo1-single-bundle.sh         # Demo 1 workload"
