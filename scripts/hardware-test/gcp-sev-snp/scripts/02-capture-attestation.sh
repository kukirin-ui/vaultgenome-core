#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 02-capture-attestation.sh — capture an AMD SEV-SNP attestation report
# directly from /dev/sev-guest via ioctl. Writes a 1184-byte raw report
# to ~/vg/evidence/snp-attestation-report.bin and a hex-dump preview
# to ~/vg/evidence/snp-attestation-report.txt.

set -euo pipefail

cd ~/vg

# Build snpreport.go (in this repo's scripts/ dir) into a small binary.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ ! -x ./snpreport ]; then
  cp "$SCRIPT_DIR/snpreport.go" ./snpreport.go
  go build -o snpreport snpreport.go
fi

mkdir -p evidence

echo "=== requesting AMD SEV-SNP attestation report from /dev/sev-guest ==="
sudo ./snpreport evidence/snp-attestation-report.bin
sudo chown "$USER:$USER" evidence/snp-attestation-report.bin

echo
echo "=== file metadata ==="
ls -lh evidence/snp-attestation-report.bin
echo "size in bytes (should be 1184): $(stat -c %s evidence/snp-attestation-report.bin)"
echo "sha256: $(sha256sum evidence/snp-attestation-report.bin | awk '{print $1}')"

echo
echo "=== first 96 bytes (response header + start of report) ==="
xxd -l 96 evidence/snp-attestation-report.bin | tee evidence/snp-attestation-report.hex

echo
echo "=== capture kernel SEV log too ==="
journalctl -k --no-pager 2>/dev/null | grep -iE "sev|memory encryption" | head -10 \
  > evidence/kernel-sev.txt
cat evidence/kernel-sev.txt

echo
echo "=== done. attestation captured ==="
echo "Next: ./scripts/03-demo1-single-bundle.sh"
