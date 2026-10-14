#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 02d-build-enclave-image-prod.sh — production-mode enclave image build.
#
# Differences from 02-build-enclave-image.sh:
#   * Uses the in-tree vsock-attest Go binary as ENTRYPOINT (not acpctl).
#   * Bakes 02-report-data.bin into /etc/vault-genome/ inside the .eif.
#   * The resulting .eif is intended to run WITHOUT --debug-mode
#     (so PCR0/PCR1/PCR2 will be NON-ZERO and match describe-eif).
#
# Output:
#   ~/vg/enclave-build-prod/
#     ├── vsock-attest                    (compiled Go binary)
#     ├── 02-report-data.bin              (64-byte SHA-512 of manifest)
#     ├── Dockerfile.enclave              (build context)
#     ├── vault-genome-attest-prod.eif    (the enclave image)
#     ├── eif-build-prod.json             (nitro-cli build-enclave output)
#     └── eif-describe-prod.json          (the EXPECTED PCR0 — used by verifier)
#
# Prerequisites:
#   * 01-bootstrap-vm.sh has been run (Go + Docker + nitro-cli installed,
#     ne and docker groups active).
#   * 02-build-enclave-image.sh has been run (so 01-vaultgenome-enclave-build-manifest.json
#     and 02-report-data.bin already exist in ~/vg/enclave-build/).
#     This keeps the workload manifest identical between debug-mode and
#     production-mode runs — the only thing that changes is the enclave
#     binary (acpctl → vsock-attest) and the launch flags.

set -euo pipefail

WORK_DIR="$HOME/vg/enclave-build-prod"
DEBUG_DIR="$HOME/vg/enclave-build"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# Locate the vsock-attest source. Script lives at
# core/scripts/hardware-test/aws-nitro/scripts/, source at
# core/scripts/hardware-test/aws-nitro/vsock-attest/
KIT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VSOCK_SRC_DIR="$KIT_DIR/vsock-attest"
[ -d "$VSOCK_SRC_DIR" ] || { echo "ERROR: vsock-attest source not found at $VSOCK_SRC_DIR"; exit 1; }

# Reuse the manifest + report-data from the debug-mode build (same workload).
[ -f "$DEBUG_DIR/01-vaultgenome-enclave-build-manifest.json" ] || {
  echo "ERROR: $DEBUG_DIR/01-vaultgenome-enclave-build-manifest.json not found."
  echo "       Run 02-build-enclave-image.sh first."
  exit 1
}
[ -f "$DEBUG_DIR/02-report-data.bin" ] || {
  echo "ERROR: $DEBUG_DIR/02-report-data.bin not found."
  exit 1
}
cp "$DEBUG_DIR/01-vaultgenome-enclave-build-manifest.json" .
cp "$DEBUG_DIR/02-report-data.bin" .
cp "$DEBUG_DIR/02-report-data.hex" . 2>/dev/null || true

echo "=== compiling vsock-attest (linux/amd64, static) ==="
cp -r "$VSOCK_SRC_DIR" ./vsock-attest-src
cd vsock-attest-src
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -mod=readonly -trimpath -ldflags="-s -w" -o ../vsock-attest .
cd ..
ls -lh vsock-attest

echo
echo "=== writing Dockerfile.enclave (production-mode) ==="
cat > Dockerfile.enclave <<'EOF'
FROM amazonlinux:2023
RUN mkdir -p /etc/vault-genome /usr/local/bin
COPY vsock-attest /usr/local/bin/vsock-attest
COPY 02-report-data.bin /etc/vault-genome/report-data.bin
RUN chmod +x /usr/local/bin/vsock-attest
ENTRYPOINT ["/usr/local/bin/vsock-attest"]
EOF
cat Dockerfile.enclave

echo
echo "=== building Docker image ==="
docker build -f Dockerfile.enclave -t vault-genome-attest-prod:latest .

echo
echo "=== converting Docker image to .eif (production-mode) ==="
nitro-cli build-enclave \
  --docker-uri vault-genome-attest-prod:latest \
  --output-file vault-genome-attest-prod.eif \
  > eif-build-prod.json 2>&1
cat eif-build-prod.json

echo
echo "=== capturing EXPECTED PCR0 from describe-eif ==="
nitro-cli describe-eif --eif-path vault-genome-attest-prod.eif > eif-describe-prod.json 2>&1

EXPECTED_PCR0=$(jq -r '.Measurements.PCR0' eif-describe-prod.json 2>/dev/null || echo "unknown")
EXPECTED_PCR1=$(jq -r '.Measurements.PCR1' eif-describe-prod.json 2>/dev/null || echo "unknown")
EXPECTED_PCR2=$(jq -r '.Measurements.PCR2' eif-describe-prod.json 2>/dev/null || echo "unknown")

echo "EXPECTED PCR0 (production): $EXPECTED_PCR0"
echo "EXPECTED PCR1: $EXPECTED_PCR1"
echo "EXPECTED PCR2: $EXPECTED_PCR2"

# Save the expected values in a compact JSON for the verifier to consume.
cat > 02d-expected-pcrs.json <<EOF
{
  "expected_pcr0": "$EXPECTED_PCR0",
  "expected_pcr1": "$EXPECTED_PCR1",
  "expected_pcr2": "$EXPECTED_PCR2",
  "eif_path": "$WORK_DIR/vault-genome-attest-prod.eif",
  "build_timestamp_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
cat 02d-expected-pcrs.json

ls -la

echo
echo "=== ✓ production-mode enclave image built ==="
echo "Next: ./scripts/02e-capture-attestation-prod.sh"
