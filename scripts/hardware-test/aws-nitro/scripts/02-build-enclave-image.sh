#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 02-build-enclave-image.sh — build the Vault Genome enclave image (.eif)
# from a Docker image, capture its PCR0 (SHA-384 of the enclave content),
# and write the PCR record to ~/vg/enclave-build/.
#
# The .eif (Enclave Image Format) is the immutable artifact that boots
# inside the Nitro hypervisor. Its SHA-384 (PCR0) is what AWS KMS keys
# can be conditionally bound to — meaning a wrapped key can be released
# only to an enclave whose image hashes to a specific value.
#
# This script also produces the build manifest that we'll later bind
# into the attestation report's user_data field (analog of REPORT_DATA
# in AMD SEV-SNP).
#
# Prerequisites: 01-bootstrap-vm.sh has been run, user has logged out
# and back in (so ne + docker groups are active).

set -euo pipefail

WORK_DIR="$HOME/vg/enclave-build"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

echo "=== verifying nitro-cli + docker accessible ==="
nitro-cli --version
docker --version

echo
echo "=== building Vault Genome enclave Docker image ==="
# We use a minimal Alpine-based image with our acpctl Go binary inside.
# In production, this would be the customer's signed image; for the
# hardware test, we build it from acpctl source on the fly.
cat > Dockerfile.enclave <<'EOF'
# Stage 1: build acpctl from source
FROM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS builder
RUN apk add --no-cache git build-base
WORKDIR /src
# Copy our acpctl source. In a real workflow this is mounted in.
COPY . .
RUN cd cmd/acpctl && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/acpctl .

# Stage 2: minimal runtime
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache ca-certificates openssl
COPY --from=builder /out/acpctl /usr/local/bin/acpctl
# Enclave entrypoint: capture attestation report on demand from /dev/nsm
# and respond over vsock. For the hardware test we just exec acpctl
# tee status to verify the binary works inside the enclave context.
ENTRYPOINT ["/usr/local/bin/acpctl"]
CMD ["tee", "status", "--provider", "aws-nitro"]
EOF

# Build context = the core/ directory (acpctl source).
# We assume this script runs from core/scripts/hardware-test/aws-nitro/scripts/
CORE_DIR="$(cd "$(dirname "$0")/../../../.." && pwd)"
echo "Build context: $CORE_DIR"
docker build -f Dockerfile.enclave -t vault-genome/acpctl:enclave "$CORE_DIR"

echo
echo "=== converting Docker image to .eif (Enclave Image Format) ==="
nitro-cli build-enclave \
  --docker-uri vault-genome/acpctl:enclave \
  --output-file vault-genome.eif \
  > eif-build-output.json 2>&1

cat eif-build-output.json

echo
echo "=== capturing PCR measurements from .eif ==="
# describe-eif emits PCR0/PCR1/PCR2 measurements.
nitro-cli describe-eif --eif-path vault-genome.eif > eif-describe.json 2>&1
cat eif-describe.json

# Extract PCR0 specifically (SHA-384 of the entire enclave image —
# this is what KMS keys can be policy-bound to).
PCR0=$(jq -r '.Measurements.PCR0' eif-describe.json 2>/dev/null || echo "unknown")
PCR1=$(jq -r '.Measurements.PCR1' eif-describe.json 2>/dev/null || echo "unknown")
PCR2=$(jq -r '.Measurements.PCR2' eif-describe.json 2>/dev/null || echo "unknown")

echo
echo "=== build manifest ==="
cat > 01-vaultgenome-enclave-build-manifest.json <<EOF
{
  "vault_genome_version": "1.0.0",
  "platform": "aws-nitro-enclaves",
  "enclave_image_path": "$WORK_DIR/vault-genome.eif",
  "enclave_image_sha384_pcr0": "$PCR0",
  "enclave_kernel_pcr1": "$PCR1",
  "enclave_application_pcr2": "$PCR2",
  "build_date_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "docker_image": "vault-genome/acpctl:enclave",
  "build_host": "$(hostname)"
}
EOF
cat 01-vaultgenome-enclave-build-manifest.json

# REPORT_DATA = SHA-512 of build manifest. This is what we'll embed in
# the attestation document's user_data field, so the chip's signature
# covers a hash of THIS specific build.
sha512sum 01-vaultgenome-enclave-build-manifest.json | awk '{print $1}' > 02-report-data.hex
python3 -c 'import sys; open("02-report-data.bin", "wb").write(bytes.fromhex(open("02-report-data.hex").read().strip()))'

echo
echo "=== REPORT_DATA (SHA-512 of manifest) ==="
cat 02-report-data.hex
echo

ls -la

echo
echo "=== ✓ enclave image built ==="
echo "PCR0 (image hash): $PCR0"
echo "Next: ./scripts/02-capture-attestation.sh"
