#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 02c-fetch-nitro-root-ca.sh — fetch the AWS Nitro Enclaves Root CA G1 into
# the evidence directory and check it against two published values:
#   * the archive's SHA-256, from
#     https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
#   * the root certificate's SHA-256 fingerprint
# Either mismatch is fatal. The PEM is what 08-normalize-attestation-
# output.py anchors the captured document's certificate chain to, so the
# anchor travels with the evidence and the check is on record
# (06-certificates/root-ca-check.json).
#
# Run after 02e-capture-attestation-prod.sh, from the parent host.

set -euo pipefail

EVIDENCE_DIR="$HOME/vg/attestation-validation/$(hostname)"
mkdir -p "$EVIDENCE_DIR/06-certificates"
cd "$EVIDENCE_DIR/06-certificates"

ROOT_CA_URL="https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip"
ROOT_CA_ZIP_SHA256="8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c"
ROOT_CA_CERT_FINGERPRINT="641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"

echo "=== fetching $ROOT_CA_URL ==="
curl -fsSL "$ROOT_CA_URL" -o aws-nitro-root.zip
echo "${ROOT_CA_ZIP_SHA256}  aws-nitro-root.zip" | sha256sum -c -
python3 -c 'import zipfile; z=zipfile.ZipFile("aws-nitro-root.zip"); n=[i for i in z.namelist() if i.endswith("root.pem")]; assert len(n)==1, z.namelist(); open("aws-nitro-root.pem","wb").write(z.read(n[0]))'

ACTUAL_FP=$(openssl x509 -in aws-nitro-root.pem -noout -fingerprint -sha256 | sed 's/^.*=//; s/://g' | tr 'A-F' 'a-f')
SUBJECT=$(openssl x509 -in aws-nitro-root.pem -noout -subject | sed 's/^subject=//')
NOT_AFTER=$(openssl x509 -in aws-nitro-root.pem -noout -enddate | sed 's/^notAfter=//')
if [ "$ACTUAL_FP" != "$ROOT_CA_CERT_FINGERPRINT" ]; then
  echo "ERROR: root certificate fingerprint $ACTUAL_FP, expected $ROOT_CA_CERT_FINGERPRINT"
  exit 1
fi

cat > root-ca-check.json <<EOF
{
  "url": "$ROOT_CA_URL",
  "zip_sha256": "$ROOT_CA_ZIP_SHA256",
  "zip_sha256_checked": true,
  "cert_sha256_fingerprint": "$ACTUAL_FP",
  "cert_fingerprint_checked": true,
  "subject": "$SUBJECT",
  "not_after": "$NOT_AFTER",
  "fetched_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
cat root-ca-check.json
echo
echo "=== ✓ AWS Nitro Root CA G1 on record ==="
