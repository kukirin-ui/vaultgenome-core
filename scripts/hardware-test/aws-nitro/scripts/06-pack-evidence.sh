#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 06-pack-evidence.sh — collect every captured artefact into a single
# tar archive ready for review or upload to a data room.

set -euo pipefail

EVIDENCE_DIR="$HOME/vg/attestation-validation/$(hostname)"
cd "$EVIDENCE_DIR"

# Use IMDSv2 to fetch instance metadata
TOKEN=$(curl -fsS -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || echo "")
if [ -n "$TOKEN" ]; then
  INSTANCE_ID=$(curl -fsS -H "X-aws-ec2-metadata-token: $TOKEN" \
                http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || hostname)
  AZ=$(curl -fsS -H "X-aws-ec2-metadata-token: $TOKEN" \
       http://169.254.169.254/latest/meta-data/placement/availability-zone 2>/dev/null || echo "unknown")
  REGION=$(curl -fsS -H "X-aws-ec2-metadata-token: $TOKEN" \
           http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || echo "unknown")
else
  INSTANCE_ID=$(hostname)
  AZ="unknown"
  REGION="unknown"
fi

echo "=== capture VM identity ==="
{
  echo "instance_id: $INSTANCE_ID"
  echo "az:          $AZ"
  echo "region:      $REGION"
  echo "uname:       $(uname -a)"
  echo "captured_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "nitro-cli:   $(nitro-cli --version 2>/dev/null || echo 'not installed')"
} | tee vm-identity-pack.txt

OUT="$HOME/${INSTANCE_ID}-${AZ}-aws-nitro-evidence.tar.gz"
echo
echo "=== pack into $OUT ==="
cd "$HOME/vg/attestation-validation"
tar czf "$OUT" "$(basename "$EVIDENCE_DIR")/"
ls -lh "$OUT"

echo
echo "=== contents ==="
tar tzf "$OUT" | head -30

echo
echo "=== to download to your laptop ==="
echo "  ssh -i ~/.ssh/<key>.pem ec2-user@<public-ip>:$OUT ./"
echo "  Or use AWS Systems Manager Session Manager file transfer."

echo
echo "=== to upload to S3 bucket ==="
echo "  aws s3 cp $OUT s3://YOUR-BUCKET/"
