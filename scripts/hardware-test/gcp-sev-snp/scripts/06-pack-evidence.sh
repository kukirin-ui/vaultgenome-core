#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 06-pack-evidence.sh — collect every captured artefact into a single
# tar archive ready for review or upload to a data room.

set -euo pipefail

cd ~/vg

VM_NAME=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/name" 2>/dev/null \
  || hostname)
ZONE=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/zone" 2>/dev/null \
  | awk -F/ '{print $NF}' || echo "unknown")

echo "=== capture VM identity ==="
{
  echo "vm_name:     $VM_NAME"
  echo "zone:        $ZONE"
  echo "uname:       $(uname -a)"
  echo "captured_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} | tee evidence/vm-identity.txt

OUT="$HOME/${VM_NAME}-evidence.tar.gz"
echo
echo "=== pack into $OUT ==="
tar czf "$OUT" evidence/
ls -lh "$OUT"

echo
echo "=== contents ==="
tar tzf "$OUT"

echo
echo "=== to download to your laptop ==="
echo "  In SSH-in-browser: click DOWNLOAD FILE, enter path: $OUT"
echo "  Or via gcloud:     gcloud compute scp $VM_NAME:$OUT ./ --zone=$ZONE"

echo
echo "=== to upload to a Cloud Storage bucket ==="
echo "  gcloud storage cp $OUT gs://YOUR-BUCKET/"
