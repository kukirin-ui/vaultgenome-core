#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 06-pack-evidence.sh — collect every captured artefact into a single
# tar archive ready for review or upload to a data room. Includes both
# AMD chain (snpguest) and MAA chain (JWT) evidence — Azure-specific
# dual-PKI structure.

set -euo pipefail

cd ~/vg

# Get VM identity from Azure IMDS
IMDS_JSON=$(curl -fs -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance/compute?api-version=2021-12-13" 2>/dev/null || echo "{}")
VM_NAME=$(echo "${IMDS_JSON}" | jq -r '.name // empty')
[ -z "${VM_NAME}" ] && VM_NAME=$(hostname)
LOCATION=$(echo "${IMDS_JSON}" | jq -r '.location // "unknown"')
ZONE=$(echo "${IMDS_JSON}" | jq -r '.zone // "unknown"')
VM_SIZE=$(echo "${IMDS_JSON}" | jq -r '.vmSize // "unknown"')

echo "=== capture VM identity ==="
{
  echo "vm_name:       $VM_NAME"
  echo "cloud:         azure"
  echo "location:      $LOCATION"
  echo "zone:          $ZONE"
  echo "vm_size:       $VM_SIZE"
  echo "uname:         $(uname -a)"
  echo "captured_at:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "tee_backend:   azure-sev-snp"
  echo "amd_chain:     captured at attestation-validation/${VM_NAME}/{04-attestation-report.bin, 06-certificates/, 08-verify-certs.txt, 09-verify-attestation.txt}"
  echo "maa_chain:     captured at attestation-validation/${VM_NAME}/{15-maa-jwt.txt, 17-maa-jwt-payload.json, 19-maa-jwt-verify.txt}"
} | tee evidence/vm-identity.txt

# Include attestation-validation dir in the pack if present
if [ -d "${HOME}/vg/attestation-validation" ]; then
  cp -r "${HOME}/vg/attestation-validation" evidence/
fi

OUT="$HOME/${VM_NAME}-evidence.tar.gz"
echo
echo "=== pack into $OUT ==="
tar czf "$OUT" evidence/
ls -lh "$OUT"

echo
echo "=== contents ==="
tar tzf "$OUT" | head -40
echo "..."
tar tzf "$OUT" | wc -l
echo "(total entries shown above)"

echo
echo "=== to download to your laptop ==="
echo "  Via SSH: scp azureuser@<vm-public-ip>:$OUT ./"
echo "  Or via Azure CLI:  az vm run-command invoke --resource-group <rg> --name $VM_NAME \\"
echo "                       --command-id RunShellScript --scripts \"cat $OUT | base64\""
