#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 07-cross-vm-matrix.sh — collate AWS Nitro Enclaves attestation evidence
# from N instance directories into a single CROSS-VM-MATRIX.md report.
#
# Run on your laptop after the per-VM evidence has been captured into
# directories named like 01-VM1-<az>/, 02-VM2-<az>/, ...
#
# Each VM directory must contain (produced by 02-capture-attestation.sh +
# 02b-cryptographic-attestation.sh):
#
#   00-vm-identity.txt          (instance_id, region, AZ — text grep)
#   05-attestation-parsed.json  (module_id, pcr0, user_data, cabundle_count)
#   06-chain-validation.json    (chain_valid, anchor_valid, cose_valid,
#                                user_data_match, all_pass, cert_chain[])
#
# Usage:
#   ./07-cross-vm-matrix.sh <evidence-root-dir>
#
# Output: <evidence-root-dir>/CROSS-VM-MATRIX.md
#
# Compatible with macOS bash 3.x (no mapfile, no printf "--"-leading args).

set -euo pipefail

ROOT="${1:-}"
[ -n "${ROOT}" ] && [ -d "${ROOT}" ] || {
  echo "Usage: $0 <evidence-root-dir>" >&2
  exit 1
}
cd "${ROOT}"

OUT="${ROOT}/CROSS-VM-MATRIX.md"

VM_DIRS=()
while IFS= read -r line; do
  VM_DIRS+=("$line")
done < <(find . -maxdepth 1 -mindepth 1 -type d -name '0[0-9]-VM*' | sort)
[ "${#VM_DIRS[@]}" -gt 0 ] || { echo "No VM directories found in ${ROOT}" >&2; exit 1; }

mark() {
  if [ "$1" = "true" ]; then echo "✓"; else echo "✗"; fi
}

extract_identity() {
  grep "^$2:" "$1" | head -1 | sed "s/^$2:[[:space:]]*//"
}

{
  echo "# Cross-VM AWS Nitro Enclaves Attestation Matrix"
  echo ""
  echo "**Generated:** $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "**Cohort size:** ${#VM_DIRS[@]} VMs across regions/AZs"
  echo "**Test Kit:** \`core/scripts/hardware-test/aws-nitro/\`"
  echo "**Anchor:** AWS Nitro Root CA G1 (\`CN=aws.nitro-enclaves, O=Amazon, C=US\`)"
  echo ""
  echo "---"
  echo ""

  echo "## 1. Hardware identity"
  echo ""
  echo "Each Nitro Security Module has a unique \`module_id\` baked into the chip."
  echo "Distinct \`module_id\` values prove distinct physical hardware instances."
  echo ""
  echo "| VM | Region | AZ | Instance ID | Module ID |"
  echo "|----|--------|-----|-------------|-----------|"
  for vm_dir in "${VM_DIRS[@]}"; do
    name=$(basename "${vm_dir}" | sed 's/^[0-9]*-//')
    iid=$(extract_identity "${vm_dir}/00-vm-identity.txt" "Instance ID")
    region=$(extract_identity "${vm_dir}/00-vm-identity.txt" "Region")
    az=$(extract_identity "${vm_dir}/00-vm-identity.txt" "Availability Zone")
    mid=$(jq -r '.module_id' "${vm_dir}/05-attestation-parsed.json")
    short_id=$(echo "$name" | cut -d- -f1)
    echo "| ${short_id} | ${region} | ${az} | \`${iid}\` | \`${mid}\` |"
  done
  echo ""

  echo "## 2. Workload binding (REPORT_DATA / user_data)"
  echo ""
  echo "All enclaves were given the **same** \`report-data.bin\` (SHA-512 of the"
  echo "Vault Genome workload manifest). The Nitro hypervisor signed each attestation"
  echo "with that user_data embedded — proving the attestation describes *this*"
  echo "specific workload, not some other binary."
  echo ""
  echo "| VM | user_data (first 32 bytes) | Match expected |"
  echo "|----|-----------------------------|----------------|"
  for vm_dir in "${VM_DIRS[@]}"; do
    short_id=$(basename "${vm_dir}" | sed 's/^[0-9]*-//' | cut -d- -f1)
    ud=$(jq -r '.user_data' "${vm_dir}/05-attestation-parsed.json" | head -c 64)
    ud_match=$(jq -r '.user_data_match' "${vm_dir}/06-chain-validation.json")
    echo "| ${short_id} | \`${ud}…\` | $(mark "${ud_match}") |"
  done
  echo ""

  echo "## 3. Cryptographic chain validation per VM"
  echo ""
  echo "Each attestation document is COSE_Sign1 (CBOR/COSE wire format), signed"
  echo "with ECDSA P-384 over SHA-384. Validation checks:"
  echo ""
  echo "1. **chain** — each cert in cabundle signed by the previous one"
  echo "2. **anchor** — root of cabundle matches AWS Nitro Root CA G1 fingerprint"
  echo "3. **COSE_Sign1** — leaf cert public key verifies the COSE signature"
  echo "4. **user_data** — payload's \`user_data\` field matches expected SHA-512"
  echo ""
  printf "| Check |"
  for vm_dir in "${VM_DIRS[@]}"; do
    short_id=$(basename "${vm_dir}" | sed 's/^[0-9]*-//' | cut -d- -f1)
    printf " %s |" "${short_id}"
  done
  printf "\n|---|"
  for _ in "${VM_DIRS[@]}"; do printf '%s' "---|"; done
  printf "\n"

  printf "| Attestation document captured |"
  for vm_dir in "${VM_DIRS[@]}"; do
    if [ -s "${vm_dir}/04-attestation-document.bin" ]; then printf " ✓ |"; else printf " ✗ |"; fi
  done
  printf "\n"

  printf "| Chain valid (cabundle integrity) |"
  for vm_dir in "${VM_DIRS[@]}"; do
    cv=$(jq -r '.chain_valid' "${vm_dir}/06-chain-validation.json")
    printf " %s |" "$(mark "$cv")"
  done
  printf "\n"

  printf "| Anchor valid (Root CA G1) |"
  for vm_dir in "${VM_DIRS[@]}"; do
    av=$(jq -r '.anchor_valid' "${vm_dir}/06-chain-validation.json")
    printf " %s |" "$(mark "$av")"
  done
  printf "\n"

  printf "| COSE_Sign1 (ECDSA P-384) |"
  for vm_dir in "${VM_DIRS[@]}"; do
    cs=$(jq -r '.cose_valid' "${vm_dir}/06-chain-validation.json")
    printf " %s |" "$(mark "$cs")"
  done
  printf "\n"

  printf "| user_data binding (SHA-512 manifest) |"
  for vm_dir in "${VM_DIRS[@]}"; do
    udm=$(jq -r '.user_data_match' "${vm_dir}/06-chain-validation.json")
    printf " %s |" "$(mark "$udm")"
  done
  printf "\n"

  printf "| PCR0 non-zero (production mode marker) |"
  for vm_dir in "${VM_DIRS[@]}"; do
    nz=$(jq -r '.pcr0_nonzero // false' "${vm_dir}/06-chain-validation.json")
    printf " %s |" "$(mark "$nz")"
  done
  printf "\n"

  printf "| PCR0 matches expected (built .eif binding) |"
  for vm_dir in "${VM_DIRS[@]}"; do
    me=$(jq -r '.pcr0_matches_expected // false' "${vm_dir}/06-chain-validation.json")
    if [ "$me" = "null" ]; then me="false"; fi
    printf " %s |" "$(mark "$me")"
  done
  printf "\n"

  printf "| **All core checks pass** |"
  for vm_dir in "${VM_DIRS[@]}"; do
    ap=$(jq -r '.all_pass' "${vm_dir}/06-chain-validation.json")
    printf " **%s** |" "$(mark "$ap")"
  done
  printf "\n"

  printf "| **Production-grade (core + non-zero PCR0 + match)** |"
  for vm_dir in "${VM_DIRS[@]}"; do
    pg=$(jq -r '.production_grade // false' "${vm_dir}/06-chain-validation.json")
    printf " **%s** |" "$(mark "$pg")"
  done
  printf "\n"
  echo ""

  echo "## 4. Certificate chain (proof of common AWS PKI anchor)"
  echo ""
  echo "All attestations chain back to the SAME root certificate"
  echo "(\`CN=aws.nitro-enclaves\`), but through **different intermediates**"
  echo "(regional + zonal + per-instance), proving distinct hardware while"
  echo "validating against one common AWS-signed PKI root."
  echo ""
  for vm_dir in "${VM_DIRS[@]}"; do
    short_id=$(basename "${vm_dir}" | sed 's/^[0-9]*-//' | cut -d- -f1)
    region=$(extract_identity "${vm_dir}/00-vm-identity.txt" "Region")
    az=$(extract_identity "${vm_dir}/00-vm-identity.txt" "Availability Zone")
    echo "**${short_id} (${region} ${az})**"
    echo ""
    jq -r '.cert_chain[]' "${vm_dir}/06-chain-validation.json" | nl -nrz -w2 -s'. '
    echo ""
  done

  echo "## 5. Reproducibility"
  echo ""
  echo "This entire matrix can be reproduced by any third party with an AWS account:"
  echo ""
  echo "\`\`\`bash"
  echo "git clone https://github.com/<org>/<repo>.git && cd repo"
  echo "cd vaultgenome-core/scripts/hardware-test/aws-nitro/"
  echo "for az in us-east-2a us-east-2b us-east-2c eu-west-1a; do"
  echo "  TF_VAR_availability_zone=\$az TF_VAR_instance_name=vault-genome-nitro-\$az \\"
  echo "    ./examples/full-test-run.sh"
  echo "done"
  echo "./scripts/07-cross-vm-matrix.sh ./evidence-root/"
  echo "\`\`\`"
  echo ""
  echo "Total cost on AWS: about \$0.50 (4× m5.xlarge × ~30 min wall time)."
  echo ""

  echo "## 6. Attestation timestamps (Nitro hypervisor clocks)"
  echo ""
  echo "Each timestamp is set by the AWS Nitro hypervisor at the moment of"
  echo "attestation request. Spread across multiple regions in the same hour"
  echo "shows independent hypervisors, not a replay of one document."
  echo ""
  echo "| VM | Timestamp (UTC) | Unix ms |"
  echo "|----|-----------------|---------|"
  for vm_dir in "${VM_DIRS[@]}"; do
    short_id=$(basename "${vm_dir}" | sed 's/^[0-9]*-//' | cut -d- -f1)
    ms=$(jq -r '.timestamp_ms' "${vm_dir}/06-chain-validation.json")
    iso=$(date -u -r "$((ms / 1000))" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "—")
    echo "| ${short_id} | ${iso} | ${ms} |"
  done
  echo ""

  echo "---"
  echo ""
  echo "_**Vault Genome Inc.** — AWS Nitro Enclaves hardware validation cohort_"
  echo "_AGPL-3.0-or-later (kit + tools) · NDA-scoped artifacts_"
} > "${OUT}"

echo "=== ✓ matrix written to ${OUT} ==="
wc -l "${OUT}"
