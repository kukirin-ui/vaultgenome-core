#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 07-cross-vm-matrix.sh — collate cryptographic attestation evidence from
# N VM directories into a single CROSS-VM-MATRIX.md report. Run on your
# laptop after downloading evidence tarballs from each VM.
#
# Usage:
#   ./07-cross-vm-matrix.sh <evidence-root-dir>
#
# Where <evidence-root-dir> contains subdirectories like:
#   01-VM1-<zone>/
#   02-VM2-<zone>/
#   ...
#   each containing 04-attestation-report.bin, 05-attestation-report-decoded.txt,
#   08-verify-certs.txt, 09-verify-attestation.txt, etc.
#
# Output: <evidence-root-dir>/CROSS-VM-MATRIX.md

set -euo pipefail

ROOT="${1:-}"
[ -n "${ROOT}" ] && [ -d "${ROOT}" ] || { echo "Usage: $0 <evidence-root-dir>"; exit 1; }
cd "${ROOT}"

OUT="${ROOT}/CROSS-VM-MATRIX.md"

# Find VM directories (sorted)
mapfile -t VM_DIRS < <(find . -maxdepth 1 -mindepth 1 -type d -name '0[0-9]-VM*' | sort)
[ "${#VM_DIRS[@]}" -gt 0 ] || { echo "No VM directories found in ${ROOT}"; exit 1; }

extract_field() {
  # extract a multi-line hex field from decoded report
  awk -v label="^${2}:" '$0 ~ label {flag=1; next} flag && /^$/{flag=0; next} flag' "${1}" 2>/dev/null \
    | tr -d ' \n' | tr 'A-F' 'a-f'
}

verify_status() {
  # check status of a verify file: ✓ if all expected pass strings present, ✗ otherwise
  if [ ! -f "${1}" ] || [ ! -s "${1}" ]; then
    echo "⏳"
    return
  fi
  if grep -q "ARK was self-signed" "${1}" 2>/dev/null && \
     grep -q "ASK was signed by the AMD ARK" "${1}" 2>/dev/null && \
     grep -q "VCEK was signed by the AMD ASK" "${1}" 2>/dev/null; then
    echo "✓"
  elif grep -q "VEK signed the Attestation Report" "${1}" 2>/dev/null && \
       grep -q "Chip ID from certificate matches" "${1}" 2>/dev/null; then
    echo "✓"
  else
    echo "✗"
  fi
}

{
  echo "# Cross-VM SEV-SNP Cryptographic Attestation Matrix"
  echo
  echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "## VM count: ${#VM_DIRS[@]}"
  echo
  echo "## Hardware identity (Chip IDs — must all be distinct)"
  echo
  echo "| VM | Chip ID (hex) |"
  echo "|---|---|"
  for vm_dir in "${VM_DIRS[@]}"; do
    name=$(basename "${vm_dir}")
    chip_id=$(extract_field "${vm_dir}/05-attestation-report-decoded.txt" "Chip ID")
    echo "| ${name} | \`${chip_id:0:32}…${chip_id: -16}\` |"
  done
  echo
  echo "## Workload binding (REPORT_DATA = SHA-512 of manifest — must be distinct per workload)"
  echo
  echo "| VM | REPORT_DATA (first 32 bytes) |"
  echo "|---|---|"
  for vm_dir in "${VM_DIRS[@]}"; do
    name=$(basename "${vm_dir}")
    rd=$(extract_field "${vm_dir}/05-attestation-report-decoded.txt" "Report Data")
    echo "| ${name} | \`${rd:0:64}\` |"
  done
  echo
  echo "## Cryptographic checks"
  echo
  echo "| Check | $(printf '%s | ' "${VM_DIRS[@]##*/}" | sed 's/-VM[0-9]*-//; s/| $/|/' ) "
  printf "|---"
  for _ in "${VM_DIRS[@]}"; do printf "|---"; done
  printf "|\n"

  # Build header row of VM short names
  printf "| Check |"
  for vm_dir in "${VM_DIRS[@]}"; do
    short=$(basename "${vm_dir}" | sed 's/^[0-9]*-//')
    printf " %s |" "${short}"
  done
  printf "\n|---|"
  for _ in "${VM_DIRS[@]}"; do printf "---|"; done
  printf "\n"

  # Row: report present
  printf "| Report captured (1184 bytes) |"
  for vm_dir in "${VM_DIRS[@]}"; do
    if [ -f "${vm_dir}/04-attestation-report.bin" ]; then
      sz=$(stat -f %z "${vm_dir}/04-attestation-report.bin" 2>/dev/null || stat -c %s "${vm_dir}/04-attestation-report.bin")
      [ "${sz}" = "1184" ] && printf " ✓ |" || printf " ✗ |"
    else
      printf " ✗ |"
    fi
  done
  printf "\n"

  # Row: cert chain verified
  printf "| Cert chain (ARK → ASK → VCEK) |"
  for vm_dir in "${VM_DIRS[@]}"; do
    status=$(verify_status "${vm_dir}/08-verify-certs.txt")
    [ "${status}" = "⏳" ] && [ -f "${vm_dir}/08-verify-certs-v2.txt" ] && status=$(verify_status "${vm_dir}/08-verify-certs-v2.txt")
    printf " %s |" "${status}"
  done
  printf "\n"

  # Row: report signature verified
  printf "| Report signature (VCEK → Report) |"
  for vm_dir in "${VM_DIRS[@]}"; do
    status=$(verify_status "${vm_dir}/09-verify-attestation.txt")
    printf " %s |" "${status}"
  done
  printf "\n"

  echo
  echo "Legend: ✓ verified · ✗ failed · ⏳ deferred (e.g. AMD KDS unreachable; complete via 02c-deferred-vcek-fetch.sh)"
} > "${OUT}"

echo "=== ✓ matrix written to ${OUT} ==="
cat "${OUT}"
