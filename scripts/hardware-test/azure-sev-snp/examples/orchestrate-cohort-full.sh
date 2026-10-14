#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# orchestrate-cohort-full.sh — run the full Azure SEV-SNP cohort sequentially:
#   VM1 + VM2 + VM3 in East US  → 3 silicon chips proven distinct
#   VM4 in West Europe          → cross-region DR (restores VM3's bundle byte-identical)
#
# Total wall time: ~75-90 min (4 VMs × ~25 min)
# Total cost: ~$0.30
#
# Prereqs:
#   - DCASv5 quota approved in East US (≥16 vCPU) and West Europe (≥16 vCPU)
#   - acpctl-linux-amd64 in <repo>/bin/
#   - SSH key at ~/.ssh/id_ed25519
#   - az login already done
#   - Microsoft.Compute provider registered

set -euo pipefail

cd "$(dirname "$0")"

START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=== Azure SEV-SNP cohort run started at ${START_TS} ==="

# VM1: first East US chip
./orchestrate-cohort-vm.sh 1 eastus

# VM2: second East US chip
./orchestrate-cohort-vm.sh 2 eastus

# VM3: third East US chip — saves demo1 bundle to ~/Desktop/azure-sev-snp-shared/
./orchestrate-cohort-vm.sh 3 eastus

# VM4: West Europe — restores VM3's bundle byte-identical (cross-region DR)
./orchestrate-cohort-vm.sh 4 westeurope "${HOME}/Desktop/azure-sev-snp-shared/donor-bundle.genome"

END_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo
echo "=== ✓ Full Azure SEV-SNP cohort complete (started ${START_TS}, ended ${END_TS}) ==="
echo "Evidence:"
echo "  VM1: ../evidence/01-VM1-eastus/"
echo "  VM2: ../evidence/02-VM2-eastus/"
echo "  VM3: ../evidence/03-VM3-eastus/"
echo "  VM4: ../evidence/04-VM4-westeurope/   (with cross-region-result.txt)"
echo
echo "Next: review evidence + update CROSS-VM-MATRIX.md, then commit."
