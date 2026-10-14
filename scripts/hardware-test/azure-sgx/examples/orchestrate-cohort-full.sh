#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# orchestrate-cohort-full.sh — run the full Azure SGX cohort sequentially:
#   VM2 + VM3 in eastus2  → 2 more silicon chips proven distinct from VM1
#   VM4 in westeurope     → cross-region DR test (restores VM3's bundle byte-identical)
#
# Total wall time: ~75-90 min (3 VMs × ~25 min each)
# Total cost: ~$0.20
#
# Prereqs:
#   - VM1 already done (evidence in ../evidence/01-VM1-eastus2/)
#   - acpctl-linux-amd64 in <repo>/bin/
#   - SSH key at ~/.ssh/id_ed25519
#   - az login already done
#   - Microsoft.Compute provider registered

set -euo pipefail

cd "$(dirname "$0")"

START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=== Azure SGX cohort run started at ${START_TS} ==="

# VM2: second eastus2 chip
./orchestrate-cohort-vm.sh 2 eastus2

# VM3: third eastus2 chip — saves demo1 bundle to ~/Desktop/azure-sgx-shared/
./orchestrate-cohort-vm.sh 3 eastus2

# VM4: westeurope — restores VM3's bundle byte-identical (cross-region DR)
./orchestrate-cohort-vm.sh 4 westeurope "${HOME}/Desktop/azure-sgx-shared/donor-bundle.genome"

END_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo
echo "=== ✓ Full Azure SGX cohort complete (started ${START_TS}, ended ${END_TS}) ==="
echo "Evidence:"
echo "  VM2: ../evidence/02-VM2-eastus2/"
echo "  VM3: ../evidence/03-VM3-eastus2/"
echo "  VM4: ../evidence/04-VM4-westeurope/   (with cross-region-result.txt)"
echo
echo "Next: review evidence + update CROSS-VM-MATRIX.md, then commit."
