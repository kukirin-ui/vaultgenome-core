#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# full-test-run.sh — orchestrate the entire kit end-to-end against a
# single Confidential VM. Run from your laptop. The runner:
#
#   1. terraform apply       provisions a Confidential VM
#   2. uploads scripts        pushes the kit's scripts/ dir to the VM
#   3. ssh + bootstrap        installs Go + Ollama + acpctl
#   4. captures attestation   1184-byte SEV-SNP report
#   5. runs Demo 1            single-bundle round-trip + tamper test
#   6. runs Demo 2            chain operations
#   7. (optional) inference   empirical model output comparison
#   8. packs evidence         single tar archive
#   9. downloads it           scp to your laptop
#  10. terraform destroy      tears VM down (no ongoing billing)
#
# A bundle of scripts the kit uploads to the VM lives under scripts/.
# The acpctl binary must be available locally — by default the runner
# expects it at ../../../bin/acpctl (the standard build output path
# from the Vault Genome repo root). Override via $ACPCTL if needed.

set -euo pipefail

KIT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ACPCTL="${ACPCTL:-$KIT_DIR/../../../bin/acpctl}"

if [ ! -x "$ACPCTL" ]; then
  echo "ERROR: acpctl binary not found at $ACPCTL"
  echo "       Build with: go build -o ../../../bin/acpctl ./cmd/acpctl"
  echo "       Or set ACPCTL=/path/to/acpctl"
  exit 1
fi

if [ -z "${TF_VAR_project_id:-}" ]; then
  echo "ERROR: set TF_VAR_project_id=<your-gcp-project-id> before running."
  exit 1
fi

echo "=== 1. provision VM ==="
cd "$KIT_DIR/terraform"
terraform init -upgrade -input=false
terraform apply -auto-approve

VM_NAME="$(terraform output -raw instance_name)"
ZONE="$(terraform output -raw zone)"

# Wait for VM to be SSH-ready.
echo "=== 1a. wait for SSH ==="
for _ in $(seq 1 30); do
  if gcloud compute ssh "$VM_NAME" --zone="$ZONE" --command="echo ready" \
        --quiet >/dev/null 2>&1; then
    break
  fi
  sleep 5
done

echo
echo "=== 2. upload scripts + acpctl to VM ==="
gcloud compute scp --recurse "$KIT_DIR/scripts" "$VM_NAME":~/scripts \
  --zone="$ZONE" --quiet
gcloud compute scp "$ACPCTL" "$VM_NAME":~/acpctl --zone="$ZONE" --quiet

echo
echo "=== 3-8. run all phases on the VM ==="
gcloud compute ssh "$VM_NAME" --zone="$ZONE" --quiet --command='
  set -e
  chmod +x ~/scripts/*.sh
  cd ~ && mkdir -p vg && cd vg && cp ~/acpctl ./acpctl && chmod +x ./acpctl

  ~/scripts/01-bootstrap-vm.sh
  ~/scripts/02-capture-attestation.sh
  ~/scripts/03-demo1-single-bundle.sh
  ~/scripts/04-demo2-chain.sh
  ~/scripts/05-inference-test.sh || echo "(inference skipped — non-fatal)"
  ~/scripts/06-pack-evidence.sh
'

echo
echo "=== 9. download evidence to laptop ==="
gcloud compute scp "$VM_NAME":~/${VM_NAME}-evidence.tar.gz ./ \
  --zone="$ZONE" --quiet

echo
echo "evidence: $(pwd)/${VM_NAME}-evidence.tar.gz"
ls -lh "${VM_NAME}-evidence.tar.gz"

echo
echo "=== 10. teardown VM ==="
cd "$KIT_DIR/terraform"
terraform destroy -auto-approve

echo
echo "=== ✓ all done ==="
