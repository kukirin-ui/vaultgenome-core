#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# full-test-run.sh — orchestrate the entire Azure SEV-SNP kit end-to-end
# against a single Confidential VM. Run from your laptop. The runner:
#
#   1. terraform apply       provisions a DCasv5 Confidential VM
#   2. uploads scripts        pushes the kit's scripts/ dir to the VM
#   3. ssh + bootstrap        installs Go + Ollama + acpctl + snpguest + az CLI
#   4. captures AMD chain     1184-byte SEV-SNP report + ARK→ASK→VCEK + verify
#   5. captures MAA chain     Microsoft Azure Attestation JWT + verify
#   6. runs Demo 1            single-bundle round-trip + tamper test
#   7. runs Demo 2            chain operations
#   8. (optional) inference   empirical model output comparison
#   9. packs evidence         single tar archive
#  10. downloads it           scp to your laptop
#  11. terraform destroy      tears VM down (no ongoing billing)

set -euo pipefail

KIT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ACPCTL="${ACPCTL:-$KIT_DIR/../../../bin/acpctl}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"

if [ ! -x "$ACPCTL" ]; then
  echo "ERROR: acpctl binary not found at $ACPCTL"
  echo "       Build with: go build -o ../../../bin/acpctl ./cmd/acpctl"
  echo "       Or set ACPCTL=/path/to/acpctl"
  exit 1
fi

if [ ! -f "${SSH_KEY}" ] || [ ! -f "${SSH_KEY}.pub" ]; then
  echo "ERROR: SSH keypair not found at ${SSH_KEY}{,.pub}"
  echo "       Generate with: ssh-keygen -t ed25519 -f ${SSH_KEY}"
  exit 1
fi

# Ensure az CLI is logged in
if ! az account show >/dev/null 2>&1; then
  echo "ERROR: 'az' CLI is not logged in. Run 'az login' first."
  exit 1
fi

echo "=== 1. provision Azure Confidential VM ==="
cd "$KIT_DIR/terraform"
export TF_VAR_admin_ssh_public_key="$(cat "${SSH_KEY}.pub")"
terraform init -upgrade -input=false
terraform apply -auto-approve

VM_NAME="$(terraform output -raw instance_name)"
LOCATION="$(terraform output -raw location)"
PUBLIC_IP="$(terraform output -raw public_ip)"
RG="$(terraform output -raw resource_group)"

echo
echo "=== 1a. wait for SSH (Azure CVMs take ~60-90s to be SSH-ready) ==="
for _ in $(seq 1 30); do
  if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -i "${SSH_KEY}" "azureuser@${PUBLIC_IP}" "echo ready" >/dev/null 2>&1; then
    break
  fi
  sleep 5
done

SSH="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ${SSH_KEY} azureuser@${PUBLIC_IP}"
SCP="scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ${SSH_KEY}"

echo
echo "=== 2. upload scripts + acpctl to VM ==="
${SCP} -r "$KIT_DIR/scripts" "azureuser@${PUBLIC_IP}:~/scripts"
${SCP} "$ACPCTL" "azureuser@${PUBLIC_IP}:~/acpctl"

echo
echo "=== 3-9. run all phases on the VM ==="
${SSH} '
  set -e
  chmod +x ~/scripts/*.sh
  cd ~ && mkdir -p vg && cd vg && cp ~/acpctl ./acpctl && chmod +x ./acpctl

  ~/scripts/01-bootstrap-vm.sh
  ~/scripts/02-capture-attestation.sh
  ~/scripts/02b-cryptographic-attestation.sh
  ~/scripts/02f-capture-maa-jwt.sh
  ~/scripts/03-demo1-single-bundle.sh
  ~/scripts/04-demo2-chain.sh
  ~/scripts/05-inference-test.sh || echo "(inference skipped — non-fatal)"
  ~/scripts/06-pack-evidence.sh
'

echo
echo "=== 10. download evidence to laptop ==="
${SCP} "azureuser@${PUBLIC_IP}:~/${VM_NAME}-evidence.tar.gz" ./

echo
echo "evidence: $(pwd)/${VM_NAME}-evidence.tar.gz"
ls -lh "${VM_NAME}-evidence.tar.gz"

echo
echo "=== 11. teardown VM ==="
cd "$KIT_DIR/terraform"
terraform destroy -auto-approve

echo
echo "=== ✓ all done — Azure SEV-SNP cohort step complete ==="
echo "Both AMD chain (snpguest) and MAA chain (Microsoft JWT) captured + verified."
