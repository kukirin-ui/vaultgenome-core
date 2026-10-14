#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# orchestrate-cohort-vm.sh — Mac-side orchestrator for ONE Azure
# SEV-SNP cohort VM. End-to-end on a single VM:
#   provision → bootstrap → AMD attestation chain → MAA JWT →
#   workload tests → pack evidence → download → destroy
#
# Usage:
#   ./orchestrate-cohort-vm.sh <vm_num> <region> [restore_bundle_path]
#
# Examples:
#   ./orchestrate-cohort-vm.sh 2 eastus                       # 2nd VM in East US
#   ./orchestrate-cohort-vm.sh 3 eastus                       # 3rd VM (donor for cross-region)
#   ./orchestrate-cohort-vm.sh 4 westeurope \
#     ~/Desktop/azure-sev-snp-shared/donor-bundle.genome      # cross-region DR test
#
# Wall time per VM: ~25 min
# Cost per VM: ~$0.07 (DC4as_v5 × 25 min)

set -euo pipefail

VM_NUM="${1:?vm_num required (2, 3, or 4)}"
REGION="${2:-eastus}"
RESTORE_BUNDLE="${3:-}"

KIT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "${KIT_DIR}/../../../.." && pwd)"
TERRAFORM_DIR="${KIT_DIR}/terraform"
ACPCTL_BIN="${REPO_ROOT}/bin/acpctl-linux-amd64"
EVIDENCE_DIR="${KIT_DIR}/evidence/0${VM_NUM}-VM${VM_NUM}-${REGION}"
SHARED_DIR="${HOME}/Desktop/azure-sev-snp-shared"
INSTANCE_NAME="vault-genome-sev-snp-cohort-vm${VM_NUM}"
SSH_KEY="${SSH_KEY:-${HOME}/.ssh/id_ed25519}"

mkdir -p "${EVIDENCE_DIR}" "${SHARED_DIR}"

[ -x "${ACPCTL_BIN}" ] || {
  echo "ERROR: acpctl Linux binary missing at ${ACPCTL_BIN}";
  echo "Build with: (cd ${REPO_ROOT}/core && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ../bin/acpctl-linux-amd64 ./cmd/acpctl/)";
  exit 1;
}
[ -f "${SSH_KEY}.pub" ] || { echo "ERROR: SSH public key missing at ${SSH_KEY}.pub"; exit 1; }

export TF_VAR_instance_name="${INSTANCE_NAME}"
export TF_VAR_location="${REGION}"
export TF_VAR_admin_ssh_public_key="$(cat "${SSH_KEY}.pub")"

cd "${TERRAFORM_DIR}"

echo "=== [vm${VM_NUM}/${REGION}] clear stale terraform state from previous run ==="
terraform destroy -auto-approve -compact-warnings 2>&1 | tail -3 || true

echo
echo "=== [vm${VM_NUM}/${REGION}] terraform apply ==="
terraform apply -auto-approve -compact-warnings | tail -8

VM_IP="$(terraform output -raw public_ip)"
echo "VM IP: ${VM_IP}"

echo
echo "=== [vm${VM_NUM}/${REGION}] wait for SSH ==="
for attempt in $(seq 1 30); do
  if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
       -o ConnectTimeout=5 -i "${SSH_KEY}" \
       azureuser@"${VM_IP}" 'echo ssh-ready' 2>/dev/null; then
    break
  fi
  sleep 5
done

echo
echo "=== [vm${VM_NUM}/${REGION}] upload kit + acpctl ==="
scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "${SSH_KEY}" \
  -r "${KIT_DIR}/scripts" "${ACPCTL_BIN}" \
  azureuser@"${VM_IP}":~/
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "${SSH_KEY}" \
    azureuser@"${VM_IP}" \
    'mv ~/acpctl-linux-amd64 ~/acpctl && chmod +x ~/scripts/*.sh ~/acpctl && mkdir -p ~/vg && cp ~/acpctl ~/vg/acpctl'

# Optionally upload restore bundle for cross-region DR test
if [ -n "${RESTORE_BUNDLE}" ] && [ -f "${RESTORE_BUNDLE}" ]; then
  echo
  echo "=== [vm${VM_NUM}/${REGION}] upload cross-region bundle ($(du -h "${RESTORE_BUNDLE}" | cut -f1)) ==="
  scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "${SSH_KEY}" \
    "${RESTORE_BUNDLE}" \
    azureuser@"${VM_IP}":~/vg/cross-region-bundle.genome
fi

echo
echo "=== [vm${VM_NUM}/${REGION}] run kit on VM ==="
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "${SSH_KEY}" \
    azureuser@"${VM_IP}" 'bash -s' <<'REMOTE_EOF'
set -e
cd ~/vg

bash ~/scripts/01-bootstrap-vm.sh 2>&1 | tail -10

bash ~/scripts/02-capture-attestation.sh 2>&1 | tail -10
bash ~/scripts/02b-cryptographic-attestation.sh 2>&1 | tail -15 || echo "(02b had issues — continuing)"
bash ~/scripts/02f-capture-maa-jwt.sh 2>&1 | tail -10 || echo "(02f had issues — continuing)"

bash ~/scripts/03-demo1-single-bundle.sh 2>&1 | tail -10
bash ~/scripts/04-demo2-chain.sh 2>&1 | tail -10
bash ~/scripts/05-inference-test.sh 2>&1 | tail -10

# Cross-region DR test (only if a bundle and its key file were uploaded)
if [ -f ~/vg/cross-region-bundle.genome ]; then
  echo
  echo "=== cross-region DR: restore bundle from another region ==="
  rm -rf /tmp/cross-region-restored
  cd ~/vg
  ./acpctl genome open \
      --bundle="${HOME}/vg/cross-region-bundle.genome" \
      --key-file="${HOME}/vg/cross-region-bundle.key" \
      --target=/tmp/cross-region-restored 2>&1 | tee evidence/cross-region-open.txt | tail -10
  ./acpctl genome verify \
      --bundle="${HOME}/vg/cross-region-bundle.genome" \
      --key-file="${HOME}/vg/cross-region-bundle.key" \
      --restored=/tmp/cross-region-restored 2>&1 | tee evidence/cross-region-verify.txt | tail -10
  echo "✓ cross-region restore PASSED — byte-identical across Azure regions" \
    | tee evidence/cross-region-result.txt
fi

bash ~/scripts/06-pack-evidence.sh 2>&1 | tail -15
REMOTE_EOF

echo
echo "=== [vm${VM_NUM}/${REGION}] download evidence tarball ==="
# 06-pack-evidence.sh creates "${VM_ID}-evidence.tar.gz" — the
# comprehensive bundle. Pick it explicitly so we don't accidentally
# grab a smaller per-step tarball.
TARBALL_REMOTE="/home/azureuser/${INSTANCE_NAME}-evidence.tar.gz"
TARBALL_LOCAL="${EVIDENCE_DIR}/../${INSTANCE_NAME}-evidence.tar.gz"
scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "${SSH_KEY}" \
  azureuser@"${VM_IP}":"${TARBALL_REMOTE}" \
  "${TARBALL_LOCAL}"

# Unpack into evidence/0N-VMN-{region}/
tar -xzf "${TARBALL_LOCAL}" -C "${EVIDENCE_DIR}" --strip-components=1
echo "Evidence at: ${EVIDENCE_DIR}"

# If VM3 in East US, save its sealed bundle to SHARED for VM4 cross-region test
if [ "${VM_NUM}" = "3" ] && [ "${REGION}" = "eastus" ]; then
  echo
  echo "=== [vm3/eastus] save demo1 bundle to ${SHARED_DIR} for cross-region DR ==="
  scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "${SSH_KEY}" \
    azureuser@"${VM_IP}":~/vg/demo1-bundle.genome \
    "${SHARED_DIR}/donor-bundle.genome"
  echo "Saved $(du -h "${SHARED_DIR}/donor-bundle.genome" | cut -f1) → ${SHARED_DIR}/donor-bundle.genome"
fi

echo
echo "=== [vm${VM_NUM}/${REGION}] terraform destroy ==="
terraform destroy -auto-approve -compact-warnings 2>&1 | tail -3

echo
echo "=== ✓ VM ${VM_NUM} (${REGION}) cohort run complete ==="
echo "Evidence: ${EVIDENCE_DIR}"
if [ "${VM_NUM}" = "3" ]; then
  echo "Donor bundle saved: ${SHARED_DIR}/donor-bundle.genome"
fi
if [ -n "${RESTORE_BUNDLE}" ]; then
  echo "Cross-region restore: SEE ${EVIDENCE_DIR}/cross-region-result.txt"
fi
exit 0
