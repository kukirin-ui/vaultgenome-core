#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# full-test-run.sh — orchestrate the AWS Nitro Enclaves kit end-to-end
# against a single EC2 instance. Run from your laptop.
#
# Workflow:
#   1. terraform apply        provisions m5.xlarge with Nitro Enclaves enabled
#   2. waits for SSH
#   3. uploads the tree       rsync of this repository to ~/core on the instance
#   4. bootstrap              nitro-cli, Docker, Go 1.27.2, the allocator, cbor2
#   5. enclave image          debug image from acpctl source: build manifest,
#                             REPORT_DATA = SHA-512 of the manifest
#   6. production image       vsock-attest inside; EXPECTED PCR0/1/2 from describe-eif
#   7. production capture     enclave launched WITHOUT --debug-mode, the document
#                             comes back over vsock, PCRs checked against expected
#   8. root CA                AWS Nitro Root CA G1 fetched and checked (archive
#                             sha256, certificate fingerprint)
#   9. Demo 1, Demo 2         seal/open/verify round trip, tamper, chain of six
#  10. (optional) inference   same prompt and seed before and after restore
#  11. packs evidence         tar archive, downloaded to the laptop
#  12. terraform destroy      also on failure (trap), after a best-effort download
#
# The debug-mode capture (02-capture-attestation.sh, 02b-cryptographic-
# attestation.sh) needs an in-enclave acpctl attestation command this tree
# does not ship (VERIFIABLE-CLAIMS: no Nitro verifier is claimed); the
# production path above is the kit's path. Validate the downloaded document
# on the laptop with scripts/08-normalize-attestation-output.py and collate
# with scripts/07-cross-vm-matrix.sh.
#
# Required env:
#   TF_VAR_ssh_key_name=<existing EC2 key pair name>
# Optional env:
#   SSH_KEY=<private key path>           default ~/.ssh/<key pair name>.pem
#   TF_VAR_region, TF_VAR_availability_zone, TF_VAR_instance_name
#   TF_VAR_allowed_ssh_cidr=<ip>/32      default 0.0.0.0/0 — set it
#   TF_VAR_create_iam_role=false         EC2-only operators (see terraform/main.tf)
#   EVIDENCE_OUT=<dir>                   where the archive and run notes land (default .)

set -euo pipefail

KIT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CORE_DIR="$(cd "$KIT_DIR/../../.." && pwd)"

if [ -z "${TF_VAR_ssh_key_name:-}" ]; then
  echo "ERROR: set TF_VAR_ssh_key_name=<your EC2 key pair name> before running."
  exit 1
fi
SSH_KEY="${SSH_KEY:-$HOME/.ssh/${TF_VAR_ssh_key_name}.pem}"
if [ ! -f "$SSH_KEY" ]; then
  echo "ERROR: SSH private key not found at $SSH_KEY (set SSH_KEY=<path>)."
  exit 1
fi
EVIDENCE_OUT="${EVIDENCE_OUT:-$(pwd)}"
mkdir -p "$EVIDENCE_OUT"
EVIDENCE_OUT="$(cd "$EVIDENCE_OUT" && pwd)"

SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o ConnectTimeout=10 -o ServerAliveInterval=30)
REMOTE_KIT='$HOME/core/scripts/hardware-test/aws-nitro/scripts'   # expanded on the instance

PUBLIC_IP=""
INSTANCE_ID=""
AZ=""
STATE="started"

cleanup() {
  rc=$?
  set +e
  if [ "$STATE" != "packed" ] && [ -n "$PUBLIC_IP" ]; then
    echo
    echo "=== run ended in state '$STATE': best-effort download of whatever the instance holds ==="
    ssh "${SSH_OPTS[@]}" "ec2-user@${PUBLIC_IP}" \
      'cd ~/vg/attestation-validation 2>/dev/null && tar czf ~/partial-evidence.tar.gz . && echo packed' \
      && scp "${SSH_OPTS[@]}" "ec2-user@${PUBLIC_IP}:~/partial-evidence.tar.gz" \
             "$EVIDENCE_OUT/${INSTANCE_ID:-unknown}-partial-evidence.tar.gz"
  fi
  echo
  echo "=== 12. teardown EC2 instance ==="
  cd "$KIT_DIR/terraform"
  terraform destroy -input=false -auto-approve
  echo "teardown done (run state: $STATE, exit $rc)"
  exit "$rc"
}
trap cleanup EXIT

echo "=== 1. provision EC2 instance with Nitro Enclaves enabled ==="
cd "$KIT_DIR/terraform"
terraform init -input=false
terraform apply -input=false -auto-approve

INSTANCE_ID="$(terraform output -raw instance_id)"
INSTANCE_NAME="$(terraform output -raw instance_name)"
PUBLIC_IP="$(terraform output -raw public_ip)"
AZ="$(terraform output -raw availability_zone)"
AMI_ID="$(terraform output -raw ami_id_used)"
echo "Instance: $INSTANCE_ID ($INSTANCE_NAME) at $PUBLIC_IP in $AZ, AMI $AMI_ID"
terraform output -json > "$EVIDENCE_OUT/terraform-outputs.json"
STATE="provisioned"

echo
echo "=== 1a. wait for SSH ==="
for _ in $(seq 1 60); do
  if ssh "${SSH_OPTS[@]}" "ec2-user@${PUBLIC_IP}" "echo ready" >/dev/null 2>&1; then
    break
  fi
  sleep 5
done
ssh "${SSH_OPTS[@]}" "ec2-user@${PUBLIC_IP}" "echo ready"

echo
echo "=== 2. upload the tree to ~/core (the kit's scripts run from it) ==="
rsync -az -e "ssh ${SSH_OPTS[*]}" \
  --exclude='.git' --exclude='dist' --exclude='.terraform' \
  --exclude='node_modules' --exclude='.venv' \
  "$CORE_DIR/" "ec2-user@${PUBLIC_IP}:~/core/"
STATE="uploaded"

echo
echo "=== 3. bootstrap (nitro-cli, Docker, Go, allocator, cbor2) ==="
# shellcheck disable=SC2029 # $REMOTE_KIT holds a literal $HOME for the instance's shell
ssh "${SSH_OPTS[@]}" "ec2-user@${PUBLIC_IP}" \
  "chmod +x $REMOTE_KIT/*.sh && $REMOTE_KIT/01-bootstrap-vm.sh"
STATE="bootstrapped"

echo
echo "=== 4-11. phases on the instance, with the ne and docker groups active ==="
ssh "${SSH_OPTS[@]}" "ec2-user@${PUBLIC_IP}" 'cat > ~/run-phases.sh' <<'PHASES'
#!/usr/bin/env bash
set -euo pipefail
export PATH="$PATH:/usr/local/go/bin:$HOME/.local/bin"
K="$HOME/core/scripts/hardware-test/aws-nitro/scripts"
cd "$HOME/core"
"$K/02-build-enclave-image.sh"
"$K/02d-build-enclave-image-prod.sh"
"$K/02e-capture-attestation-prod.sh"
"$K/02c-fetch-nitro-root-ca.sh"
"$K/03-demo1-single-bundle.sh"
"$K/04-demo2-chain.sh"
"$K/05-inference-test.sh" || echo "(inference skipped — non-fatal)"
"$K/06-pack-evidence.sh"
PHASES
ssh "${SSH_OPTS[@]}" "ec2-user@${PUBLIC_IP}" \
  'chmod +x ~/run-phases.sh && exec sg ne -c "exec sg docker -c ~/run-phases.sh"'
STATE="phases-done"

echo
echo "=== 11a. download evidence to the laptop ==="
EVIDENCE_FILE="${INSTANCE_ID}-${AZ}-aws-nitro-evidence.tar.gz"
scp "${SSH_OPTS[@]}" "ec2-user@${PUBLIC_IP}:~/${EVIDENCE_FILE}" "$EVIDENCE_OUT/"
ls -lh "$EVIDENCE_OUT/${EVIDENCE_FILE}"
STATE="packed"

echo
echo "evidence: $EVIDENCE_OUT/${EVIDENCE_FILE}"
echo "next, on the laptop:"
echo "  tar xzf $EVIDENCE_OUT/${EVIDENCE_FILE} -C <evidence-root>/01-VM1-${AZ}"
echo "  $KIT_DIR/scripts/08-normalize-attestation-output.py <evidence-root>/01-VM1-${AZ}"
echo "  $KIT_DIR/scripts/07-cross-vm-matrix.sh <evidence-root>"
echo
echo "=== ✓ all phases done; the trap tears the instance down ==="
