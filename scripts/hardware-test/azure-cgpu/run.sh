#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# A confidential GPU on Azure: one Standard_NCC40ads_H100_v5 Confidential VM
# (AMD SEV-SNP guest with an NVIDIA H100 in confidential-computing mode,
# Ubuntu 24.04 CVM image) in West Europe, brought up the way Microsoft's
# onboarding package does it (kernel, the NVIDIA open driver, the local GPU
# verifier), then asked for everything the composite verifier needs:
#
#   - the HCL report from the vTPM (the SEV-SNP report whose REPORT_DATA is
#     the hash of the runtime data carrying the vTPM's attestation key);
#   - the VCEK and chain Azure serves for this chip (IMDS THIM);
#   - two TPM quotes by that attestation key over the PCRs with our nonces;
#   - the GPU's attestation report and certificate chain for the same
#     nonce, NVIDIA's local verifier's verdict, and NVIDIA's remote
#     attestation service's signed EAT for it, with the JWKS it verifies
#     under;
#   - the 7B genome path on the H100 (bfloat16; float32 as a measurement).
#
# Everything collected is public by construction (reports, certificates,
# tokens, measurements); the genome key is shredded on the VM, no key or
# seed leaves it. The VM's resources are deleted at the end — after the
# evidence has been read back and checked.
#
# Usage: run.sh [resource-group] [location]      (about 60 minutes; ~$9/h): the capture, then the Return Path
set -euo pipefail
RG="${1:-vg-cgpu-weu}"
LOC="${2:-westeurope}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOW="$(echo "$STAMP" | tr 'A-Z' 'a-z')"
VM="vg-cgpu-$LOW"
ADMIN="vg"
SSH_PUB="${VG_SSH_PUB:-$HOME/.ssh/id_ed25519.pub}"
SSH_KEY="${SSH_PUB%.pub}"
IMAGE="Canonical:ubuntu-24_04-lts:cvm:24.04.202607310"   # the version Microsoft's onboarding V4.4.1 pins for Ubuntu 24.04
PKG_URL="https://github.com/Azure/az-cgpu-onboarding/releases/download/V4.4.1/cgpu-onboarding-package.tar.gz"
PKG_SHA="455ac1c1318d857c36dbae3432e023aebcb983dbcbd0ab1c3973af3a43eb480e"
BUILD="$(mktemp -d)"
EVIDENCE="$HERE/evidence/$STAMP"
CREATED=0
OK=0

cleanup() {
  if [ "$CREATED" = 1 ] && [ "$OK" = 0 ] && [ -n "${VG_KEEP_ON_FAILURE:-}" ]; then
    echo "cleanup: VG_KEEP_ON_FAILURE is set and the run failed — $VM is left running for a look; delete it yourself (az group delete -n $RG)"
    rm -rf "$BUILD"; return
  fi
  if [ "$CREATED" = 1 ]; then
    echo "cleanup: deleting $VM and its disk, NIC, IP and NSG"
    az vm delete -g "$RG" -n "$VM" --yes >/dev/null 2>&1 || true
    for r in $(az resource list -g "$RG" --query "[?contains(name, '$VM')].id" -o tsv 2>/dev/null); do
      az resource delete --ids "$r" >/dev/null 2>&1 || true
    done
    for r in $(az resource list -g "$RG" --query "[?contains(name, '$VM')].id" -o tsv 2>/dev/null); do
      az resource delete --ids "$r" >/dev/null 2>&1 || true
    done
    az resource list -g "$RG" --query "[].{name:name,type:type}" -o table 2>/dev/null || true
  fi
  rm -rf "$BUILD"
}
trap cleanup EXIT

ssh_vm() { ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ServerAliveInterval=15 -o ServerAliveCountMax=8 -o ConnectTimeout=20 "$ADMIN@$IP" "$@"; }
scp_to() { scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q "$@" "$ADMIN@$IP:"; }
wait_ssh() { # wait_ssh <minutes>
  local deadline=$(( $(date +%s) + $1 * 60 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    ssh_vm -o BatchMode=yes true >/dev/null 2>&1 && return 0
    sleep 10
  done
  echo "no ssh after $1 minutes"; return 1
}

echo "build acpctl (linux/amd64) and pack workers/genome"
( cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/acpctl" ./cmd/acpctl )
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$BUILD/worker.tgz" -C "$ROOT/workers/genome" --exclude __pycache__ --exclude .pytest_cache vg_genome requirements.txt examples
echo "Microsoft's onboarding package V4.4.1 (pinned by SHA-256)"
curl -fsSL "$PKG_URL" -o "$BUILD/cgpu-onboarding-package.tar.gz"
echo "$PKG_SHA  $BUILD/cgpu-onboarding-package.tar.gz" | shasum -a 256 -c - >/dev/null

MYIP="$(curl -s https://api.ipify.org)"
echo "boot $VM ($IMAGE, Standard_NCC40ads_H100_v5, $LOC; ssh from $MYIP only)"
az group create -n "$RG" -l "$LOC" >/dev/null
az vm create -g "$RG" -n "$VM" -l "$LOC" --image "$IMAGE" --size Standard_NCC40ads_H100_v5 \
  --security-type ConfidentialVM --os-disk-security-encryption-type DiskWithVMGuestState \
  --enable-secure-boot true --enable-vtpm true --os-disk-size-gb 200 \
  --public-ip-sku Standard --admin-username "$ADMIN" --ssh-key-values "@$SSH_PUB" \
  --nsg-rule SSH --query '{ip:publicIpAddress,state:powerState}' -o json > "$BUILD/create.json"
CREATED=1
IP="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ip"])' "$BUILD/create.json")"
NSG="$(az network nsg list -g "$RG" --query "[?contains(name, '$VM')].name" -o tsv | head -1)"
RULE="$(az network nsg rule list -g "$RG" --nsg-name "$NSG" --query "[?destinationPortRange=='22'].name" -o tsv | head -1)"
az network nsg rule update -g "$RG" --nsg-name "$NSG" -n "$RULE" --source-address-prefixes "$MYIP/32" >/dev/null
echo "vm $VM at $IP; ssh rule $NSG/$RULE limited to $MYIP"
wait_ssh 10

echo "upload"
scp_to "$BUILD/cgpu-onboarding-package.tar.gz" "$BUILD/acpctl" "$BUILD/worker.tgz" "$HERE/cgpu-capture.sh" "$HERE/nras_attest.py"
ssh_vm 'tar -xzf cgpu-onboarding-package.tar.gz && sha256sum cgpu-onboarding-package.tar.gz acpctl worker.tgz'

echo "step 0: kernel (dist-upgrade, reboot)"
BOOTED="$(ssh_vm 'uptime -s')"
ssh_vm 'cd cgpu-onboarding-package && sudo bash step-0-prepare-kernel.sh 2>&1 | tail -5; sudo systemctl reboot' || true
for i in $(seq 1 60); do   # until the guest has booted again
  sleep 10
  NOW="$(ssh_vm -o BatchMode=yes 'uptime -s' 2>/dev/null || true)"
  [ -n "$NOW" ] && [ "$NOW" != "$BOOTED" ] && break
done
ssh_vm 'echo "kernel after step 0: $(uname -r)"'
echo "step 1: the NVIDIA open driver in confidential-computing mode"
# Ubuntu's signed kernel modules for the 595 server driver are built against
# one userspace version; noble-updates carries a newer one that apt would
# pick and fail on. Pin the userspace to the version the modules need.
# The X driver package is a strict "=" dependency of the driver meta-package
# and is not matched by the nvidia-* patterns, so it is pinned by name too
# (seen 2026-09-16: a newer 595 build in noble-updates left it unpinned and
# the install unresolvable).
ssh_vm 'MOD=$(apt-cache show linux-modules-nvidia-595-server-open-$(uname -r) 2>/dev/null | sed -n "s/.*nvidia-kernel-common-595-server (<= \([^)]*\)).*/\1/p" | head -1); \
  V=$(apt-cache madison nvidia-kernel-common-595-server | awk "{print \$3}" | sort -V | while read x; do dpkg --compare-versions "$x" le "${MOD:-999}" && echo "$x"; done | tail -1); \
  echo "modules want nvidia-kernel-common-595-server <= ${MOD:-?}; pinning userspace ${V:-?}"; \
  [ -n "$V" ] && printf "Package: nvidia-*-595-server* libnvidia-*-595-server* xserver-xorg-video-nvidia-595-server nvidia-kernel-common-595-server nvidia-kernel-source-595-server-open nvidia-driver-595-server-open nvidia-utils-595-server nvidia-compute-utils-595-server nvidia-firmware-595-server*\nPin: version %s\nPin-Priority: 1001\n" "$V" | sudo tee /etc/apt/preferences.d/nvidia-595-userspace.pref >/dev/null'
ssh_vm 'cd cgpu-onboarding-package && sudo bash step-1-install-gpu-driver.sh 2>&1 | tail -30'
ssh_vm 'nvidia-smi -L && nvidia-smi conf-compute -q' || { echo "no working NVIDIA driver after step 1"; exit 1; }
echo "step 2: Microsoft's attestation tools (the local GPU verifier, azure-guest-attest)"
ssh_vm 'cd cgpu-onboarding-package && sudo bash step-2-attestation.sh --install-to-usr-local 2>&1 | tail -40'

echo "capture + the genome path on the confidential GPU (${VG_BASE_REPO:-Qwen/Qwen2.5-7B-Instruct}; this takes a while)"
# The guest's sshd can be away for a minute after Microsoft's attestation
# step (seen 2026-09-16: a banner-exchange timeout right after step 2);
# wait for it rather than fail the run on the first dropped connection.
wait_ssh 5 || { echo "the guest did not answer SSH before the capture"; exit 1; }
ssh_vm "sudo env VG_STAMP=$STAMP VG_BASE_REPO=${VG_BASE_REPO:-} VG_BASE_REV=${VG_BASE_REV:-} bash cgpu-capture.sh 2>&1 | tail -60"

echo "read the evidence back"
mkdir -p "$EVIDENCE"
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q "$ADMIN@$IP:out/$STAMP.tgz" "$BUILD/"
tar -xzf "$BUILD/$STAMP.tgz" -C "$EVIDENCE" --strip-components=1   # the guest packs out/<stamp>/
( cd "$EVIDENCE" && grep -v ' sha256sums.txt$' sha256sums.txt | shasum -a 256 -c --quiet ) && echo "evidence checksums: ok"
ls "$EVIDENCE" | wc -l
grep -q 'CAPTURE DONE' "$EVIDENCE/steps.txt" || { echo "the capture did not finish cleanly"; cat "$EVIDENCE/steps.txt"; exit 1; }
for f in gate-gpu.json nras-response.json snp-report.bin quote1.msg; do [ -s "$EVIDENCE/$f" ] || { echo "the capture has no $f"; exit 1; }; done
echo "capture evidence: $EVIDENCE"

echo "the Return Path on the guest: sagvd and acp-compute as azure-cgpu, the escrow key sealed to the vTPM, the handshake under gpu_policy.evaluation both"
( cd "$ROOT" && for b in sagvd acp-compute; do CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/$b" "./cmd/$b"; done )
( cd "$ROOT/deploy/compose/keygen" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$BUILD/keygen" . )
wait_ssh 5 || { echo "the guest did not answer SSH before the Return Path"; exit 1; }
scp_to "$BUILD/sagvd" "$BUILD/acp-compute" "$BUILD/keygen" "$HERE/returnpath-cgpu.sh" "$HERE/gpu-token.py"
ssh_vm "sudo env VG_STAMP=$STAMP VG_CAPTURE_STAMP=$STAMP bash returnpath-cgpu.sh 2>&1 | tail -40"
wait_ssh 5 || { echo "the guest did not answer SSH after the Return Path"; exit 1; }
mkdir -p "$EVIDENCE-returnpath"
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q "$ADMIN@$IP:out/$STAMP-returnpath.tgz" "$BUILD/"
tar -xzf "$BUILD/$STAMP-returnpath.tgz" -C "$EVIDENCE-returnpath" --strip-components=1
( cd "$EVIDENCE-returnpath" && grep -v ' sha256sums.txt$' sha256sums.txt | shasum -a 256 -c --quiet ) && echo "return path checksums: ok"
grep -q 'RETURNPATH DONE' "$EVIDENCE-returnpath/steps.txt" || { echo "the Return Path did not finish cleanly"; cat "$EVIDENCE-returnpath/steps.txt"; exit 1; }
for f in escrow-provision.json escrow-reprovision.json job.json audit-verify.json; do [ -s "$EVIDENCE-returnpath/$f" ] || { echo "the Return Path run has no $f"; exit 1; }; done
OK=1
echo "evidence: $EVIDENCE and $EVIDENCE-returnpath"
