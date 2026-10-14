#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Startup script of the drill's destination: a GCP VM with an NVIDIA GPU
# (an L4, or a T4 where no L4 is free).
# It restores the genome the SEV-SNP source sealed, then measures how the
# fine-tune came back: the equivalence gate on the GPU and on this VM's
# (Intel) CPU, fidelity token by token, and the recipe replayed on the GPU.
# Reports and logs go to out/gpu/.
set -u
exec > >(tee -a /root/drill.log) 2>&1
BUCKET=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-bucket")
OUT=/root/out; mkdir -p "$OUT" /opt/worker; cd /root
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
finish() {
  cp /root/drill.log "$OUT/console.log"
  for f in "$OUT"/*; do gcs_put "$f" "out/gpu/$(basename "$f")"; done
  echo "$1" > /root/marker; gcs_put /root/marker "out/gpu/$1"
}
trap 'finish FAILED' ERR

curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-common" > /root/common.sh
. /root/common.sh
set -eE

step "inputs"
gcs_get in/acpctl /usr/local/bin/acpctl && chmod +x /usr/local/bin/acpctl
gcs_get in/worker.tgz /root/worker.tgz && tar -xzf /root/worker.tgz -C /opt/worker
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; } > "$OUT/metadata.txt"
{ uname -a; lscpu; } > "$OUT/system.txt"

step "GPU driver"
for i in $(seq 1 90); do nvidia-smi > "$OUT/nvidia-smi.txt" 2>&1 && break; sleep 10; done
nvidia-smi > "$OUT/nvidia-smi.txt"

step "python runtime (CUDA 12.6 wheels)"
python_runtime https://download.pytorch.org/whl/cu126
/opt/vg/bin/python -c "import torch; print(torch.__version__, torch.version.cuda, torch.cuda.get_device_name(0))" > "$OUT/torch.txt"

step "base model $BASE_REPO@$BASE_REV"
base_model

step "wait for the hand-off from the SEV-SNP source"
# The source writes the bundle, then its key: once the key is there, both are.
umask 077
for i in $(seq 1 160); do gcs_get handoff/gen-1.key /root/gen-1.key 2>/dev/null && break; rm -f /root/gen-1.key; sleep 15; done
[ -s /root/gen-1.key ] || { echo "no hand-off after 40 minutes"; false; }
gcs_get handoff/gen-1.genome /root/gen-1.genome
umask 022

step "restore the sealed genome"
acpctl genome open --bundle /root/gen-1.genome --key-file /root/gen-1.key --target /root/restored --json > "$OUT/open-gpu.json"
acpctl genome verify --bundle /root/gen-1.genome --key-file /root/gen-1.key --restored /root/restored --json > "$OUT/verify-gpu.json"
shred -u /root/gen-1.key

step "gate and measure on the GPU"
acpctl genome gate --genome /root/restored --json -- env PYTHONPATH=/opt/worker TOKENIZERS_PARALLELISM=false \
  /opt/vg/bin/python -m vg_genome door --genome /root/restored --base /opt/base --device cuda > "$OUT/gate-gpu.json" || true
vg measure --genome /root/restored --base /opt/base --device cuda > "$OUT/measure-gpu.json" 2> "$OUT/measure-gpu.log"

step "gate and measure on this VM's CPU"
acpctl genome gate --genome /root/restored --json -- env PYTHONPATH=/opt/worker TOKENIZERS_PARALLELISM=false \
  /opt/vg/bin/python -m vg_genome door --genome /root/restored --base /opt/base --device cpu > "$OUT/gate-intel-cpu.json" || true
vg measure --genome /root/restored --base /opt/base --device cpu > "$OUT/measure-intel-cpu.json" 2> "$OUT/measure-intel-cpu.log"

step "replay the recipe on the GPU"
vg replay --genome /root/restored --base /opt/base --device cuda > "$OUT/replay-gpu.json" 2> "$OUT/replay-gpu.log" || true

trap - ERR
finish DONE
