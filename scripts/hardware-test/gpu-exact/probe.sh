#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Startup script of the EXACT probe VM (one NVIDIA GPU). It measures where
# CPU↔GPU float divergence enters a real Qwen2.5-0.5B forward and whether an
# integer projection is byte-identical across devices (exact_probe.py).
# Reports go to out/.
set -u
exec > >(tee -a /root/probe.log) 2>&1
BUCKET=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-bucket")
OUT=/root/out; mkdir -p "$OUT" /opt/worker; cd /root
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
finish() {
  cp /root/probe.log "$OUT/console.log" 2>/dev/null || true
  tar -C "$OUT" -czf /root/out.tgz . 2>/dev/null && gcs_put /root/out.tgz out.tgz 2>/dev/null || true
  echo "$1" > /root/marker; gcs_put /root/marker "out/$1" 2>/dev/null || true
}
trap 'finish FAILED' ERR

curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-common" > /root/common.sh
. /root/common.sh
set -eE

step "inputs"
gcs_get in/worker.tgz /root/worker.tgz && tar -xzf /root/worker.tgz -C /opt/worker
gcs_get in/exact_probe.py /root/exact_probe.py
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; } > "$OUT/metadata.txt"
{ uname -a; lscpu; } > "$OUT/system.txt" 2>&1

step "GPU driver"
for i in $(seq 1 90); do nvidia-smi > "$OUT/nvidia-smi.txt" 2>&1 && break; sleep 10; done
nvidia-smi > "$OUT/nvidia-smi.txt"

step "python runtime (CUDA 12.6 wheels)"
python_runtime https://download.pytorch.org/whl/cu126
/opt/vg/bin/python -c "import torch; print(torch.__version__, torch.version.cuda, torch.cuda.get_device_name(0))" > "$OUT/torch.txt"

step "base model $BASE_REPO@$BASE_REV"
base_model

step "EXACT probe (cpu/cuda × f32/f64, per-layer divergence, integer projection)"
TOKENIZERS_PARALLELISM=false /opt/vg/bin/python /root/exact_probe.py > "$OUT/probe.json" 2> "$OUT/probe.err"

trap - ERR
finish DONE
