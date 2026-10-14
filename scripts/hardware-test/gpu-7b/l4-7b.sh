#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Startup script for the L4 VM: fine-tune Qwen2.5-7B-Instruct in bfloat16
# on the GPU with vg_genome, seal the genome, restore it from the bundle,
# gate and measure it on the same GPU (the pinned runtime) and on this
# VM's CPU, replay the recipe on the GPU. Results go to out/gpu/ in the
# run's bucket; DONE or FAILED marks the end. The adapter stays here.
set -u
exec > >(tee -a /root/run.log) 2>&1
BUCKET=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-bucket")
OUT=/root/out; mkdir -p "$OUT" /opt/worker; cd /root
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
mark() { echo "$1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" >> "$OUT/timeline.txt"; }
gpu_mem() { nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader >> "$OUT/gpu-memory.txt" 2>/dev/null || true; }
finish() {
  cp /root/run.log "$OUT/console.log"
  for f in "$OUT"/*; do gcs_put "$f" "out/gpu/$(basename "$f")"; done
  echo "$1" > /root/marker; gcs_put /root/marker "out/gpu/$1"
}
trap 'finish FAILED' ERR
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-common" > /root/common.sh
. /root/common.sh
set -eE
T0=$(date +%s)

step "inputs"
gcs_get in/acpctl /usr/local/bin/acpctl && chmod +x /usr/local/bin/acpctl
gcs_get in/worker.tgz /root/worker.tgz && tar -xzf /root/worker.tgz -C /opt/worker
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; } > "$OUT/metadata.txt"
{ uname -a; lscpu; free -g; df -h /; } > "$OUT/system.txt"
sha256sum /usr/local/bin/acpctl /root/worker.tgz > "$OUT/inputs.sha256"

step "GPU driver"
for i in $(seq 1 90); do nvidia-smi > "$OUT/nvidia-smi.txt" 2>&1 && break; sleep 10; done
nvidia-smi > "$OUT/nvidia-smi.txt"

step "python runtime (CUDA 12.6 wheels)"
mark runtime_start
python_runtime https://download.pytorch.org/whl/cu126
/opt/vg/bin/python -c "import torch; print(torch.__version__, torch.version.cuda, torch.cuda.get_device_name(0), torch.cuda.get_device_properties(0).total_memory)" > "$OUT/torch.txt"
mark runtime_end

step "base model $BASE_REPO@$BASE_REV"
mark download_start
base_model
mark download_end

step "fine-tune on the L4 in bfloat16 (the recipe records device and dtype)"
mark finetune_start
gpu_mem
vg finetune --base /opt/base --base-name "$BASE_REPO" \
  --data /opt/worker/examples/drill-facts.jsonl --prompts /opt/worker/examples/drill-prompts.json \
  --out /root/genome --targets q_proj,v_proj --rank 8 --alpha 16 --steps 160 --lr 3e-4 \
  --max-len 64 --threads "$(nproc)" --top-k 64 --new-tokens 16 --critical 4 \
  --device cuda --dtype bfloat16 \
  > "$OUT/finetune.json" 2> "$OUT/finetune.log"
mark finetune_end
gpu_mem
cp /root/genome/genome.json /root/genome/fixtures.json "$OUT/"

step "seal"
acpctl genome seal --content-dir /root/genome --output /root/gen-1.genome --key-out /root/gen-1.key --json > "$OUT/seal.json"

step "restore from the bundle"
acpctl genome open --bundle /root/gen-1.genome --key-file /root/gen-1.key --target /root/restored --json > "$OUT/open.json"
acpctl genome verify --bundle /root/gen-1.genome --key-file /root/gen-1.key --restored /root/restored --json > "$OUT/verify.json"
shred -u /root/gen-1.key

step "gate and measure on the L4 (the pinned runtime)"
mark gate_gpu_start
acpctl genome gate --genome /root/restored --json -- env PYTHONPATH=/opt/worker TOKENIZERS_PARALLELISM=false \
  /opt/vg/bin/python -m vg_genome door --genome /root/restored --base /opt/base --device cuda > "$OUT/gate-gpu.json" || true
mark gate_gpu_end
vg measure --genome /root/restored --base /opt/base --device cuda > "$OUT/measure-gpu.json" 2> "$OUT/measure-gpu.log"
mark measure_gpu_end
gpu_mem

step "replay the recipe on the L4"
vg replay --genome /root/restored --base /opt/base --device cuda > "$OUT/replay-gpu.json" 2> "$OUT/replay-gpu.log" || true
mark replay_gpu_end

step "gate and measure on this VM's CPU (bfloat16, $(nproc) threads)"
mark gate_cpu_start
timeout 1800 acpctl genome gate --genome /root/restored --json -- env PYTHONPATH=/opt/worker TOKENIZERS_PARALLELISM=false \
  /opt/vg/bin/python -m vg_genome door --genome /root/restored --base /opt/base --device cpu > "$OUT/gate-cpu.json" || echo "gate on cpu: exit $?" >> "$OUT/steps.txt"
mark gate_cpu_end
timeout 2400 env PYTHONPATH=/opt/worker TOKENIZERS_PARALLELISM=false /opt/vg/bin/python -m vg_genome measure \
  --genome /root/restored --base /opt/base --device cpu > "$OUT/measure-cpu.json" 2> "$OUT/measure-cpu.log" || echo "measure on cpu: exit $?" >> "$OUT/steps.txt"
mark measure_cpu_end
echo "elapsed_seconds=$(( $(date +%s) - T0 ))" >> "$OUT/steps.txt"

trap - ERR
finish DONE
