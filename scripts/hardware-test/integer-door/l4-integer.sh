#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Startup script for the L4 VM: the integer door across the CPU/GPU
# boundary, on two genomes.
#
#   A. Qwen2.5-0.5B-Instruct fine-tuned on this VM's CPU (float32, as the
#      continuity drills do), its integer references recorded on the CPU;
#      sealed, restored, then the integer door measured on the CPU and on
#      the L4 against those references — the same bytes or not — and the
#      gate run on the L4 at zero tolerance, where the float doors must
#      fail and the integer door must open, and at the default tolerance.
#   B. Qwen2.5-7B-Instruct fine-tuned on the L4 in bfloat16, its integer
#      references recorded on the L4; the integer door measured on the L4
#      (all fixtures) and on the CPU (the first three: a 7B integer
#      forward on eight cores is slow) against those references.
#
# Results go to out/gpu/ in the run's bucket; DONE or FAILED marks the
# end. The adapters stay here.
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
DOOR="env PYTHONPATH=/opt/worker TOKENIZERS_PARALLELISM=false /opt/vg/bin/python -m vg_genome door"

step "inputs"
gcs_get in/acpctl /usr/local/bin/acpctl && chmod +x /usr/local/bin/acpctl
gcs_get in/worker.tgz /root/worker.tgz && tar -xzf /root/worker.tgz -C /opt/worker
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; } > "$OUT/metadata.txt"
{ uname -a; lscpu; free -g; df -h /; } > "$OUT/system.txt"
sha256sum /usr/local/bin/acpctl /root/worker.tgz > "$OUT/inputs.sha256"
( cd /opt/worker && find vg_genome -name '*.py' | sort | xargs sha256sum ) > "$OUT/worker.sha256"

step "GPU driver"
for i in $(seq 1 90); do nvidia-smi > "$OUT/nvidia-smi.txt" 2>&1 && break; sleep 10; done
nvidia-smi > "$OUT/nvidia-smi.txt"

step "python runtime (CUDA 12.6 wheels)"
mark runtime_start
python_runtime https://download.pytorch.org/whl/cu126
/opt/vg/bin/python -c "import torch; print(torch.__version__, torch.version.cuda, torch.cuda.get_device_name(0), torch.cuda.get_device_properties(0).total_memory)" > "$OUT/torch.txt"
PYTHONPATH=/opt/worker /opt/vg/bin/python -c "import torch; from vg_genome import integer; print('cpu divides exactly:', integer.device_divides_exactly(torch.device('cpu'))); print('cuda divides exactly:', integer.device_divides_exactly(torch.device('cuda')))" > "$OUT/divides-exactly.txt"
mark runtime_end

# ---------------------------------------------------------------- A: 0.5B
step "A. base model $SMALL_REPO@$SMALL_REV"
base_model "$SMALL_REPO" "$SMALL_REV" /opt/base-small

step "A. fine-tune on the CPU in float32; the integer references are recorded on the CPU"
mark a_finetune_start
vg finetune --base /opt/base-small --base-name "$SMALL_REPO" \
  --data /opt/worker/examples/drill-facts.jsonl --prompts /opt/worker/examples/drill-prompts.json \
  --out /root/genome-a --targets q_proj,v_proj --rank 8 --alpha 16 --steps 120 --lr 3e-4 \
  --max-len 64 --threads "$(nproc)" --top-k 64 --new-tokens 16 --critical 4 --device cpu \
  > "$OUT/a-finetune.json" 2> "$OUT/a-finetune.log"
mark a_finetune_end
cp /root/genome-a/genome.json "$OUT/a-genome.json"; cp /root/genome-a/fixtures.json "$OUT/a-fixtures.json"

step "A. seal, restore, verify"
acpctl genome seal --content-dir /root/genome-a --output /root/a.genome --key-out /root/a.key --json > "$OUT/a-seal.json"
acpctl genome open --bundle /root/a.genome --key-file /root/a.key --target /root/restored-a --json > "$OUT/a-open.json"
acpctl genome verify --bundle /root/a.genome --key-file /root/a.key --restored /root/restored-a --json > "$OUT/a-verify.json"
shred -u /root/a.key

step "A. the integer door on the CPU, against the references (the same machine)"
mark a_int_cpu_start
vg measure --genome /root/restored-a --base /opt/base-small --device cpu --door integer > "$OUT/a-measure-integer-cpu.json" 2> "$OUT/a-measure-integer-cpu.log"
mark a_int_cpu_end

step "A. the integer door on the L4, against the references recorded on the CPU"
mark a_int_gpu_start
vg measure --genome /root/restored-a --base /opt/base-small --device cuda --door integer > "$OUT/a-measure-integer-cuda.json" 2> "$OUT/a-measure-integer-cuda.log"
mark a_int_gpu_end
gpu_mem

step "A. the float door on the L4 (the cross-device float error, for context)"
vg measure --genome /root/restored-a --base /opt/base-small --device cuda > "$OUT/a-measure-float-cuda.json" 2> "$OUT/a-measure-float-cuda.log"

step "A. gate on the L4 at zero tolerance: the float doors must fail, the integer door must open"
mark a_gate_tol0_start
acpctl genome gate --genome /root/restored-a --atol 0 --rtol 0 --json -- $DOOR --genome /root/restored-a --base /opt/base-small --device cuda > "$OUT/a-gate-cuda-tol0.json" || echo "a gate cuda tol0: exit $?" >> "$OUT/steps.txt"
mark a_gate_tol0_end
step "A. gate on the L4 at the default tolerance, and on the CPU"
acpctl genome gate --genome /root/restored-a --json -- $DOOR --genome /root/restored-a --base /opt/base-small --device cuda > "$OUT/a-gate-cuda.json" || echo "a gate cuda: exit $?" >> "$OUT/steps.txt"
acpctl genome gate --genome /root/restored-a --json -- $DOOR --genome /root/restored-a --base /opt/base-small --device cpu > "$OUT/a-gate-cpu.json" || echo "a gate cpu: exit $?" >> "$OUT/steps.txt"

# ---------------------------------------------------------------- B: 7B
step "B. base model $LARGE_REPO@$LARGE_REV"
mark b_download_start
base_model "$LARGE_REPO" "$LARGE_REV" /opt/base-large
mark b_download_end

step "B. fine-tune on the L4 in bfloat16; the integer references are recorded on the L4"
mark b_finetune_start
gpu_mem
vg finetune --base /opt/base-large --base-name "$LARGE_REPO" \
  --data /opt/worker/examples/drill-facts.jsonl --prompts /opt/worker/examples/drill-prompts.json \
  --out /root/genome-b --targets q_proj,v_proj --rank 8 --alpha 16 --steps 160 --lr 3e-4 \
  --max-len 64 --threads "$(nproc)" --top-k 64 --new-tokens 16 --critical 4 \
  --device cuda --dtype bfloat16 \
  > "$OUT/b-finetune.json" 2> "$OUT/b-finetune.log"
mark b_finetune_end
gpu_mem
cp /root/genome-b/genome.json "$OUT/b-genome.json"; cp /root/genome-b/fixtures.json "$OUT/b-fixtures.json"

step "B. seal, restore"
acpctl genome seal --content-dir /root/genome-b --output /root/b.genome --key-out /root/b.key --json > "$OUT/b-seal.json"
acpctl genome open --bundle /root/b.genome --key-file /root/b.key --target /root/restored-b --json > "$OUT/b-open.json"
shred -u /root/b.key

step "B. the integer door on the L4, against the references (the same device)"
mark b_int_gpu_start
vg measure --genome /root/restored-b --base /opt/base-large --device cuda --door integer > "$OUT/b-measure-integer-cuda.json" 2> "$OUT/b-measure-integer-cuda.log"
mark b_int_gpu_end
gpu_mem

step "B. the integer door on the CPU, the first three fixtures, against the references recorded on the L4"
mark b_int_cpu_start
timeout 2700 env PYTHONPATH=/opt/worker TOKENIZERS_PARALLELISM=false /opt/vg/bin/python -m vg_genome measure \
  --genome /root/restored-b --base /opt/base-large --device cpu --door integer --limit 3 > "$OUT/b-measure-integer-cpu.json" 2> "$OUT/b-measure-integer-cpu.log" || echo "b measure integer cpu: exit $?" >> "$OUT/steps.txt"
mark b_int_cpu_end
echo "elapsed_seconds=$(( $(date +%s) - T0 ))" >> "$OUT/steps.txt"

trap - ERR
finish DONE
