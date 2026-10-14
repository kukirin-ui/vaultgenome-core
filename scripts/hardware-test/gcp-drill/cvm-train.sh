#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Startup script of the drill's source: a GCP AMD SEV-SNP Confidential VM.
# It fine-tunes the base model deterministically on its CPUs, inside the
# confidential guest, writes the genome, seals it (acpctl genome seal),
# proves the sealed genome restores here byte-exact (open + gate + replay),
# and hands the bundle and its key to the GPU leg through the run's
# private bucket. Reports and logs go to out/source/; the key goes only
# to handoff/ and dies with the bucket.
set -u
exec > >(tee -a /root/drill.log) 2>&1
BUCKET=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-bucket")
OUT=/root/out; mkdir -p "$OUT" /opt/worker; cd /root
step() { echo "== $(date -u +%H:%M:%S) $*"; echo "== $(date -u +%H:%M:%S) $*" >> "$OUT/steps.txt"; }
finish() { # finish <marker>
  cp /root/drill.log "$OUT/console.log"
  for f in "$OUT"/*; do gcs_put "$f" "out/source/$(basename "$f")"; done
  echo "$1" > /root/marker; gcs_put /root/marker "out/source/$1"
}
trap 'finish FAILED' ERR

curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/vg-common" > /root/common.sh
. /root/common.sh
set -eE

step "inputs"
gcs_get in/acpctl /usr/local/bin/acpctl && chmod +x /usr/local/bin/acpctl
gcs_get in/worker.tgz /root/worker.tgz && tar -xzf /root/worker.tgz -C /opt/worker
{ echo "instance=$(md name)"; echo "zone=$(md zone | awk -F/ '{print $NF}')"; echo "machine=$(md machine-type | awk -F/ '{print $NF}')"; } > "$OUT/metadata.txt"
{ uname -a; lscpu; dmesg | grep -iE "SEV|SNP" | head -8; } > "$OUT/system.txt"

step "python runtime (CPU)"
python_runtime https://download.pytorch.org/whl/cpu

step "base model $BASE_REPO@$BASE_REV"
base_model

step "fine-tune (deterministic, $(nproc) threads, inside the SEV-SNP guest)"
vg finetune --base /opt/base --base-name "$BASE_REPO" \
  --data /opt/worker/examples/drill-facts.jsonl --prompts /opt/worker/examples/drill-prompts.json \
  --out /root/genome --targets q_proj,v_proj --rank 8 --alpha 16 --steps 160 --lr 3e-4 \
  --max-len 64 --threads "$(nproc)" --top-k 64 --new-tokens 16 --critical 4 \
  > "$OUT/finetune.json" 2> "$OUT/finetune.log"
cp /root/genome/genome.json /root/genome/fixtures.json "$OUT/"

step "seal"
acpctl genome seal --content-dir /root/genome --output /root/gen-1.genome --key-out /root/gen-1.key --json > "$OUT/seal.json"

step "restore here from the bundle, gate, measure, replay"
acpctl genome open --bundle /root/gen-1.genome --key-file /root/gen-1.key --target /root/restored --json > "$OUT/open-source.json"
acpctl genome gate --genome /root/restored --json -- env PYTHONPATH=/opt/worker TOKENIZERS_PARALLELISM=false \
  /opt/vg/bin/python -m vg_genome door --genome /root/restored --base /opt/base --device cpu > "$OUT/gate-source-cpu.json" || true
vg measure --genome /root/restored --base /opt/base --device cpu > "$OUT/measure-source-cpu.json" 2> "$OUT/measure-source-cpu.log"
vg replay --genome /root/restored --base /opt/base --device cpu > "$OUT/replay-source-cpu.json" 2> "$OUT/replay-source-cpu.log"

step "hand off the bundle and its key"
gcs_put /root/gen-1.genome handoff/gen-1.genome
gcs_put /root/gen-1.key handoff/gen-1.key
shred -u /root/gen-1.key

trap - ERR
finish DONE
