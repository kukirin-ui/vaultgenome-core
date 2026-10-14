#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# continuous-loop.sh — narrated end-to-end demo of CONTINUOUS model
# evolution under Vault Genome.
#
# What it shows:
#   1. Start with the MLX-converted Llama 3.2 1B base model (no adapter)
#   2. For each of N cycles:
#        a) Run mlx_lm.lora for K incremental fine-tune iterations
#        b) Save the resulting LoRA adapter to ./adapters/cycle-N/
#        c) Seal the adapter directory as a new .genome bundle
#           (gen-N), linked to the previous bundle as its parent
#   3. After all cycles complete:
#        - acpctl genome chain  → full timeline of generations
#        - acpctl genome lineage → walk parents back from latest to genesis
#        - acpctl genome rewind --bundle gen-2 --key-file gen-2.key → restore a middle generation
#        - inference comparison: base model vs gen-3 vs gen-N (final)
#        - tamper test on a middle generation → chain integrity breaks
#
# Designed for asciinema recording. Each step pauses briefly so a viewer
# can read the output before the next command lands.
#
# Requirements:
#   - acpctl binary (default: ../bin/acpctl)
#   - python3 venv with mlx-lm installed (default: /tmp/mlx-venv)
#   - mlx-community/Llama-3.2-1B-Instruct-4bit downloaded to HF cache
#   - dataset at ./lora-demo/data/{train,valid}.jsonl
#   - bash, sha256sum (or shasum on macOS), dd

set -euo pipefail

# ----- configuration ---------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ACPCTL="${ACPCTL:-${SCRIPT_DIR}/../bin/acpctl}"
VENV="${VENV:-/tmp/mlx-venv}"
DATA_DIR="${DATA_DIR:-${SCRIPT_DIR}/lora-demo/data}"
WORK_DIR="${WORK_DIR:-/tmp/vault-genome-cycle}"
MODEL="${MODEL:-mlx-community/Llama-3.2-1B-Instruct-4bit}"
CYCLES="${CYCLES:-6}"
ITERS_PER_CYCLE="${ITERS_PER_CYCLE:-10}"
LORA_LAYERS="${LORA_LAYERS:-4}"
PROBE_PROMPT='What is TAP V0.1 in Vault Genome? One short sentence.'
PAUSE="${PAUSE:-1.5}"

# ----- helpers ---------------------------------------------------------------

if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
    GREEN=$'\033[32m'; YELLOW=$'\033[33m'; CYAN=$'\033[36m'
    DIM=$'\033[2m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
    GREEN=""; YELLOW=""; CYAN=""; DIM=""; BOLD=""; RESET=""
fi

step() { echo; echo "${BOLD}${CYAN}▸ $*${RESET}"; sleep 1; }
note() { echo "${DIM}# $*${RESET}"; }
ok()   { echo "${GREEN}✓ $*${RESET}"; }
warn() { echo "${YELLOW}! $*${RESET}"; }
run()  { echo "${DIM}\$${RESET} $*"; eval "$@"; sleep "$PAUSE"; }

cleanup() {
    note "cleanup: removing $WORK_DIR"
    rm -rf "$WORK_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# ----- preflight -------------------------------------------------------------

if [ ! -x "$ACPCTL" ]; then
    echo "continuous-loop.sh: acpctl not found at $ACPCTL" >&2
    exit 1
fi
if [ ! -d "$VENV" ]; then
    echo "continuous-loop.sh: mlx venv not found at $VENV" >&2
    echo "Bootstrap with: python3 -m venv $VENV && source $VENV/bin/activate && pip install mlx-lm" >&2
    exit 1
fi
if [ ! -f "$DATA_DIR/train.jsonl" ] || [ ! -f "$DATA_DIR/valid.jsonl" ]; then
    echo "continuous-loop.sh: training data not found at $DATA_DIR" >&2
    exit 1
fi

# Activate the MLX venv for the rest of the script.
# shellcheck disable=SC1091
source "$VENV/bin/activate"

# Stage acpctl on a path-friendly location so every command in the demo
# reads as just `acpctl ...` (clearer in the asciinema recording, and
# avoids word-splitting issues when ACPCTL contains spaces).
ACPCTL_LINK_DIR="$(mktemp -d)"
ln -sf "$ACPCTL" "$ACPCTL_LINK_DIR/acpctl"
export PATH="$ACPCTL_LINK_DIR:$PATH"
trap 'cleanup; rm -rf "$ACPCTL_LINK_DIR"' EXIT

# ----- demo ------------------------------------------------------------------

if [ -t 1 ]; then printf '\033[2J\033[H'; fi
mkdir -p "$WORK_DIR/adapters" "$WORK_DIR/generations"

echo "${BOLD}Vault Genome — continuous-cycle demo${RESET}"
echo "${DIM}Real LoRA fine-tune on Llama 3.2 1B · ${CYCLES} cycles × ${ITERS_PER_CYCLE} iters · chain of generation bundles${RESET}"
sleep 2

step "Show the starting state — base model only, no adapter, no generations sealed"
run "ls -la \"$WORK_DIR/generations/\""
run "echo 'base model: $MODEL'"

step "Capture a baseline answer from the model BEFORE any fine-tune. We'll compare against this at the end."
echo "${DIM}\$${RESET} python -m mlx_lm generate --model $MODEL --prompt \"$PROBE_PROMPT\" --max-tokens 50 --temp 0"
BASELINE_RESPONSE=$(python -m mlx_lm generate --model "$MODEL" --prompt "$PROBE_PROMPT" --max-tokens 50 --temp 0 2>/dev/null \
    | sed -n '/^==========$/,/^==========$/p' | sed '1d;$d')
echo "$BASELINE_RESPONSE"
echo "$BASELINE_RESPONSE" > "$WORK_DIR/baseline-response.txt"
sleep "$PAUSE"

# --- continuous loop ---------------------------------------------------------

step "Start the continuous fine-tune cycle. Each pass: train ${ITERS_PER_CYCLE} more iters, save the adapter, seal it as a new generation linked to its parent."

PARENT_FLAG=""
PREV_ADAPTER=""
for i in $(seq 0 $((CYCLES - 1))); do
    CYCLE_DIR="$WORK_DIR/adapters/cycle-$i"
    BUNDLE="$WORK_DIR/generations/gen-$i.genome"
    KEY="$WORK_DIR/keys/gen-$i.key"
    mkdir -p "$CYCLE_DIR" "$WORK_DIR/keys"

    echo
    echo "${YELLOW}── cycle $i ───────────────────────────────────${RESET}"

    if [ -z "$PREV_ADAPTER" ]; then
        # First cycle: train from scratch.
        TRAIN_FLAGS="--train --iters ${ITERS_PER_CYCLE} --num-layers ${LORA_LAYERS} --batch-size 1 --learning-rate 1e-4 --max-seq-length 512 --steps-per-report 5 --steps-per-eval 50"
    else
        # Subsequent cycles: resume from previous adapter so each gen-N
        # is a real cumulative fine-tune state, not 10 fresh iters.
        TRAIN_FLAGS="--train --iters ${ITERS_PER_CYCLE} --num-layers ${LORA_LAYERS} --batch-size 1 --learning-rate 1e-4 --max-seq-length 512 --steps-per-report 5 --steps-per-eval 50 --resume-adapter-file $PREV_ADAPTER/adapters.safetensors"
    fi
    note "train: ${ITERS_PER_CYCLE} more iters → $CYCLE_DIR"
    python -m mlx_lm lora --model "$MODEL" $TRAIN_FLAGS --data "$DATA_DIR" --adapter-path "$CYCLE_DIR" 2>&1 \
        | grep -E "^Iter|^Saved|^Trainable" | tail -5
    PREV_ADAPTER="$CYCLE_DIR"

    note "seal: cycle-$i adapter → $(basename $BUNDLE) ${PARENT_FLAG:+(parent=$(basename ${PARENT_FLAG#--parent=}))}"
    acpctl genome seal --content-dir="$CYCLE_DIR" $PARENT_FLAG --output="$BUNDLE" --key-out="$KEY" --force 2>&1 \
        | grep -E "✓|key id|bundle bytes"

    PARENT_FLAG="--parent=$BUNDLE"
done

# --- chain ops ---------------------------------------------------------------

step "Show the full chain of generations — linked, sorted by generation, validated"
run "acpctl genome chain --dir=$WORK_DIR/generations"

step "Walk the lineage from the LATEST generation back to genesis"
LATEST=$((CYCLES - 1))
run "acpctl genome lineage --bundle=$WORK_DIR/generations/gen-$LATEST.genome --dir=$WORK_DIR/generations"

step "Rewind to a MIDDLE generation (gen-2) — restore that exact adapter to a fresh directory"
run "acpctl genome rewind --bundle=$WORK_DIR/generations/gen-2.genome --key-file=$WORK_DIR/keys/gen-2.key --target=$WORK_DIR/restored-gen-2"

# --- inference comparison ----------------------------------------------------

step "Inference comparison — same prompt against three different generations of the model"
echo
echo "${YELLOW}prompt:${RESET} $PROBE_PROMPT"

echo
echo "${BOLD}— BASELINE (no adapter, base model only):${RESET}"
echo "$BASELINE_RESPONSE"
sleep "$PAUSE"

GENS_TO_SHOW=$(echo "0 $((LATEST / 2)) $LATEST" | tr ' ' '\n' | sort -nu | tr '\n' ' ')
for GEN in $GENS_TO_SHOW; do
    GEN_BUNDLE="$WORK_DIR/generations/gen-$GEN.genome"
    GEN_RESTORED="$WORK_DIR/restored-gen-$GEN"
    if [ ! -d "$GEN_RESTORED" ]; then
        acpctl genome rewind --bundle="$GEN_BUNDLE" --key-file="$WORK_DIR/keys/gen-$GEN.key" --target="$GEN_RESTORED" >/dev/null
    fi
    echo
    echo "${BOLD}— GENERATION $GEN (after $(( (GEN+1) * ITERS_PER_CYCLE )) cumulative training iters):${RESET}"
    RESP=$(python -m mlx_lm generate --model "$MODEL" --adapter-path "$GEN_RESTORED" --prompt "$PROBE_PROMPT" --max-tokens 50 --temp 0 2>/dev/null \
        | sed -n '/^==========$/,/^==========$/p' | sed '1d;$d')
    echo "$RESP"
    sleep "$PAUSE"
done

# --- tamper test -------------------------------------------------------------

step "Tamper test: modify ONE byte deep inside a middle generation's sealed bytes. AEAD authentication should reject the unseal."
TAMPER_GEN=$((LATEST / 2))
TAMPER_TARGET="$WORK_DIR/generations/gen-${TAMPER_GEN}.genome"
note "target: gen-${TAMPER_GEN}.genome"

note "flipping one byte at offset 1 MiB inside the sealed payload..."
printf '\xff' | dd of="$TAMPER_TARGET" bs=1 seek=1048576 count=1 conv=notrunc 2>/dev/null
echo "$(basename $TAMPER_TARGET) modified — 1 byte flipped at offset 1048576"

note "after tamper: try to open the bundle with its key (the edited segment fails authentication)"
set +e
acpctl genome rewind --bundle="$TAMPER_TARGET" --key-file="$WORK_DIR/keys/gen-${TAMPER_GEN}.key" --target=/tmp/should-not-exist 2>&1
TAMPER_EXIT=$?
set -e
echo
if [ $TAMPER_EXIT -ne 0 ] && [ ! -d /tmp/should-not-exist ]; then
    ok "tamper rejected (exit $TAMPER_EXIT) — partial restore prevented"
else
    warn "tamper test did NOT reject as expected — exit=$TAMPER_EXIT"
fi

# --- closing -----------------------------------------------------------------

echo
echo "${BOLD}${GREEN}Done.${RESET} ${CYCLES} generations sealed in $WORK_DIR/generations/"
echo "Each generation is a real LoRA adapter snapshot at a specific point in training,"
echo "linked to its parent by SHA-256, and individually unsealable in seconds."
echo
echo "Same architecture extends to:"
echo "  - Periodic snapshots of a production model (every N hours)"
echo "  - RAG corpus ingest events"
echo "  - Inference lineage (each prompt/response → audit chain → model genome)"
echo "all under the same frozen Producer/Verifier/Sealer interface."
