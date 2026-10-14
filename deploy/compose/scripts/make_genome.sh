#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# make_genome.sh — give the compose demo a genome to restore. Builds a tiny
# random Llama and its tokenizer locally (the same one workers/genome's tests
# use; nothing is downloaded), fine-tunes a LoRA adapter on it with the real
# vg_genome worker, seals the genome with acpctl, and lands:
#
#   deploy/compose/models/base/      the public base model (mounted read-only
#                                    into the worker at /models/base)
#   deploy/compose/genomes/gen-0.genome  the sealed genome (mounted read-only
#   deploy/compose/genomes/gen-0.key     into sagvd at /var/lib/acp/genomes)
#
# Invoked by `make demo-genome`. To use a real model instead, point BASE_DIR
# at a local copy of it (e.g. Qwen/Qwen2.5-0.5B-Instruct) and DATA at your
# JSONL of {prompt, completion}; the worker container must then mount that
# same base directory (ACP_BASE_MODEL=/path/to/base make demo-up).
#
# Requirements: python3 with workers/genome/requirements.txt installed
# (pip install --index-url https://download.pytorch.org/whl/cpu torch==2.7.1;
# pip install -r workers/genome/requirements.txt), and acpctl built
# (make build). Both genomes/ and models/ are git-ignored: the key file must
# never be committed.

set -o errexit
set -o pipefail
set -o nounset

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROOT="$(cd "${COMPOSE_DIR}/../.." && pwd)"
WORKER="${ROOT}/workers/genome"
ACPCTL="${ACPCTL:-${ROOT}/bin/acpctl}"
PYTHON="${PYTHON:-python3}"
NAME="${NAME:-gen-0}"
GENOMES_DIR="${GENOMES_DIR:-${COMPOSE_DIR}/genomes}"
MODELS_DIR="${MODELS_DIR:-${COMPOSE_DIR}/models}"
BASE_DIR="${BASE_DIR:-${MODELS_DIR}/base}"
DATA="${DATA:-}"
STEPS="${STEPS:-20}"

if [[ ! -x "${ACPCTL}" ]]; then
  echo "make_genome.sh: acpctl not found at ${ACPCTL}; run 'make build' first" >&2
  exit 4
fi
if ! "${PYTHON}" -c "import torch, transformers, safetensors" >/dev/null 2>&1; then
  echo "make_genome.sh: ${PYTHON} lacks the worker runtime; install workers/genome/requirements.txt" >&2
  exit 4
fi
if [[ -e "${GENOMES_DIR}/${NAME}.genome" || -e "${GENOMES_DIR}/${NAME}.key" ]]; then
  echo "make_genome.sh: ${GENOMES_DIR}/${NAME}.genome or .key exists; remove them to reseal" >&2
  exit 2
fi
mkdir -p "${GENOMES_DIR}" "${MODELS_DIR}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export PYTHONPATH="${WORKER}"
export TOKENIZERS_PARALLELISM=false

if [[ -z "${DATA}" ]]; then
  echo "==> building a tiny base model at ${BASE_DIR} (nothing is downloaded)"
  rm -rf "${BASE_DIR}"
  DATA="${WORK}/train.jsonl"
  (cd "${WORKER}" && "${PYTHON}" -c 'import sys, json; sys.path.insert(0, "tests"); import conftest
conftest.make_base(sys.argv[1])
open(sys.argv[2], "w").write("".join(json.dumps(e) + "\n" for e in conftest.EXAMPLES))' "${BASE_DIR}" "${DATA}")
  BASE_NAME="tiny-llama"
  FT_ARGS=(--targets q_proj,v_proj,lm_head --lr 1e-2 --max-len 32 --top-k 8 --new-tokens 4)
else
  BASE_NAME="${BASE_NAME:-$(basename "${BASE_DIR}")}"
  FT_ARGS=()
fi

echo "==> fine-tuning a LoRA adapter (${STEPS} steps) and writing the genome"
"${PYTHON}" -m vg_genome finetune --base "${BASE_DIR}" --base-name "${BASE_NAME}" --data "${DATA}" \
  --out "${WORK}/genome" --steps "${STEPS}" --threads 1 "${FT_ARGS[@]}"

echo "==> sealing ${GENOMES_DIR}/${NAME}.genome (key to ${NAME}.key, mode 0600)"
"${ACPCTL}" genome seal --content-dir "${WORK}/genome" \
  --output "${GENOMES_DIR}/${NAME}.genome" --key-out "${GENOMES_DIR}/${NAME}.key" --json

echo "==> done. Submit it with: GENOME_BUNDLE=${NAME}.genome GENOME_KEY=${NAME}.key make demo-submit"
