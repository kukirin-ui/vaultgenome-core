#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 05-inference-test.sh — empirical inference comparison on the restored
# model. Confirms the restored bundle isn't just byte-identical (which
# verify already proved) but actually produces identical model output
# under deterministic sampling. The strongest possible proof of
# functional continuity over the seal/restore boundary.
#
# Trick: copy the restored model files into Ollama's default location
# (/usr/share/ollama/.ollama/models/) and let the systemd-managed Ollama
# daemon use them. This avoids a known Ollama quirk where custom
# OLLAMA_MODELS paths sometimes fail to register the model on startup.

set -euo pipefail

MODEL="${MODEL:-llama3.2:3b}"
PROMPT="${PROMPT:-Name three companies running confidential computing programs.}"
SEED="${SEED:-42}"

cd ~/vg

if [ ! -d /tmp/demo1-restored/models ]; then
  echo "ERROR: /tmp/demo1-restored not found — run 03-demo1-single-bundle.sh first."
  exit 1
fi

echo "=== capture original-daemon response (model in /usr/share/ollama) ==="
sudo systemctl restart ollama
sleep 5
ORIG=$(curl -s http://127.0.0.1:11434/api/generate \
  -d "$(printf '{"model":"%s","prompt":%s,"stream":false,"options":{"seed":%d,"temperature":0}}' \
        "$MODEL" "$(printf '%s' "$PROMPT" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')" "$SEED")" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["response"])')
echo "$ORIG" >evidence/inference-original.txt
echo "$ORIG"

echo
echo "=== overlay restored files onto Ollama default location ==="
sudo systemctl stop ollama
sudo cp -r /tmp/demo1-restored/models/blobs/. /usr/share/ollama/.ollama/models/blobs/
sudo cp -r /tmp/demo1-restored/models/manifests/. /usr/share/ollama/.ollama/models/manifests/
sudo chown -R ollama:ollama /usr/share/ollama/.ollama
sudo systemctl start ollama
sleep 5

echo
echo "=== capture restored-from-bundle response ==="
REST=$(curl -s http://127.0.0.1:11434/api/generate \
  -d "$(printf '{"model":"%s","prompt":%s,"stream":false,"options":{"seed":%d,"temperature":0}}' \
        "$MODEL" "$(printf '%s' "$PROMPT" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')" "$SEED")" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["response"])')
echo "$REST" >evidence/inference-restored.txt
echo "$REST"

echo
echo "=== diff ==="
if diff -u evidence/inference-original.txt evidence/inference-restored.txt; then
  echo "✓ BYTE-IDENTICAL — inference continuity proven empirically"
else
  echo "✗ DIVERGED — investigate"
  exit 1
fi

echo
echo "Next: ./scripts/06-pack-evidence.sh"
