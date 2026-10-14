#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# 05-inference-test.sh — empirical inference comparison: original vs
# restored daemon. Same logic as GCP version.

set -euo pipefail

MODEL="${MODEL:-llama3.2:3b}"
PROMPT="${PROMPT:-Name three companies running confidential computing programs.}"
SEED="${SEED:-42}"
EVIDENCE_DIR="$HOME/vg/attestation-validation/$(hostname)"

cd ~/vg
mkdir -p "$EVIDENCE_DIR"

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
echo "$ORIG" > "$EVIDENCE_DIR/inference-original.txt"
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
echo "$REST" > "$EVIDENCE_DIR/inference-restored.txt"
echo "$REST"

echo
echo "=== diff ==="
if diff -u "$EVIDENCE_DIR/inference-original.txt" "$EVIDENCE_DIR/inference-restored.txt"; then
  echo "✓ BYTE-IDENTICAL — inference continuity proven empirically"
else
  echo "✗ DIVERGED — investigate"
  exit 1
fi

echo
echo "Next: ./scripts/06-pack-evidence.sh"
