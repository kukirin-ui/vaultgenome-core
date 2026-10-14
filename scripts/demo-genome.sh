#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# demo-genome.sh — narrated end-to-end demo of model continuity over real bytes.
#
# What it shows:
#   1. A real Llama 3.2 3B model running locally under Ollama
#   2. `acpctl genome seal` — capture the model's full on-disk state
#      (manifest + content-addressed blobs, ~1.9 GB) and seal it inside a
#      Simulated TEE
#   3. `acpctl genome inspect` — display envelope metadata without unsealing
#   4. `acpctl genome open` — restore the bundle into a fresh OLLAMA_MODELS
#      directory at /tmp/restored-ollama
#   5. `acpctl genome verify --restored` — re-hash every blob on disk and
#      confirm bit-identical recovery
#   6. Spin up a second Ollama daemon on :11435 pointing at /tmp/restored-ollama
#   7. Send the same deterministic prompt to both daemons and show the
#      responses match byte-for-byte (proves stateful inference continuity)
#   8. Flip a single byte deep inside the bundle and prove the unseal
#      refuses with an authentication failure (proves AEAD integrity)
#
# Designed for asciinema recording. Each step pauses briefly so a viewer
# can read the output before the next command lands.
#
# Requirements:
#   - Ollama installed and running on :11434 with `llama3.2:3b` already pulled
#   - acpctl built at $ACPCTL (default: ../bin/acpctl)
#   - python3 (for JSON pretty-printing of inference responses)

set -euo pipefail

# ----- configuration ---------------------------------------------------------

ACPCTL="${ACPCTL:-$(dirname "$0")/../bin/acpctl}"
MODEL="${MODEL:-llama3.2:3b}"
BUNDLE="${BUNDLE:-/tmp/llama-genome-demo.genome}"
KEY="${KEY:-/tmp/llama-genome-demo.key}"
RESTORED="${RESTORED:-/tmp/restored-ollama}"
TAMPERED="${TAMPERED:-/tmp/tampered.genome}"
ORIGINAL_PORT="${ORIGINAL_PORT:-11434}"
RESTORED_PORT="${RESTORED_PORT:-11435}"
OLLAMA_BIN="${OLLAMA_BIN:-/Applications/Ollama.app/Contents/Resources/ollama}"
PROMPT='List three companies, one per line, that operate at-scale confidential computing programs. No prose, just three lines.'
PAUSE="${PAUSE:-2}"

# ----- helpers ---------------------------------------------------------------

# ANSI escape codes directly — no TERM dependency, works in raw asciinema and pipes.
if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    CYAN=$'\033[36m'
    DIM=$'\033[2m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
else
    GREEN=""; YELLOW=""; CYAN=""; DIM=""; BOLD=""; RESET=""
fi

step() {
    echo
    echo "${BOLD}${CYAN}▸ $*${RESET}"
    sleep 1
}

note() {
    echo "${DIM}# $*${RESET}"
}

ok() {
    echo "${GREEN}✓ $*${RESET}"
}

warn() {
    echo "${YELLOW}! $*${RESET}"
}

run() {
    echo "${DIM}\$${RESET} $*"
    eval "$@"
    sleep "$PAUSE"
}

run_silent() {
    eval "$@" >/dev/null 2>&1 || true
}

inference() {
    local port=$1
    curl -s "http://127.0.0.1:${port}/api/generate" \
        -d "{\"model\":\"${MODEL}\",\"prompt\":$(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$PROMPT"),\"stream\":false,\"options\":{\"seed\":42,\"temperature\":0}}" \
        | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('response',''))"
}

cleanup() {
    note "cleanup: stopping restored daemon and removing temp files"
    run_silent "lsof -ti:${RESTORED_PORT} | xargs -r kill"
    run_silent "rm -rf ${BUNDLE} ${KEY} ${TAMPERED} ${RESTORED}"
}

trap cleanup EXIT

# ----- preflight -------------------------------------------------------------

if [ ! -x "$ACPCTL" ]; then
    echo "demo-genome.sh: acpctl binary not found at $ACPCTL" >&2
    echo "Build with: go build -o ./bin/acpctl ./cmd/acpctl" >&2
    exit 1
fi
if ! curl -sf "http://localhost:${ORIGINAL_PORT}/api/version" >/dev/null; then
    echo "demo-genome.sh: original Ollama daemon not responding on :${ORIGINAL_PORT}" >&2
    echo "Start it with: open /Applications/Ollama.app  (or: ollama serve &)" >&2
    exit 1
fi

# ----- demo ------------------------------------------------------------------

if [ -t 1 ]; then printf '\033[2J\033[H'; fi
echo "${BOLD}Vault Genome — local model-continuity demo${RESET}"
echo "${DIM}Real Llama 3.2 3B · Simulated TEE · two-daemon round-trip · tamper test${RESET}"
sleep 2

step "Show that the model is real and the original daemon is serving it"
run "${OLLAMA_BIN} list"

step "Seal the model: read manifest + every content-addressed blob, stream them as a deterministic tar through AES-256-GCM in 1 MiB segments under a fresh key, write one .genome bundle — and the key to its own 0600 file"
run "${ACPCTL} genome seal --model=${MODEL} --output=${BUNDLE} --key-out=${KEY} --force"

step "Inspect the sealed bundle without its key — header only"
run "${ACPCTL} genome inspect --bundle=${BUNDLE}"

step "Open the bundle with its key into a fresh OLLAMA_MODELS directory at ${RESTORED}/models"
run "${ACPCTL} genome open --bundle=${BUNDLE} --key-file=${KEY} --target=${RESTORED}"

step "Verify: open the bundle again with its key, re-hash every restored blob and confirm each matches the sealed record"
run "${ACPCTL} genome verify --bundle=${BUNDLE} --key-file=${KEY} --restored=${RESTORED}"

step "Spin up a second Ollama daemon on :${RESTORED_PORT} pointing at the restored models directory"
note "this is the 'second machine' — independent process, independent OLLAMA_MODELS tree"
OLLAMA_HOST=127.0.0.1:${RESTORED_PORT} OLLAMA_MODELS=${RESTORED}/models "${OLLAMA_BIN}" serve >/tmp/ollama-restored.log 2>&1 &
RESTORED_PID=$!
note "restored daemon pid: ${RESTORED_PID}"
# Wait for the daemon to come up.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -sf "http://127.0.0.1:${RESTORED_PORT}/api/version" >/dev/null; then
        break
    fi
    sleep 1
done
run "curl -s http://127.0.0.1:${RESTORED_PORT}/api/tags | python3 -m json.tool"

step "Send the same deterministic prompt (seed=42, temp=0) to BOTH daemons"
echo
echo "${YELLOW}prompt:${RESET} ${PROMPT}"
echo
echo "${BOLD}— ORIGINAL daemon (port ${ORIGINAL_PORT}, models in \$HOME/.ollama):${RESET}"
ORIG_RESP=$(inference "${ORIGINAL_PORT}")
echo "${ORIG_RESP}"
sleep "$PAUSE"
echo
echo "${BOLD}— RESTORED daemon (port ${RESTORED_PORT}, models in ${RESTORED}/models):${RESET}"
REST_RESP=$(inference "${RESTORED_PORT}")
echo "${REST_RESP}"
sleep "$PAUSE"

echo
if [ "$ORIG_RESP" = "$REST_RESP" ]; then
    ok "BIT-IDENTICAL inference across two independent daemons over a sealed-and-restored model bundle"
else
    warn "responses diverged — inspect $ORIG_RESP vs $REST_RESP"
fi
sleep "$PAUSE"

step "Tamper test: flip one byte deep inside the sealed bundle, then try to open it"
note "the segment holding that byte fails AES-256-GCM authentication; the restore stages everything and moves nothing into place"
run "cp ${BUNDLE} ${TAMPERED}"
run "printf '\\xff' | dd of=${TAMPERED} bs=1 seek=104857600 count=1 conv=notrunc 2>/dev/null && echo 'flipped 1 byte at offset 100 MiB'"
echo
echo "${DIM}\$${RESET} ${ACPCTL} genome open --bundle=${TAMPERED} --key-file=${KEY} --target=/tmp/should-not-exist"
set +e
"${ACPCTL}" genome open --bundle="${TAMPERED}" --key-file="${KEY}" --target=/tmp/should-not-exist
TAMPER_EXIT=$?
set -e
echo
if [ ${TAMPER_EXIT} -ne 0 ] && [ ! -d /tmp/should-not-exist ]; then
    ok "tamper rejected (exit ${TAMPER_EXIT}); /tmp/should-not-exist was never created — no partial write"
else
    warn "tamper test did NOT reject as expected — exit=${TAMPER_EXIT}"
fi

echo
echo "${BOLD}${GREEN}Done.${RESET} Bundle ${BUNDLE} can be stored anywhere — it opens only with ${KEY}."
echo "Across clouds, sagvd crosscloud-restore releases that key only to an attested, allow-listed"
echo "destination TEE, which restores the model itself and signs a receipt (ADR 0011)."
