#!/bin/bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
# On the Azure VM after the failover: stop acp-bootstrap, gather its log,
# the restore receipts and reports (no keys), and pack out/destination.
set -u
H="$(pwd)"; OUT="$H/out/destination"
[ -f "$H/acp-bootstrap.pid" ] && kill -TERM "$(cat "$H/acp-bootstrap.pid")" 2>/dev/null; sleep 2
cp "$H/acp-bootstrap.log" "$OUT/acp-bootstrap.log" 2>/dev/null || true
ls -la "$H/restored" > "$OUT/restored-ls.txt" 2>/dev/null || true
for r in "$H"/restored/*.receipt.json; do [ -f "$r" ] && cp "$r" "$OUT/"; done
for d in "$H"/restored/*/; do [ -d "$d" ] && { echo "$(basename "$d")"; ls "$d" ; head -c 200 "$d/adapter/adapter_model.safetensors" 2>/dev/null | sha256sum; } >> "$OUT/restored-tree.txt"; done
curl -s http://127.0.0.1:8444/metrics > "$OUT/acp-bootstrap-metrics.txt" 2>/dev/null || true
ls "$H/bundles" > "$OUT/bundles-ls.txt" 2>/dev/null || true
echo "== COLLECTED" >> "$OUT/steps.txt"
( cd "$OUT" && sha256sum $(ls | grep -v '^sha256sums.txt$') > sha256sums.txt )
( cd "$H/out" && tar czf destination.tgz destination )
chown "$(stat -c %U "$H")" "$H/out/destination.tgz" 2>/dev/null || true
echo "DESTINATION COLLECTED"
