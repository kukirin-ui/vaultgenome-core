#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# check_dep_allowlist.sh — fails if this module declares a direct Go-module
# dependency that is not present on scripts/dep_allowlist.txt.
#
# Doctrinal role
#
#   Policy docs/doctrine/ci-security-policy.md §3.1 fixes the set of allowed direct
#   dependencies. A silent addition — even a reputable one — is a governance
#   violation: every external surface we link against widens the supply-chain
#   blast radius. This script is the mechanical enforcement of that rule.
#
# Behavior
#
#   1. Reads the allowlist file (one module-path prefix per line; `#` comments
#      and blank lines ignored).
#   2. Reads the main module's DIRECT dependencies from `go mod edit -json`
#      (each require whose `Indirect` flag is false) — exact under vendoring
#      and module-graph pruning. See the detailed note above DIRECT_RAW below.
#   3. For every direct dependency, requires that its module path either
#      matches an allowlist entry exactly OR has an allowlist entry as a
#      path-segment prefix (e.g. `golang.org/x/crypto/chacha20` is accepted
#      if `golang.org/x/crypto` is listed).
#   4. Prints every violation and exits 1; otherwise prints PASS.
#
# The script does not modify files and is safe to run locally.

set -euo pipefail

ALLOWLIST_FILE="${ALLOWLIST_FILE:-scripts/dep_allowlist.txt}"

if ! command -v go >/dev/null 2>&1; then
  echo "check_dep_allowlist: FAIL — 'go' is not on PATH" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "check_dep_allowlist: FAIL — 'jq' is not on PATH (needed to read 'go mod edit -json')" >&2
  exit 1
fi

if [[ ! -f "$ALLOWLIST_FILE" ]]; then
  echo "check_dep_allowlist: FAIL — allowlist file not found at $ALLOWLIST_FILE" >&2
  exit 1
fi

# Parse the allowlist into an array, stripping comments and whitespace.
declare -a ALLOWED=()
while IFS= read -r raw; do
  line="${raw%%#*}"
  # Trim leading/trailing whitespace.
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  [[ -z "$line" ]] && continue
  ALLOWED+=("$line")
done < "$ALLOWLIST_FILE"

if [[ "${#ALLOWED[@]}" -eq 0 ]]; then
  echo "check_dep_allowlist: FAIL — allowlist file is empty" >&2
  exit 1
fi

# Enumerate DIRECT dependencies only.
#
# Source of truth: `go mod edit -json`, which reads go.mod and reports each
# require entry's `Indirect` flag — the machine-readable form of the
# `// indirect` marker. A direct dependency is a require whose Indirect is
# false. This is the exact distinction policy §3.1 (direct → allowlist) and
# §3.2 (indirect → transitive depth cap) draw.
#
# Why not `go mod graph`? Under Go 1.17+ module-graph pruning the main
# module's go.mod records EVERY require — direct and indirect alike — so the
# main-module node in `go mod graph` roots edges to indirect deps too. Keying
# on "first column == main module" therefore misclassifies indirect deps
# (e.g. gopkg.in/yaml.v3, pulled in transitively by testify) as direct and
# demands they be allowlisted — the opposite of what §3.2 requires.
#
# Why not `go mod vendor`'s modules.txt `## explicit` marker? Same trap: with
# graph pruning, indirect requires recorded in go.mod are also written as
# `## explicit` in vendor/modules.txt, so it cannot distinguish either.
#
# `go mod edit -json` reads only go.mod (no build list, no network), so it is
# unaffected by the vendor directory that makes `go list -m all` fail here.
DIRECT_RAW="$(go mod edit -json | jq -r '.Require[]? | select(.Indirect | not) | .Path' | sort -u)"

if [[ -z "$DIRECT_RAW" ]]; then
  echo "check_dep_allowlist: PASS — module declares no direct dependencies"
  exit 0
fi

fail=0
while IFS= read -r dep; do
  [[ -z "$dep" ]] && continue
  # Strip @version suffix, keep only the module path.
  path="${dep%@*}"
  allowed=0
  for entry in "${ALLOWED[@]}"; do
    if [[ "$path" == "$entry" || "$path" == "$entry"/* ]]; then
      allowed=1
      break
    fi
  done
  if [[ "$allowed" -eq 0 ]]; then
    echo "check_dep_allowlist: FORBIDDEN direct dependency: $path"
    echo "  add a justification at docs/dependencies/$(basename "$path").md"
    echo "  and append '$path' to $ALLOWLIST_FILE per docs/doctrine/ci-security-policy.md §3.1"
    fail=1
  fi
done <<<"$DIRECT_RAW"

if [[ "$fail" -ne 0 ]]; then
  echo "check_dep_allowlist: FAIL"
  exit 1
fi

echo "check_dep_allowlist: PASS"
