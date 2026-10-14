#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# check_dep_depth.sh — fails if the transitive dependency graph exceeds the
# depth cap set by docs/doctrine/ci-security-policy.md §3.2.
#
# Doctrinal role
#
#   Every transitive hop multiplies the supply-chain blast radius. Policy §3.2
#   therefore fixes a hard cap of three: no direct dependency may pull in a
#   chain longer than 3 edges (direct = depth 1, its dep = depth 2, etc.).
#   Exceptions are permissible only when documented in
#   docs/dependencies/exceptions.md with both founders' sign-off.
#
# Algorithm
#
#   1. Determine the main module path via `go list -m`.
#   2. Enumerate edges with `go mod graph`. Each line is
#          <parent@version>   <child@version>
#      except lines whose first field is the main module, which has no
#      @version suffix.
#   3. BFS from the main module. Depth of main = 0. Depth of a direct
#      dependency = 1. Fail if any reachable node has depth > MAX_DEPTH.
#   4. Explicitly allow entries listed in scripts/dep_depth_exceptions.txt
#      (one module-path prefix per line, `#` comments ignored). This mirrors
#      the exceptions mechanism in docs/doctrine/ci-security-policy.md §3.2 without
#      requiring the script to parse the prose markdown.
#
# The script does not modify files and is safe to run locally.

set -euo pipefail

MAX_DEPTH="${MAX_DEPTH:-3}"
EXCEPTIONS_FILE="${EXCEPTIONS_FILE:-scripts/dep_depth_exceptions.txt}"

if ! command -v go >/dev/null 2>&1; then
  echo "check_dep_depth: FAIL — 'go' is not on PATH" >&2
  exit 1
fi

MAIN="$(go list -m 2>/dev/null)"
if [[ -z "$MAIN" ]]; then
  echo "check_dep_depth: FAIL — 'go list -m' returned no main module" >&2
  exit 1
fi

# Load exceptions, if any.
declare -a EXCEPTIONS=()
if [[ -f "$EXCEPTIONS_FILE" ]]; then
  while IFS= read -r raw; do
    line="${raw%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    EXCEPTIONS+=("$line")
  done < "$EXCEPTIONS_FILE"
fi

# Capture the graph once, then let awk compute depths.
GRAPH_FILE="$(mktemp)"
trap 'rm -f "$GRAPH_FILE"' EXIT
go mod graph > "$GRAPH_FILE"

# The awk program below performs BFS over the module graph. It exits with
# status 0 if all reachable nodes have depth <= max_depth (ignoring any
# node whose path-prefix matches an exception), and status 1 otherwise.
awk \
  -v main="$MAIN" \
  -v max_depth="$MAX_DEPTH" \
  -v exceptions_joined="$(printf '%s\n' "${EXCEPTIONS[@]:-}")" '
BEGIN {
  # Parse exceptions.
  n_exc = 0
  if (exceptions_joined != "") {
    n_exc = split(exceptions_joined, exc_lines, "\n")
  }
}
{
  # Build adjacency list. We keep keys with their @version intact; BFS visits
  # *nodes* (i.e. module@version), which is what the MVS graph encodes.
  parent = $1
  child  = $2
  edges[parent] = edges[parent] SUBSEP child
}
END {
  # BFS from main. Main is stored as its path without @version.
  depth[main] = 0
  q_head = 1
  q_tail = 1
  queue[q_tail] = main

  worst = 0
  fail = 0
  n_bad = 0

  while (q_head <= q_tail) {
    node = queue[q_head++]
    d = depth[node]
    if (d > worst) worst = d

    if (!(node in edges)) continue

    # Split children on SUBSEP; first token is empty because of prepend.
    n = split(edges[node], cs, SUBSEP)
    for (i = 1; i <= n; i++) {
      c = cs[i]
      if (c == "") continue
      if (c in depth) continue
      depth[c] = d + 1

      # Check depth.
      if (depth[c] > max_depth) {
        # Strip @version for exception matching and reporting.
        path = c
        sub(/@[^ ]*$/, "", path)
        excused = 0
        for (k = 1; k <= n_exc; k++) {
          e = exc_lines[k]
          if (e == "") continue
          if (path == e) { excused = 1; break }
          if (index(path, e "/") == 1) { excused = 1; break }
        }
        if (!excused) {
          fail = 1
          n_bad++
          bad[n_bad] = sprintf("depth=%d  %s", depth[c], c)
        }
      }

      q_tail++
      queue[q_tail] = c
    }
  }

  if (fail) {
    printf("check_dep_depth: FAIL — %d node(s) exceed depth %d\n", n_bad, max_depth)
    # Emit at most 50 offending entries; beyond that the list is not actionable.
    cap = (n_bad > 50) ? 50 : n_bad
    for (i = 1; i <= cap; i++) print "  " bad[i]
    if (n_bad > cap) printf("  ... (%d more suppressed)\n", n_bad - cap)
    exit 1
  }

  printf("check_dep_depth: PASS — worst observed depth = %d (cap = %d)\n", worst, max_depth)
  exit 0
}
' "$GRAPH_FILE"
