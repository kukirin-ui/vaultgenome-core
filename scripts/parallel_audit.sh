#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# parallel_audit.sh — reports the fraction of top-level Test* functions
# that call t.Parallel(). Enforces the doctrinal floor (≥80%) recorded
# in 00_Bootstrap_Contracts_Doctrine.md §13 (Stage G Iteration 4).
#
# Rationale
#
# The Go race detector only trips when goroutines actually overlap on
# shared memory. A codebase that declares t.Parallel() on 80%+ of its
# tests exposes concurrency bugs under `go test -race ./...` that would
# otherwise sleep for years. This script keeps that coverage from
# regressing.
#
# Exit codes:
#   0 — OK (coverage ≥ PARALLEL_AUDIT_FLOOR, default 80).
#   1 — coverage below the floor.
#   2 — invocation / environment error.
#
# Usage: run from the repo root. No arguments.

set -euo pipefail

FLOOR="${PARALLEL_AUDIT_FLOOR:-80}"

if ! command -v grep >/dev/null 2>&1; then
  echo "parallel_audit: grep not found" >&2
  exit 2
fi

# Count every top-level Test function. We restrict the match to
# 'func TestXxx(t *testing.T)' — benchmarks, helpers, and example
# functions are deliberately excluded from the denominator because
# t.Parallel() is only meaningful on test functions.
#
# Tight regex so `TestingFoo` helpers and `funcTest*` typos don't
# contribute false positives to the denominator.
TESTS_TOTAL=$(grep -rhE '^func Test[A-Za-z0-9_]*\(t \*testing\.T\) \{$' \
  --include='*_test.go' . | wc -l | tr -d ' ')

if [ "$TESTS_TOTAL" -eq 0 ]; then
  echo "parallel_audit: no Test* functions found — is this the repo root?" >&2
  exit 2
fi

# Count tests that actually declare t.Parallel() anywhere in their body.
# The heuristic scans every Test* function's opening line and the line
# immediately following; we consider the test "parallel-enabled" if the
# first non-blank line of its body is `t.Parallel()`. This matches the
# idiomatic placement and is what the sweep script in
# scripts/parallel_audit.sh (self) produced.
#
# Implementation note: awk is simpler than a multi-pass grep pipeline
# for the "next non-blank line after a matching header" pattern.
TESTS_PARALLEL=$(find . -name '*_test.go' -print0 \
  | xargs -0 awk '
      /^func Test[A-Za-z0-9_]*\(t \*testing\.T\) \{$/ {
        # Read the next non-blank line; if it is t.Parallel(), count.
        n = 1
        do {
          if ((getline line) <= 0) { break }
          if (line ~ /^[[:space:]]*$/) { n++; continue }
          if (line ~ /^[[:space:]]*t\.Parallel\(\)[[:space:]]*$/) { count++ }
          break
        } while (1)
      }
      END { print count+0 }
    ')

# Percentage, rounded down. Bash arithmetic is integer-only; scale by
# 100 before dividing so we don't lose the fractional part entirely.
PCT=$(( TESTS_PARALLEL * 100 / TESTS_TOTAL ))

echo "parallel_audit: $TESTS_PARALLEL / $TESTS_TOTAL tests call t.Parallel() (${PCT}%)"

if [ "$PCT" -lt "$FLOOR" ]; then
  echo "parallel_audit: FAIL — coverage ${PCT}% < floor ${FLOOR}%" >&2
  exit 1
fi

echo "parallel_audit: OK — coverage ${PCT}% ≥ floor ${FLOOR}%"
exit 0
