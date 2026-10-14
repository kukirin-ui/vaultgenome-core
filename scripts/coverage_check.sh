#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# coverage_check.sh — enforces the coverage policy in
# docs/doctrine/ci-security-policy.md §8.
#
# What is measured: statement coverage of every product package
# (internal/, cmd/, pkg/), read from a cross-package profile
# (`go test -coverpkg=./... -coverprofile=coverage.out ./...`, which is
# what `make coverage` produces). A statement counts as covered when any
# test in the module executes it; each statement is counted once, however
# many test binaries report it. Packages are weighted by statements, not
# by function.
#
# What is required: every product package reaches its class target —
#
#   internal/contracts/...               80%
#   internal/validation/operational/...  90%
#   internal/vault/orchestration/...     85%
#   everything else                      70%
#
# — unless scripts/coverage_floors.txt lists it with a lower floor.
# That file is a ratchet for packages still below target: a listed
# package may not drop below its floor, floors are only ever raised,
# and a package leaves the file once it meets its target. The product
# total may not drop below the file's `total` floor either. A new
# package cannot be added below target without a reviewed floors entry.
#
# Usage: scripts/coverage_check.sh [profile]   (default: coverage.out)

set -euo pipefail

PROFILE="${1:-coverage.out}"
FLOORS="$(dirname "$0")/coverage_floors.txt"
MODULE="github.com/vault-genome/vaultgenome-core/"

if [ ! -f "$PROFILE" ]; then
  echo "coverage_check: FAIL — $PROFILE not found. Run 'make coverage' first."
  exit 1
fi
if ! head -1 "$PROFILE" | grep -q '^mode: '; then
  echo "coverage_check: FAIL — $PROFILE is not a Go coverage profile."
  exit 1
fi
if [ ! -f "$FLOORS" ]; then
  echo "coverage_check: FAIL — $FLOORS not found."
  exit 1
fi

awk -v module="$MODULE" '
# Pass 1: the floors file ("<package> <floor%>", # comments).
FILENAME == ARGV[1] {
  sub(/#.*/, "")
  if (NF == 0) next
  if (NF != 2 || $2 !~ /^[0-9]+(\.[0-9]+)?$/) { printf("coverage_check: FAIL — malformed floors line: %s\n", $0); bad = 1; next }
  floor[$1] = $2 + 0
  next
}
# Pass 2: the profile. Line format: <file>:<pos> <statements> <count>.
FNR == 1 { next }
{
  key = $1
  if (!(key in stmts)) stmts[key] = $2 + 0
  if ($3 + 0 > 0) hit[key] = 1
}
function target(p) {
  if (p ~ /^internal\/contracts\//) return 90
  if (p ~ /^internal\/validation\/operational(\/|$)/) return 90
  if (p ~ /^internal\/vault\/orchestration(\/|$)/) return 90
  return 80
}
END {
  if (bad) exit 1
  for (k in stmts) {
    f = k; sub(/:[^:]*$/, "", f)
    p = f; sub(/\/[^\/]*$/, "", p)
    if (index(p, module) != 1) continue
    p = substr(p, length(module) + 1)
    if (p !~ /^(internal|cmd|pkg)\//) continue      # product code only
    if (p ~ /^internal\/integration(\/|$)/) continue # test-only package
    total[p] += stmts[k]
    if (k in hit) covered[p] += stmts[k]
  }
  n = 0
  for (p in total) names[++n] = p
  # insertion sort: stable, deterministic report
  for (i = 2; i <= n; i++) { v = names[i]; j = i - 1; while (j > 0 && names[j] > v) { names[j+1] = names[j]; j-- } names[j+1] = v }

  fail = 0
  printf("%-48s %7s %7s %8s  %s\n", "package", "stmts", "cover", "required", "status")
  for (i = 1; i <= n; i++) {
    p = names[i]
    pct = 100 * covered[p] / total[p]
    t = target(p)
    req = (p in floor) ? floor[p] : t
    status = "ok"
    if (pct + 1e-9 < req) { status = "FAIL"; fail = 1 }
    else if ((p in floor) && pct + 1e-9 >= t) status = "ok — meets target " t "%: remove its floor"
    else if (p in floor) status = "ok (below target " t "%, floor " floor[p] "%)"
    printf("%-48s %7d %6.1f%% %7.1f%%  %s\n", p, total[p], pct, req, status)
    all += total[p]; allcov += covered[p]
  }
  for (p in floor) if (p != "total" && !(p in total)) printf("coverage_check: note — floors entry %s matches no package\n", p)

  pct = 100 * allcov / all
  req = ("total" in floor) ? floor["total"] : 0
  printf("%-48s %7d %6.1f%% %7.1f%%  %s\n", "TOTAL (product)", all, pct, req, (pct + 1e-9 < req) ? "FAIL" : "ok")
  if (pct + 1e-9 < req) fail = 1
  exit fail
}' "$FLOORS" "$PROFILE" && { echo "coverage_check: PASS"; exit 0; }

echo "coverage_check: FAIL — see the rows marked FAIL above (policy: docs/doctrine/ci-security-policy.md §8)."
exit 1
