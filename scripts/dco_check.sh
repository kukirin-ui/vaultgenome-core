#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# dco_check.sh [<range>] — every non-merge commit in the range carries a
# Developer Certificate of Origin sign-off whose email is the author's.
#
# The range defaults to origin/main..HEAD (a branch under review). CI passes
# the pull request's base..head, or the push's before..after on main. Merge
# commits are skipped: GitHub writes them, nobody signs them off. Policy:
# CONTRIBUTING.md, "Developer Certificate of Origin"; in force for commits
# authored from 2026-10-14 on.
set -euo pipefail

RANGE="${1:-origin/main..HEAD}"
SINCE="2026-10-14T00:00:00Z"
FAILED=0
CHECKED=0
while IFS= read -r sha; do
  [ -n "$sha" ] || continue
  author_email=$(git log -1 --format='%ae' "$sha")
  author_date=$(git log -1 --format='%aI' "$sha")
  if [[ "$author_date" < "$SINCE" ]]; then
    continue
  fi
  CHECKED=$((CHECKED + 1))
  signoffs=$(git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$sha" | sed '/^$/d')
  if [ -z "$signoffs" ]; then
    echo "dco_check: no Signed-off-by trailer: $sha $(git log -1 --format='%s' "$sha")"
    FAILED=1
    continue
  fi
  if ! echo "$signoffs" | grep -qF "<$author_email>"; then
    echo "dco_check: Signed-off-by does not name the author <$author_email>: $sha"
    echo "  trailer(s): $(echo "$signoffs" | tr '\n' ';')"
    FAILED=1
  fi
done < <(git rev-list --no-merges "$RANGE" 2>/dev/null || true)

if [ "$FAILED" -ne 0 ]; then
  echo "dco_check: FAIL"
  echo "Every commit certifies the Developer Certificate of Origin (https://developercertificate.org):"
  echo "  git commit -s   (adds 'Signed-off-by: Name <email>' with the author's email)"
  echo "  git rebase --signoff origin/main   (for commits already made)"
  exit 1
fi
echo "dco_check: PASS ($CHECKED commit(s) checked in $RANGE)"
