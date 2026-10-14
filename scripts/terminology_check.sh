#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# terminology_check.sh — fails if any deprecated PROJECT-NAME token from
# docs/doctrine/terminology.md §4 appears outside docs/patent_references/.
#
# Scope of the gate: it enforces that the rename away from the project's
# former names (NSV / NeuralSeedVault / neural_seed_vault / genome_vault)
# is complete — those tokens must not reappear in source or docs. The
# vocabulary preferences in terminology.md §5 (e.g. "rewind"/"regenerate"
# over "restore") are ADVISORY house style, not a build gate; see §5 for
# why they are documented rather than enforced.
#
# This script implements sub-check 09 of the vault-gate workflow.

set -euo pipefail

# Deprecated project-name tokens, frozen by docs/doctrine/terminology.md §4.
# These enforce that the rename to "VaultGenome" / "genome" is complete: the
# former names must not reappear in source or docs. Matched as whole tokens
# (so SessionFooNSV would not trip NSV) and case-sensitively.
#
# The vocabulary preferences of terminology.md §5 are deliberately NOT listed
# here. They are advisory house style, not a gate: the codebase uses words
# like "restore" and "backup" in their ordinary English sense (e.g. "restore
# a sealed genome to a target directory"), and gating them would fail on
# hundreds of correct, readable usages without improving the product.
declare -a PATTERNS=(
  '\bNSV\b'
  '\bneural_seed\b'
  '\bNeuralSeedVault\b'
  '\bneural_seed_vault\b'
  '\bgenome_vault\b'             # lowercase/underscore form is deprecated
)

# Scope: all files under the repository root, EXCEPT:
#   - docs/patent_references/*     (patent-traceability exception)
#   - scripts/terminology_check.sh (this file, which names the terms)
#   - docs/doctrine/terminology.md (the doctrine doc, which names the terms)
#   - test/doctrine/*              (doctrine meta-tests: they deliberately
#                                   embed the deprecated tokens as fixtures
#                                   to prove this check catches them)
#   - .git/*
#   - vendor/*
#   - dist/, bin/
EXCLUDES=(
  ':(exclude)docs/patent_references'
  ':(exclude)scripts/terminology_check.sh'
  ':(exclude)docs/doctrine/terminology.md'
  ':(exclude)test/doctrine'
  ':(exclude).git'
  ':(exclude)vendor'
  ':(exclude)dist'
  ':(exclude)bin'
)

FAILED=0

# Scope: files that carry doctrine. Operational config files (.gitignore,
# Dockerfile, Terraform) may legitimately use words like "backup" in their
# non-doctrinal senses (file-extension patterns, OS backups); those files
# are intentionally out of scope.
INCLUDE_GLOBS=(
  '*.go'
  '*.md'
  '*.yml'
  '*.yaml'
  '*.proto'
  '*.sh'
)

# Build the file list once.
FILES=()
while IFS= read -r -d '' f; do
  FILES+=("$f")
done < <(
  find . -type f \( \
       -name '*.go' -o -name '*.md' -o -name '*.yml' \
    -o -name '*.yaml' -o -name '*.proto' -o -name '*.sh' \
  \) \
  -not -path './.git/*' \
  -not -path './vendor/*' \
  -not -path './dist/*' \
  -not -path './bin/*' \
  -not -path './docs/patent_references/*' \
  -not -path './test/doctrine/*' \
  -not -path './docs/doctrine/terminology.md' \
  -not -name 'terminology_check.sh' \
  -print0
)

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "terminology_check: no in-scope files to check"
  echo "terminology_check: PASS"
  exit 0
fi

for pat in "${PATTERNS[@]}"; do
  MATCHES=$(grep -nE "$pat" "${FILES[@]}" 2>/dev/null || true)
  if [ -n "$MATCHES" ]; then
    echo "terminology_check: deprecated term matched by pattern: $pat"
    echo "$MATCHES" | head -20
    echo
    FAILED=1
  fi
done

if [ "$FAILED" -ne 0 ]; then
  echo "terminology_check: FAIL"
  echo "See docs/doctrine/terminology.md §4 for the canonical names and the"
  echo "frozen deprecation list. Deprecated project names are permitted only"
  echo "under docs/patent_references/."
  exit 1
fi

echo "terminology_check: PASS"
