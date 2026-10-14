#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# license_header_check.sh — every source file (Go, Python, shell) carries,
# within its first ten lines, the copyright statement of NOTICE and the
# SPDX license identifier. Policy: docs/doctrine/ci-security-policy.md §7.
set -euo pipefail

REQUIRED_LICENSE="SPDX-License-Identifier: AGPL-3.0-or-later"
REQUIRED_COPYRIGHT="Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin"
FAILED=0
CHECKED=0
while IFS= read -r -d '' f; do
  CHECKED=$((CHECKED + 1))
  HEAD=$(head -n 10 "$f")
  if [[ "$HEAD" != *"$REQUIRED_LICENSE"* ]]; then
    echo "license_header_check: missing SPDX header: $f"
    FAILED=1
  fi
  if [[ "$HEAD" != *"$REQUIRED_COPYRIGHT"* ]]; then
    echo "license_header_check: missing copyright statement: $f"
    FAILED=1
  fi
done < <(find . -type f \( -name '*.go' -o -name '*.py' -o -name '*.sh' \) \
           -not -path './vendor/*' \
           -not -path './bin/*' \
           -not -path './dist/*' \
           -not -path '*/node_modules/*' \
           -not -path '*/.venv/*' \
           -not -path '*/.terraform/*' \
           -print0)
if [ "$FAILED" -ne 0 ]; then
  echo "license_header_check: FAIL"
  echo "Every Go, Python and shell file MUST start (after a shebang, if any) with:"
  echo "  // Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin      (# in Python and shell)"
  echo "  // SPDX-License-Identifier: AGPL-3.0-or-later"
  exit 1
fi
echo "license_header_check: PASS ($CHECKED files)"
