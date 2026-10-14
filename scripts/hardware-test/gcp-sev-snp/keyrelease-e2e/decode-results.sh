#!/usr/bin/env bash
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Extracts the results tarball cvm-keyrelease.sh printed on the serial
# console, checks its size and SHA-256 against the header, and unpacks it
# under <evidence-dir>/<stamp>/.
#
# Usage: decode-results.sh <serial-output-file> <evidence-dir>
set -euo pipefail
SERIAL="${1:?serial output file}"; DEST="${2:?evidence dir}"
python3 - "$SERIAL" "$DEST" <<'PY'
import base64, hashlib, io, re, sys, tarfile, os
serial, dest = sys.argv[1], sys.argv[2]
text = open(serial, errors="replace").read()
for m in re.finditer(r"===E2E-BEGIN=== (\S+) size=(\d+) sha256=([0-9a-f]{64}) lines=(\d+) copy=\d+\n(.*?)===E2E-END===", text, re.S):
    stamp, size, digest, nlines = m.group(1), int(m.group(2)), m.group(3), int(m.group(4))
    lines = {}
    for line in m.group(5).splitlines():
        mm = re.match(r".*?@@(\d{4}) (\S+)$", line)
        if mm:
            lines[int(mm.group(1))] = mm.group(2)
    if len(lines) != nlines:
        continue
    b64 = "".join(lines[i] for i in range(nlines))
    if len(b64) != size or hashlib.sha256(b64.encode()).hexdigest() != digest:
        continue
    blob = base64.b64decode(b64)
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not (member.isfile() or member.isdir()) or member.name.startswith("/") or ".." in member.name.split("/"):
                sys.exit(f"refusing tar member {member.name!r}")
        tar.extractall(dest)
    print(f"decoded {stamp}: {len(blob)} bytes, sha256(b64)={digest} -> {dest}/{stamp}")
    sys.exit(0)
sys.exit("no intact copy of the results in the serial output")
PY
