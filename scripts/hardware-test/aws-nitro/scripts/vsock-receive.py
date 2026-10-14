#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
vsock-receive.py — parent-side listener for production-mode AWS Nitro
Enclaves attestation capture.

Pairs with the in-enclave `vsock-attest` Go binary (see ../vsock-attest/).
Listens on AF_VSOCK CID=VMADDR_CID_ANY port=5005, accepts ONE connection
from the running enclave, reads:

    [ 4 bytes big-endian length ][ N bytes COSE_Sign1 attestation document ]

and writes the COSE_Sign1 bytes to the path given on the command line.

Exits 0 on success, non-zero on protocol/IO error.

Usage (run on parent EC2 BEFORE launching the enclave):

    python3 vsock-receive.py 04-attestation-document.bin &
    LISTENER_PID=$!
    sudo nitro-cli run-enclave --eif-path prod.eif --memory 4096 \\
        --cpu-count 2 --enclave-cid 16     # NO --debug-mode
    wait "$LISTENER_PID"

Requires Python 3.7+ (AF_VSOCK socket support). No third-party deps.
"""
from __future__ import annotations  # for `bytes | None` on Python 3.7-3.9

import argparse
import socket
import struct
import sys
import time

DEFAULT_PORT = 5005
ACCEPT_TIMEOUT_SECONDS = 180  # plenty of slack while the enclave boots


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output", help="Path to write the captured attestation document")
    p.add_argument("--port", type=int, default=DEFAULT_PORT,
                   help=f"vsock port to listen on (default: {DEFAULT_PORT})")
    p.add_argument("--timeout", type=float, default=ACCEPT_TIMEOUT_SECONDS,
                   help="Seconds to wait for the enclave to connect")
    args = p.parse_args()

    if not hasattr(socket, "AF_VSOCK"):
        sys.stderr.write("Python build lacks AF_VSOCK support (needs 3.7+ on Linux)\n")
        return 2

    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.bind((socket.VMADDR_CID_ANY, args.port))
    s.listen(1)
    s.settimeout(args.timeout)
    print(f"[vsock-receive] listening on CID=ANY port={args.port} (timeout {args.timeout}s)",
          flush=True)

    try:
        conn, addr = s.accept()
    except socket.timeout:
        sys.stderr.write(f"[vsock-receive] accept timed out after {args.timeout}s\n")
        return 3
    print(f"[vsock-receive] connection from CID={addr[0]} port={addr[1]}", flush=True)

    # Length-prefix framing: 4 bytes big-endian
    length_buf = recvall(conn, 4)
    if length_buf is None:
        sys.stderr.write("[vsock-receive] EOF before length\n")
        conn.close()
        s.close()
        return 4
    (doc_len,) = struct.unpack(">I", length_buf)
    if doc_len <= 0 or doc_len > 16 * 1024:
        sys.stderr.write(f"[vsock-receive] implausible length: {doc_len}\n")
        conn.close()
        s.close()
        return 5

    print(f"[vsock-receive] expecting {doc_len} bytes of attestation", flush=True)
    payload = recvall(conn, doc_len)
    if payload is None or len(payload) != doc_len:
        got = 0 if payload is None else len(payload)
        sys.stderr.write(f"[vsock-receive] short read: got {got}/{doc_len}\n")
        conn.close()
        s.close()
        return 6

    with open(args.output, "wb") as f:
        f.write(payload)
    print(f"[vsock-receive] saved {len(payload)} bytes to {args.output}", flush=True)

    conn.close()
    s.close()
    # Brief grace period so the enclave can finish its own close cleanly
    time.sleep(0.5)
    return 0


def recvall(conn: socket.socket, n: int) -> bytes | None:
    """Read exactly n bytes from conn, returning None on premature EOF."""
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(min(4096, n - len(buf)))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


if __name__ == "__main__":
    sys.exit(main())
