#!/usr/bin/env python3
# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
# Reference backend for the reconstruction "reproducible-float" door.
#
# Implements the ExternalBackend protocol
# (core/internal/validation/reconstruction/external.go):
#   stdin  : {"fixture_id":"<id>"}
#   stdout : {"dtype":"f64","shape":[...],"raw_b64":"<base64 little-endian raw>"}
#
# It owns the restored model: it loads a genome JSON (weights + per-fixture
# inputs) and recomputes the requested fixture's output, then emits it in the
# protocol shape so the attested Go orchestrator can gate it.
#
# HONESTY / ATTRIBUTION: the numpy computation below is a *reference* — it is
# deterministic within one runtime but NOT byte-identical across heterogeneous
# CPUs/GPUs (its transcendentals and BLAS reductions vary; see
# docs/prior-art-and-attribution.md and docs/testing/cross-hardware-determinism.md).
# For true cross-hardware byte-identity, run the model under RepDL
# (arXiv:2510.09180) or a ReproBLAS-backed stack — correct-rounded ops + a fixed
# reduction order — which is the borrowed technology this door stands on. Swap the
# marked block for the RepDL forward pass; the protocol is unchanged.
#
# Usage: repdl-door-runner.py <genome.json>   (reads one request on stdin)
import sys, json, base64
import numpy as np


def block(x, P):
    d = P["d"]
    W = {k: np.asarray(P[k], dtype=np.float64) for k in
         ("Wq", "Wk", "Wv", "Wo", "W1", "W2", "G", "B")}
    x = np.asarray(x, dtype=np.float64).reshape(P["L"], d)

    # ---- BEGIN swappable numeric core (replace with RepDL forward pass) ----
    def ln(t):
        mu = t.mean(-1, keepdims=True)
        var = t.var(-1, keepdims=True)
        return (t - mu) / np.sqrt(var + P["eps"]) * W["G"] + W["B"]

    def softmax(z):
        z = z - z.max(-1, keepdims=True)
        e = np.exp(z)
        return e / e.sum(-1, keepdims=True)

    q, k, v = x @ W["Wq"], x @ W["Wk"], x @ W["Wv"]
    a = softmax(q @ k.T / np.sqrt(d))
    h = ln(x + (a @ v) @ W["Wo"])
    m = np.maximum(h @ W["W1"], 0) @ W["W2"]
    out = ln(h + m)
    # ---- END swappable numeric core ----
    return np.ascontiguousarray(out, dtype=np.float64)


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: repdl-door-runner.py <genome.json>"}))
        sys.exit(2)
    with open(sys.argv[1]) as f:
        genome = json.load(f)
    req = json.loads(sys.stdin.read() or "{}")
    fid = req.get("fixture_id")
    inputs = genome["inputs"]
    if fid not in inputs:
        print(json.dumps({"error": "unknown fixture_id: %s" % fid}))
        sys.exit(1)
    out = block(inputs[fid], genome["params"])
    sys.stdout.write(json.dumps({
        "dtype": "f64",
        "shape": list(out.shape),
        "raw_b64": base64.b64encode(out.tobytes()).decode("ascii"),
    }))


if __name__ == "__main__":
    main()
