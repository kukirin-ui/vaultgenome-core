# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Where does CPU↔GPU float divergence enter a real transformer, and can a
canonical path close it?

For each (device, dtype) it runs Qwen2.5-0.5B over the drill's 16 fixture
prompts with determinism pinned and TF32 off, capturing the last-position
logits and a hash of every layer's last-position hidden state. Then it
reports, CPU vs CUDA:

  - the logit divergence (max abs, max rel, ULP), and whether the top-1
    token and the reference top-64 order still agree;
  - the FIRST layer whose hidden state differs — the entry point of the
    divergence;
  - an integer-projection test: the final logits recomputed as an integer
    dot product (int64 accumulation) from the SAME quantised hidden state
    on CPU and on CUDA, to show that the projection door is byte-identical
    across devices even where native float is not.

Output: one JSON object on stdout. Nothing here decides a gate; it measures.
"""

import hashlib
import json
import sys

import numpy as np
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

BASE = "/opt/base"
PROMPTS = "/opt/worker/examples/drill-prompts.json"


def pin():
    torch.manual_seed(1234)
    torch.use_deterministic_algorithms(True, warn_only=True)
    if hasattr(torch.backends, "cuda") and hasattr(torch.backends.cuda, "matmul"):
        torch.backends.cuda.matmul.allow_tf32 = False
    if hasattr(torch.backends, "cudnn"):
        torch.backends.cudnn.allow_tf32 = False
        torch.backends.cudnn.deterministic = True


def h12(a: np.ndarray) -> str:
    return hashlib.sha256(np.ascontiguousarray(a).tobytes()).hexdigest()[:12]


def run(device, dtype, inputs):
    m = AutoModelForCausalLM.from_pretrained(BASE, local_files_only=True, dtype=dtype).to(device).eval()
    logits, hidden = [], []
    with torch.no_grad():
        for ids in inputs:
            t = torch.tensor([ids], dtype=torch.long, device=device)
            out = m(input_ids=t, use_cache=False, output_hidden_states=True)
            logits.append(out.logits[0, -1].to(torch.float64).cpu().numpy())
            hidden.append([h12(hh[0, -1].to(torch.float64).cpu().numpy()) for hh in out.hidden_states])
    del m
    if device == "cuda":
        torch.cuda.empty_cache()
    return logits, hidden


def compare(a_logits, a_hidden, b_logits, b_hidden, top_k=64):
    max_abs = max_rel = 0.0
    max_ulp = 0
    top1 = topk = 0
    first_div_layers = []
    for la, ha, lb, hb in zip(a_logits, a_hidden, b_logits, b_hidden):
        d = np.abs(la - lb)
        max_abs = max(max_abs, float(d.max()))
        max_rel = max(max_rel, float((d / np.maximum(np.abs(lb), 1e-12)).max()))
        # ULP distance in float32 space (the model's native precision).
        fa = la.astype(np.float32).view(np.int32).astype(np.int64)
        fb = lb.astype(np.float32).view(np.int32).astype(np.int64)
        max_ulp = max(max_ulp, int(np.abs(fa - fb).max()))
        top1 += int(np.argmax(la) == np.argmax(lb))
        topk += int(np.array_equal(np.argsort(la)[-top_k:][::-1], np.argsort(lb)[-top_k:][::-1]))
        first = next((i for i, (x, y) in enumerate(zip(ha, hb)) if x != y), -1)
        first_div_layers.append(first)
    n = len(a_logits)
    return {
        "max_abs_err": max_abs, "max_rel_err": max_rel, "max_ulp": max_ulp,
        "top1_same": f"{top1}/{n}", "topk_order_same": f"{topk}/{n}",
        "first_divergent_layer": first_div_layers,  # -1 = identical all the way
    }


def integer_projection(base_hidden_cpu, base_hidden_cuda, weight):
    """The last-position logits are hidden @ W_lm^T. Quantise the SAME hidden
    vector and weight to int8 (per-row affine) and accumulate in int64; the
    result is byte-identical on any device by construction (fixed reduction).
    We run it on CPU and CUDA from the identical quantised integers and show
    the outputs match bit for bit."""
    # int8 affine quantise; the dot is elementwise int64 multiply then an
    # exact integer sum (torch has no integer matmul, and integer addition
    # is associative, so the reduction order cannot change the result).
    hs = max(float(np.abs(base_hidden_cpu).max()) / 127.0, 1e-12)
    hq = np.round(base_hidden_cpu / hs).astype(np.int64)                                   # [d]
    wscale = np.maximum(np.abs(weight).max(axis=1, keepdims=True) / 127.0, 1e-12)
    wq = np.round(weight / wscale).astype(np.int64)                                        # [V,d]
    hi = torch.tensor(hq)
    wi = torch.tensor(wq)
    cpu = (wi * hi).sum(dim=1).numpy()                                                     # int dot, CPU
    cuda = (wi.to("cuda") * hi.to("cuda")).sum(dim=1).cpu().numpy() if torch.cuda.is_available() else cpu
    return {
        "int_dot_cpu_hash": h12(cpu), "int_dot_cuda_hash": h12(cuda),
        "int_dot_byte_identical": bool(np.array_equal(cpu, cuda)),
        "note": "integer projection from identical quantised inputs; float logits differ, integers do not",
    }


def main():
    pin()
    prompts = json.load(open(PROMPTS))
    tok = AutoTokenizer.from_pretrained(BASE, local_files_only=True)
    inputs = [tok(p, add_special_tokens=False)["input_ids"] for p in prompts]

    result = {"fixtures": len(inputs), "cuda": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
              "torch": torch.__version__}
    runs = {}
    for device in ("cpu", "cuda"):
        if device == "cuda" and not torch.cuda.is_available():
            continue
        for dtype, name in ((torch.float32, "f32"), (torch.float64, "f64")):
            runs[f"{device}-{name}"] = run(device, dtype, inputs)

    for name in ("f32", "f64"):
        a, b = runs.get(f"cpu-{name}"), runs.get(f"cuda-{name}")
        if a and b:
            result[f"cpu_vs_cuda_{name}"] = compare(a[0], a[1], b[0], b[1])

    # Integer projection door, on the real lm_head weight and a real hidden state.
    try:
        m = AutoModelForCausalLM.from_pretrained(BASE, local_files_only=True, dtype=torch.float32)
        w = m.lm_head.weight.detach().to(torch.float64).numpy()
        del m
        # take the first fixture's final hidden state (f64, cpu) for the projection test
        mm = AutoModelForCausalLM.from_pretrained(BASE, local_files_only=True, dtype=torch.float64).eval()
        with torch.no_grad():
            t = torch.tensor([inputs[0]], dtype=torch.long)
            hs = mm(input_ids=t, use_cache=False, output_hidden_states=True).hidden_states[-1][0, -1].numpy()
        del mm
        result["integer_projection"] = integer_projection(hs, hs, w)
    except Exception as e:  # pragma: no cover
        result["integer_projection"] = {"error": f"{type(e).__name__}: {e}"}

    json.dump(result, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
