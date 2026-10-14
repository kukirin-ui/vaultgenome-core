# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fixtures: the fine-tuned model's reference behaviour, recorded where it
was trained, recomputed wherever it is restored.

Each fixture is a prompt with
* ``expected``: the float32 logits at the last prompt position, gathered at
  the reference model's top-k token indices (the part of the distribution
  that decides what the model says), in the gate's tensor format;
* ``expected_integer``: the same logits as the integer door computes them
  (``integer.IntegerModel``) — the reference the integer door is held to
  byte for byte on any device; the document's ``integer`` section says
  what that door computes and how far its logits are from the float ones;
* ``greedy``: the reference greedy continuation, token by token.
"""

import base64
import hashlib
import json

import numpy as np
import torch

from . import FIXTURES_SCHEMA
from .data import prompt_ids
from .model import greedy, last_logits


def tensor_to_wire(t: torch.Tensor) -> dict:
    """The gate's tensor format: dtype, shape, little-endian raw bytes."""
    a = np.ascontiguousarray(t.detach().cpu().numpy().astype("<f4"))
    return {"dtype": "f32", "shape": list(a.shape), "raw_b64": base64.b64encode(a.tobytes()).decode("ascii")}


def array_to_wire(a: np.ndarray) -> dict:
    """The gate's tensor format for a float32 numpy array."""
    a = np.ascontiguousarray(a.astype("<f4"))
    return {"dtype": "f32", "shape": list(a.shape), "raw_b64": base64.b64encode(a.tobytes()).decode("ascii")}


def wire_to_array(w: dict) -> np.ndarray:
    if w.get("dtype") != "f32":
        raise ValueError(f"unsupported dtype {w.get('dtype')!r}")
    a = np.frombuffer(base64.b64decode(w["raw_b64"]), dtype="<f4")
    return a.reshape(w["shape"])


def build(model, tokenizer, prompts: list, device: torch.device, top_k: int, new_tokens: int, critical: int) -> dict:
    """Record the reference behaviour of model on prompts. The first
    `critical` fixtures are critical: outside tolerance, they fail the gate
    whatever the policy."""
    out = []
    for i, prompt in enumerate(prompts):
        ids = prompt_ids(tokenizer, prompt)
        logits = last_logits(model, ids, device)
        k = min(top_k, logits.shape[0])
        # Stable order: by logit descending, ties by token id.
        a = logits.numpy()
        order = [int(j) for j in np.lexsort((np.arange(a.shape[0]), -a))[:k]]
        index = torch.tensor(order, dtype=torch.long)
        cont = greedy(model, ids, new_tokens, device, tokenizer.eos_token_id)
        out.append(
            {
                "id": f"fx-{i:03d}",
                "critical": i < critical,
                "prompt": prompt,
                "input_ids": ids,
                "topk_index": order,
                "expected": tensor_to_wire(logits[index]),
                "greedy": {"ids": cont, "text": tokenizer.decode(cont, skip_special_tokens=False)},
            }
        )
    return {"schema": FIXTURES_SCHEMA, "top_k": top_k, "new_tokens": new_tokens, "fixtures": out}


def add_integer(doc: dict, integer_model) -> dict:
    """Give every fixture of doc the integer door's logits (integer_model,
    an integer.IntegerModel over the same model) and the document what
    that door computes and how far its logits are from the float ones."""
    from . import integer

    fidelity = []
    for fx in doc["fixtures"]:
        acc, shift = integer_model.last_accumulator(fx["input_ids"])
        got = integer_model.scaled(acc, shift, fx["topk_index"]).astype("<f4")
        fx["expected_integer"] = array_to_wire(got)
        want = wire_to_array(fx["expected"]).astype(np.float64)
        diff = np.abs(got.astype(np.float64) - want)
        fidelity.append({
            "max_abs_err": float(diff.max()),
            "max_rel_err": float((diff / np.maximum(np.abs(want), 1e-30)).max()),
            "top1_same": int(np.argmax(integer_model.scaled(acc, shift, np.arange(integer_model.vocab)))) == fx["topk_index"][0],
        })
    doc["integer"] = dict(integer.describe(integer_model.act_bits), fidelity={
        "fixtures": len(fidelity),
        "top1_same": sum(f["top1_same"] for f in fidelity),
        "max_abs_err": max(f["max_abs_err"] for f in fidelity),
        "max_rel_err": max(f["max_rel_err"] for f in fidelity),
    })
    return doc


def recompute(model, fixture: dict, device: torch.device) -> torch.Tensor:
    """What a restored model gives for a fixture: its last-position logits
    at the fixture's reference top-k indices."""
    logits = last_logits(model, fixture["input_ids"], device)
    return logits[torch.tensor(fixture["topk_index"], dtype=torch.long)]


def recompute_integer(integer_model, fixture: dict) -> np.ndarray:
    """What the integer door gives for a fixture on this machine: the
    integer model's last-position logits at the reference top-k indices,
    float32 — the same bytes on any device."""
    return integer_model.last_logits(fixture["input_ids"], fixture["topk_index"])


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if doc.get("schema") != FIXTURES_SCHEMA:
        raise ValueError(f"{path}: schema {doc.get('schema')!r}, want {FIXTURES_SCHEMA!r}")
    ids = [fx["id"] for fx in doc["fixtures"]]
    if len(ids) != len(set(ids)) or not ids:
        raise ValueError(f"{path}: fixture ids must be present and unique")
    return doc


def digest(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return "sha256:" + h.hexdigest()
