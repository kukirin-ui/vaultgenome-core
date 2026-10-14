# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deterministic LoRA fine-tuning, and replaying a genome's recipe.

The loop is deliberately plain: batch of one, examples in file order,
AdamW, gradient clipping, no dropout (the model stays in eval mode while the
adapter trains). The base computes in the recipe's dtype on the recipe's
device — float32 on the CPU unless the recipe says otherwise; a 7B base
trains in bfloat16 on a GPU — and the adapter is float32 wherever it
trains. On a pinned runtime the same recipe yields the same adapter, byte
for byte; the fixtures are recorded on the device that trained.
"""

import json
import os
import shutil
import time
from datetime import datetime, timezone

import torch

from . import GENOME_SCHEMA, determinism, fixtures, integer, lora, manifest
from .data import encode, file_digest, load_jsonl
from .model import DEFAULT_DTYPE, load_base, torch_dtype

BETAS = (0.9, 0.999)
EPS = 1e-8
CLIP = 1.0


def _default_prompts(rows: list, limit: int = 16) -> list:
    seen, out = set(), []
    for r in rows:
        if r["prompt"] not in seen:
            seen.add(r["prompt"])
            out.append(r["prompt"])
        if len(out) == limit:
            break
    return out


def train(base_dir: str, rows: list, *, targets: list, rank: int, alpha: float, steps: int, lr: float,
          max_len: int, seed: int, threads: int, device: str = "cpu", dtype: str = DEFAULT_DTYPE, log=None):
    """Fine-tune an adapter on rows; returns (model, tokenizer, losses, seconds).
    The model stays on the device it trained on, in the recipe's dtype."""
    torch_dtype(dtype)  # refuse an unknown dtype before loading anything
    determinism.pin(seed, threads)
    dev = determinism.device(device)
    model, tokenizer = load_base(base_dir, dtype)
    examples = [encode(tokenizer, r, max_len) for r in rows]
    lora.inject(model, targets, rank, alpha)
    model.to(dev)
    params = lora.lora_parameters(model)
    opt = torch.optim.AdamW(params, lr=lr, betas=BETAS, eps=EPS, weight_decay=0.0)
    model.eval()  # no dropout: the adapter trains on the model's inference behaviour
    losses = []
    start = time.monotonic()
    for step in range(steps):
        ex = examples[step % len(examples)]
        ids = torch.tensor([ex["input_ids"]], dtype=torch.long, device=dev)
        labels = torch.tensor([ex["labels"]], dtype=torch.long, device=dev)
        with torch.enable_grad():
            loss = model(input_ids=ids, labels=labels, use_cache=False).loss
            opt.zero_grad(set_to_none=True)
            loss.backward()
        torch.nn.utils.clip_grad_norm_(params, CLIP)
        opt.step()
        losses.append(float(loss.detach()))
        if log is not None and (step % 10 == 0 or step == steps - 1):
            log(f"step {step + 1}/{steps} loss {losses[-1]:.4f}")
    seconds = time.monotonic() - start
    return model, tokenizer, losses, seconds


def finetune(base_dir: str, data_path: str, out_dir: str, *, base_name: str, targets: list, rank: int = 8,
             alpha: float = 16.0, steps: int = 60, lr: float = 2e-4, max_len: int = 128, seed: int = 1234,
             threads: int = 4, prompts=None, top_k: int = 64, new_tokens: int = 16, critical: int = 4,
             device: str = "cpu", dtype: str = DEFAULT_DTYPE, integer_door: bool = True, log=None) -> dict:
    """Train an adapter and write a genome directory:

    out_dir/genome.json, adapter/, fixtures.json, data/train.jsonl

    device and dtype are recorded in the recipe: the fixtures are the
    model's behaviour there, and the door restores the base in that dtype.
    With integer_door the fixtures also carry the integer door's logits,
    the reference that door is held to byte for byte on any device.
    """
    if os.path.exists(out_dir) and os.listdir(out_dir):
        raise FileExistsError(f"{out_dir} exists and is not empty")
    base = manifest.build(base_dir)
    rows = load_jsonl(data_path)
    model, tokenizer, losses, seconds = train(
        base_dir, rows, targets=targets, rank=rank, alpha=alpha, steps=steps, lr=lr,
        max_len=max_len, seed=seed, threads=threads, device=device, dtype=dtype, log=log)
    dev = next(model.parameters()).device

    os.makedirs(out_dir, exist_ok=True)
    adapter_dir = os.path.join(out_dir, "adapter")
    lora.save(model, adapter_dir, base_name, targets, rank, alpha)
    os.makedirs(os.path.join(out_dir, "data"), exist_ok=True)
    shutil.copyfile(data_path, os.path.join(out_dir, "data", "train.jsonl"))

    fx = fixtures.build(model, tokenizer, prompts or _default_prompts(rows), dev, top_k, new_tokens, critical)
    if integer_door:
        # The float model has recorded its references; its integer form
        # takes the device (a large model fits once, not twice).
        if log is not None:
            log("recording the integer door's references")
        model.to("cpu")
        integer_model = integer.IntegerModel(model, dev)
        fixtures.add_integer(fx, integer_model)
        del integer_model
        if log is not None:
            f = fx["integer"]["fidelity"]
            log(f"integer door: top-1 the same on {f['top1_same']}/{f['fixtures']} fixtures, max abs err {f['max_abs_err']:.3g}")
    fx_path = os.path.join(out_dir, "fixtures.json")
    with open(fx_path, "w", encoding="utf-8") as f:
        json.dump(fx, f, sort_keys=True)
        f.write("\n")

    genome = {
        "schema": GENOME_SCHEMA,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "base": {"name": base_name, "manifest": base},
        "adapter": {
            "dir": "adapter",
            "format": "peft-lora",
            "r": rank,
            "alpha": alpha,
            "targets": sorted(targets),
            "parameters": sum(p.numel() for p in lora.lora_parameters(model)),
            "weights_sha256": file_digest(os.path.join(adapter_dir, lora.ADAPTER_WEIGHTS)),
        },
        "recipe": {
            "data": "data/train.jsonl",
            "data_sha256": file_digest(data_path),
            "examples": len(rows),
            "steps": steps,
            "lr": lr,
            "max_len": max_len,
            "seed": seed,
            "threads": threads,
            "device": dev.type,
            "dtype": dtype,
            "optimizer": {"name": "adamw", "betas": list(BETAS), "eps": EPS, "weight_decay": 0.0},
            "clip_grad_norm": CLIP,
            "losses": losses,
            "train_seconds": round(seconds, 3),
        },
        "fixtures": {
            "file": "fixtures.json",
            "sha256": fixtures.digest(fx_path),
            "count": len(fx["fixtures"]),
            "critical": min(critical, len(fx["fixtures"])),
            "top_k": top_k,
            "new_tokens": new_tokens,
            "kind": f"last-position logits at the reference top-k tokens, float32, computed in {dtype} on {dev.type}",
            "integer": fx.get("integer"),
        },
        "runtime": determinism.runtime(),
    }
    with open(os.path.join(out_dir, "genome.json"), "w", encoding="utf-8") as f:
        json.dump(genome, f, indent=2, sort_keys=True)
        f.write("\n")
    return genome


def load_genome(genome_dir: str) -> dict:
    with open(os.path.join(genome_dir, "genome.json"), encoding="utf-8") as f:
        g = json.load(f)
    if g.get("schema") != GENOME_SCHEMA:
        raise ValueError(f"{genome_dir}: schema {g.get('schema')!r}, want {GENOME_SCHEMA!r}")
    return g


def recipe_dtype(g: dict, override=None) -> str:
    """The dtype a genome's base is restored in: the recipe's, unless the
    caller overrides it for a measurement; float32 for a genome that
    predates the field."""
    return override or g["recipe"].get("dtype", DEFAULT_DTYPE)


def replay(genome_dir: str, base_dir: str, device: str = "cpu", dtype=None, log=None) -> dict:
    """Re-run a genome's recipe on base_dir (on device, in the recipe's
    dtype unless overridden) and compare the adapter it produces with the
    sealed one, tensor by tensor."""
    g = load_genome(genome_dir)
    manifest.verify(base_dir, g["base"]["manifest"])
    r = g["recipe"]
    dtype = recipe_dtype(g, dtype)
    data_path = os.path.join(genome_dir, r["data"])
    if file_digest(data_path) != r["data_sha256"]:
        raise ValueError("the genome's training data does not match its recipe")
    model, _, losses, seconds = train(
        base_dir, load_jsonl(data_path), targets=g["adapter"]["targets"], rank=g["adapter"]["r"],
        alpha=g["adapter"]["alpha"], steps=r["steps"], lr=r["lr"], max_len=r["max_len"], seed=r["seed"],
        threads=r["threads"], device=device, dtype=dtype, log=log)
    from safetensors.torch import load_file

    sealed = load_file(os.path.join(genome_dir, g["adapter"]["dir"], lora.ADAPTER_WEIGHTS))
    replayed = lora.state_dict(model)
    if set(sealed) != set(replayed):
        raise ValueError("replayed adapter has different tensors")
    # max_rel_diff is element-wise and blows up on weights near zero;
    # max_rel_l2 (||sealed - replayed|| / ||sealed|| per tensor) is the
    # figure that says how far the replayed adapter is from the sealed one.
    max_abs, max_rel, max_rel_l2, exact = 0.0, 0.0, 0.0, True
    for k in sorted(sealed):
        a, b = sealed[k], replayed[k]
        if not torch.equal(a, b):
            exact = False
            d = (a - b).abs()
            max_abs = max(max_abs, float(d.max()))
            max_rel = max(max_rel, float((d / a.abs().clamp_min(1e-12)).max()))
            max_rel_l2 = max(max_rel_l2, float(torch.linalg.vector_norm(a - b) / torch.linalg.vector_norm(a).clamp_min(1e-12)))
    loss_diff = max(abs(x - y) for x, y in zip(losses, r["losses"]))
    return {
        "device": device,
        "dtype": dtype,
        "exact": exact,
        "max_abs_diff": max_abs,
        "max_rel_diff": max_rel,
        "max_rel_l2": max_rel_l2,
        "losses_equal": losses == r["losses"],
        "max_loss_diff": loss_diff,
        "final_loss": {"sealed": r["losses"][-1], "replayed": losses[-1]},
        "train_seconds": round(seconds, 3),
        "runtime": determinism.runtime(),
    }
