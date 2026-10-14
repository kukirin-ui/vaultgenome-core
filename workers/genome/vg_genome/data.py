# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Training data: JSONL of {"prompt": ..., "completion": ...}.

The loss covers the completion only; the prompt conditions it. Examples keep
file order, so a recipe replays the same sequence of updates.
"""

import hashlib
import json


def load_jsonl(path: str) -> list:
    rows = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if not isinstance(row.get("prompt"), str) or not isinstance(row.get("completion"), str):
                raise ValueError(f"{path}:{n}: each line needs string 'prompt' and 'completion'")
            rows.append({"prompt": row["prompt"], "completion": row["completion"]})
    if not rows:
        raise ValueError(f"{path} holds no examples")
    return rows


def file_digest(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return "sha256:" + h.hexdigest()


def encode(tokenizer, row: dict, max_len: int) -> dict:
    """Token ids for prompt + completion + EOS, and labels that ignore the
    prompt (-100). Truncated to max_len from the right."""
    p = tokenizer(row["prompt"], add_special_tokens=False)["input_ids"]
    c = tokenizer(row["completion"], add_special_tokens=False)["input_ids"]
    eos = [tokenizer.eos_token_id] if tokenizer.eos_token_id is not None else []
    ids = (p + c + eos)[:max_len]
    labels = ([-100] * len(p) + c + eos)[:max_len]
    if all(label == -100 for label in labels):
        raise ValueError("an example's completion is cut off entirely; raise max_len")
    return {"input_ids": ids, "labels": labels}


def prompt_ids(tokenizer, prompt: str) -> list:
    ids = tokenizer(prompt, add_special_tokens=False)["input_ids"]
    if not ids:
        raise ValueError("empty prompt")
    return ids
