# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Loading a base model with an adapter, and the two measurements a fixture
takes: last-position logits and a greedy continuation."""

import torch

from . import lora

# The dtypes a recipe may name for the base model. The adapter and every
# measurement stay float32 whatever the base computes in.
DTYPES = {"float32": torch.float32, "bfloat16": torch.bfloat16, "float16": torch.float16}
DEFAULT_DTYPE = "float32"


def torch_dtype(name: str) -> torch.dtype:
    """The torch dtype a recipe names; anything else is refused."""
    try:
        return DTYPES[name]
    except KeyError:
        raise ValueError(f"unsupported dtype {name!r} (one of {', '.join(DTYPES)})") from None


def load_base(base_dir: str, dtype: str = DEFAULT_DTYPE):
    """The base model in dtype (float32 unless a recipe says otherwise) and
    its tokenizer, from local files only."""
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(base_dir, local_files_only=True)
    model = AutoModelForCausalLM.from_pretrained(base_dir, local_files_only=True, dtype=torch_dtype(dtype))
    model.eval()
    return model, tokenizer


def load_with_adapter(base_dir: str, adapter_dir: str, device: torch.device, dtype: str = DEFAULT_DTYPE):
    model, tokenizer = load_base(base_dir, dtype)
    lora.load(model, adapter_dir)
    model.to(device)
    model.eval()
    return model, tokenizer


@torch.no_grad()
def last_logits(model, input_ids: list, device: torch.device) -> torch.Tensor:
    """Logits at the last position, float32, on the CPU."""
    ids = torch.tensor([input_ids], dtype=torch.long, device=device)
    out = model(input_ids=ids, use_cache=False).logits[0, -1]
    return out.to(torch.float32).cpu()


@torch.no_grad()
def greedy(model, input_ids: list, new_tokens: int, device: torch.device, eos_id=None) -> list:
    """Greedy continuation, token by token, without a cache: the same
    arithmetic as last_logits at every step."""
    ids = list(input_ids)
    out = []
    for _ in range(new_tokens):
        nxt = int(torch.argmax(last_logits(model, ids, device)).item())
        out.append(nxt)
        ids.append(nxt)
        if eos_id is not None and nxt == eos_id:
            break
    return out
