# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""LoRA adapters: low-rank deltas on a frozen base model.

A LoRA layer adds ``(x @ A^T) @ B^T * alpha / r`` to a frozen linear layer,
with ``A`` (r x in) and ``B`` (out x r). ``B`` starts at zero, so an untrained
adapter changes nothing. Adapters are saved in the PEFT layout
(``adapter_model.safetensors`` with keys
``base_model.model.<module>.lora_A.weight`` / ``lora_B.weight``, and
``adapter_config.json``), so the PEFT library can load them too; this module
needs only torch.
"""

import json
import math
import os
from typing import Iterable

import torch
from safetensors.torch import load_file, save_file
from torch import nn

ADAPTER_WEIGHTS = "adapter_model.safetensors"
ADAPTER_CONFIG = "adapter_config.json"


def _conv1d_type():
    try:
        from transformers.pytorch_utils import Conv1D

        return Conv1D
    except ImportError:  # pragma: no cover
        return None


class LoRALayer(nn.Module):
    """A frozen linear layer (nn.Linear or GPT-2 style Conv1D) plus a LoRA delta."""

    def __init__(self, base: nn.Module, r: int, alpha: float):
        super().__init__()
        conv1d = _conv1d_type()
        if isinstance(base, nn.Linear):
            in_f, out_f = base.in_features, base.out_features
        elif conv1d is not None and isinstance(base, conv1d):
            in_f, out_f = base.weight.shape
        else:
            raise TypeError(f"LoRA needs a linear layer, got {type(base).__name__}")
        if r < 1:
            raise ValueError("LoRA rank must be >= 1")
        self.base = base
        self.r = r
        self.alpha = alpha
        self.scaling = alpha / r
        self.lora_A = nn.Parameter(torch.empty(r, in_f, dtype=torch.float32))
        self.lora_B = nn.Parameter(torch.zeros(out_f, r, dtype=torch.float32))
        nn.init.kaiming_uniform_(self.lora_A, a=math.sqrt(5))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        delta = (x.to(self.lora_A.dtype) @ self.lora_A.t()) @ self.lora_B.t()
        return self.base(x) + (delta * self.scaling).to(x.dtype)


def inject(model: nn.Module, targets: Iterable[str], r: int, alpha: float) -> list:
    """Wrap every module whose name ends in a target with a LoRALayer.

    Freezes the whole model first; only the LoRA parameters train. Returns the
    wrapped module names, sorted. Refuses a target list that matches nothing.
    """
    targets = list(targets)
    for p in model.parameters():
        p.requires_grad_(False)
    names = sorted(
        name
        for name, module in model.named_modules()
        if name and any(name == t or name.endswith("." + t) for t in targets)
        and not isinstance(module, LoRALayer)
    )
    if not names:
        raise ValueError(f"no module of the model matches LoRA targets {targets}")
    for name in names:
        parent_name, _, child = name.rpartition(".")
        parent = model.get_submodule(parent_name) if parent_name else model
        setattr(parent, child, LoRALayer(getattr(parent, child), r, alpha))
    return names


def lora_parameters(model: nn.Module) -> list:
    return [p for n, p in model.named_parameters() if ".lora_A" in n or ".lora_B" in n]


def state_dict(model: nn.Module) -> dict:
    """The adapter's tensors, keyed in the PEFT layout, in a stable order."""
    out = {}
    for name, module in sorted(model.named_modules()):
        if isinstance(module, LoRALayer):
            out[f"base_model.model.{name}.lora_A.weight"] = module.lora_A.detach().to(torch.float32).contiguous().cpu()
            out[f"base_model.model.{name}.lora_B.weight"] = module.lora_B.detach().to(torch.float32).contiguous().cpu()
    return out


def save(model: nn.Module, out_dir: str, base_name: str, targets: list, r: int, alpha: float) -> None:
    os.makedirs(out_dir, exist_ok=True)
    tensors = state_dict(model)
    save_file(tensors, os.path.join(out_dir, ADAPTER_WEIGHTS), metadata={"format": "pt"})
    config = {
        "peft_type": "LORA",
        "task_type": "CAUSAL_LM",
        "base_model_name_or_path": base_name,
        "r": r,
        "lora_alpha": alpha,
        "lora_dropout": 0.0,
        "bias": "none",
        "target_modules": sorted(targets),
        "fan_in_fan_out": _uses_conv1d(model),
        "inference_mode": True,
    }
    with open(os.path.join(out_dir, ADAPTER_CONFIG), "w") as f:
        json.dump(config, f, indent=2, sort_keys=True)
        f.write("\n")


def _uses_conv1d(model: nn.Module) -> bool:
    conv1d = _conv1d_type()
    return conv1d is not None and any(
        isinstance(m.base, conv1d) for m in model.modules() if isinstance(m, LoRALayer)
    )


def load(model: nn.Module, adapter_dir: str) -> dict:
    """Inject and load a saved adapter into model. Every saved tensor must
    land on a wrapped module and every wrapped module must be loaded."""
    with open(os.path.join(adapter_dir, ADAPTER_CONFIG)) as f:
        config = json.load(f)
    return load_tensors(model, config, load_file(os.path.join(adapter_dir, ADAPTER_WEIGHTS)))


def load_bytes(model: nn.Module, config_json: bytes, weights: bytes) -> dict:
    """load, from an adapter held in memory: the bytes of adapter_config.json
    and of adapter_model.safetensors. Nothing is written anywhere."""
    from safetensors.torch import load as load_safetensors

    return load_tensors(model, json.loads(config_json), load_safetensors(weights))


def load_tensors(model: nn.Module, config: dict, tensors: dict) -> dict:
    if config.get("peft_type") != "LORA":
        raise ValueError("not a LoRA adapter")
    inject(model, config["target_modules"], int(config["r"]), float(config["lora_alpha"]))
    wanted = state_dict(model)
    if set(tensors) != set(wanted):
        missing = sorted(set(wanted) - set(tensors))[:3]
        extra = sorted(set(tensors) - set(wanted))[:3]
        raise ValueError(f"adapter does not fit the model (missing {missing}, unexpected {extra})")
    for name, module in model.named_modules():
        if isinstance(module, LoRALayer):
            a = tensors[f"base_model.model.{name}.lora_A.weight"]
            b = tensors[f"base_model.model.{name}.lora_B.weight"]
            if a.shape != module.lora_A.shape or b.shape != module.lora_B.shape:
                raise ValueError(f"adapter tensor shapes do not fit {name}")
            with torch.no_grad():
                module.lora_A.copy_(a)
                module.lora_B.copy_(b)
    return config
