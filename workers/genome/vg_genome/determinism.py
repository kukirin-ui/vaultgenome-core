# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pinning the runtime so a computation repeats bit for bit.

On one machine, with the same library versions, the same thread count and
these settings, training and inference are deterministic. Across machines the
float kernels may differ in their last bits; that is what the equivalence gate
measures instead of assuming.
"""

import os
import platform
import random
import sys

import numpy as np
import torch

_pinned = None


def pin(seed: int, threads: int) -> None:
    """Seed every RNG, fix the thread count and demand deterministic kernels.

    torch allows setting the inter-op thread count once per process; pinning
    twice with different threads is refused rather than silently ignored.
    """
    global _pinned
    if threads < 1:
        raise ValueError("threads must be >= 1")
    if _pinned is not None and _pinned != threads:
        raise RuntimeError(f"runtime already pinned to {_pinned} threads")
    os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.set_num_threads(threads)
    if _pinned is None:
        try:
            torch.set_num_interop_threads(1)
        except RuntimeError:
            pass  # already fixed by an earlier call in this process
    # warn_only: on CUDA a few ops the models use have no deterministic
    # kernel; they warn instead of stopping the run. CPU kernels are
    # deterministic, and cross-device results are measured, not assumed.
    torch.use_deterministic_algorithms(True, warn_only=True)
    if hasattr(torch.backends, "cudnn"):
        torch.backends.cudnn.benchmark = False
        torch.backends.cudnn.deterministic = True
    if hasattr(torch.backends, "cuda") and hasattr(torch.backends.cuda, "matmul"):
        torch.backends.cuda.matmul.allow_tf32 = False
    if hasattr(torch.backends, "cudnn"):
        torch.backends.cudnn.allow_tf32 = False
    _pinned = threads


def runtime() -> dict:
    """What ran: interpreter, libraries, CPU and accelerator."""
    info = {
        "python": sys.version.split()[0],
        "torch": torch.__version__,
        "numpy": np.__version__,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": _cpu_model(),
        "threads": torch.get_num_threads(),
    }
    try:
        import transformers

        info["transformers"] = transformers.__version__
    except ImportError:  # pragma: no cover - transformers is a dependency
        pass
    if torch.cuda.is_available():
        info["cuda"] = torch.version.cuda
        info["gpu"] = torch.cuda.get_device_name(0)
    return info


def _cpu_model() -> str:
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def device(name: str) -> torch.device:
    """Resolve "auto", "cpu", "cuda" or "mps" to an available device."""
    if name == "auto":
        if torch.cuda.is_available():
            return torch.device("cuda")
        return torch.device("cpu")
    if name == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("cuda requested but not available")
    if name == "mps" and not torch.backends.mps.is_available():
        raise RuntimeError("mps requested but not available")
    return torch.device(name)
