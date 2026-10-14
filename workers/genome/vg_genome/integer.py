# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The integer door: the restored model's forward pass in integer arithmetic.

Float kernels differ across devices in their last bits (VERIFIABLE-CLAIMS
C6: CPU and GPU diverge at the first transformer block, even in float64).
Integer arithmetic does not: the same integer program gives the same bytes
on any CPU or GPU, under any BLAS, at any thread count. This module is
that program for a Llama-family model (Llama, Qwen2): every weight is an
int8 tensor with a per-channel integer multiplier, every activation a
fixed-point int64, every matrix product an int8 GEMM accumulated in
int32, and every non-linearity — RMSNorm, RoPE, softmax, SiLU — computed
with integer shifts, adds, multiplies and floor divisions, from tables
that `fixedmath` derives without a float. The idea of an integer-only
transformer follows I-BERT (Kim et al., 2021); the arithmetic here is our
own. The only float operations are the one-time quantisation of the
weights and the final scaling of the logits, both elementwise IEEE
operations run on the CPU with numpy, identical on every platform.

What the door proves is that the genome restored on this machine is the
same integer model, bit for bit, as the one sealed — an availability
guarantee across hardware. It is a different model from the float one:
its fidelity to the float model is measured (`fixtures.integer.fidelity`)
and certified by the gate, never assumed.

A left shift of a possibly negative value is written as a multiplication;
right shifts rely on the arithmetic shift every platform gives a signed
integer, and every division is checked exact on the device or done by
long division in shifts and subtractions.
"""

from fractions import Fraction

import numpy as np
import torch
from torch import nn

from . import fixedmath
from .lora import LoRALayer

SCHEME = "vg-integer-door/v1"

F = 20  # fraction bits of the residual stream and of every hidden value
FA = 12  # fraction bits of q, k and v inside attention
FP = 30  # fraction bits of exp and of the raw probabilities
FPV = 16  # fraction bits of the probabilities that weight the values
FT = 30  # fraction bits of the rotary tables
FG = 16  # fraction bits of the norm gains
FS = 16  # fraction bits of the attention scale
WQ = 21  # the per-channel weight multiplier is in [2^20, 2^21]
ACT_BITS = 14  # bits of a GEMM input: two int8 halves
NORM_BITS = 23  # RMSNorm squares values of at most this many bits
MAX_SHIFT = 48  # the largest pre-shift RMSNorm may need
OUT_BITS = 40  # a linear layer's output must stay below 2^40 (2^20 real)
GUARD_BITS = 62
QUANT_ROWS = 2048  # rows of a weight quantised at a time


class IntegerDoorError(RuntimeError):
    """The model or a value is outside what the integer door computes."""


# ----------------------------------------------------------------------
# integer primitives on int64 tensors
# ----------------------------------------------------------------------

_pow2_cache = {}


def pow2_table(dev: torch.device) -> torch.Tensor:
    key = str(dev)
    if key not in _pow2_cache:
        _pow2_cache[key] = torch.tensor([1 << k for k in range(63)], dtype=torch.int64, device=dev)
    return _pow2_cache[key]


def bitlen(x: torch.Tensor) -> torch.Tensor:
    """Bit length of non-negative int64 values, elementwise."""
    return (x.unsqueeze(-1) >= pow2_table(x.device)).sum(-1)


def pow2(s: torch.Tensor) -> torch.Tensor:
    """2^s for a non-negative int64 tensor s (s <= 62)."""
    return torch.ones_like(s) << s


def guard(x: torch.Tensor, bits: int, what: str) -> torch.Tensor:
    """Refuse values that could overflow further on: every platform refuses
    alike, since the test is an exact integer comparison."""
    if x.numel() and int(x.abs().max()) >= (1 << bits):
        raise IntegerDoorError(f"{what} exceeds 2^{bits}")
    return x


_divides_exactly = {}


def device_divides_exactly(dev: torch.device) -> bool:
    """Whether torch.div(rounding_mode="floor") on int64 is exact on dev.
    CPUs and CUDA divide integers exactly; MPS goes through float32 and
    does not — such a device gets the bit-serial division instead."""
    key = str(dev)
    if key not in _divides_exactly:
        a = [-(1 << 40) - 3, (1 << 45) + 7, -(1 << 59) + 123, 7, -7, 0, (1 << 62) - 1, -(1 << 62)]
        b = [7, 3, 1000003, 2, 2, 5, (1 << 31) + 11, 3]
        want = [x // y for x, y in zip(a, b)]
        got = torch.div(torch.tensor(a, dtype=torch.int64, device=dev), torch.tensor(b, dtype=torch.int64, device=dev), rounding_mode="floor")
        _divides_exactly[key] = got.cpu().tolist() == want
    return _divides_exactly[key]


def serial_floor_div(a: torch.Tensor, b) -> torch.Tensor:
    """floor(a / b) for a positive divisor b, by restoring long division:
    shifts, compares and subtractions only, 63 rounds, exact anywhere."""
    b = torch.as_tensor(b, dtype=torch.int64, device=a.device)
    neg = a < 0
    n = a.abs()
    q = torch.zeros_like(n)
    r = torch.zeros_like(n)
    for i in range(62, -1, -1):
        r = (r << 1) | ((n >> i) & 1)
        ge = r >= b
        r = torch.where(ge, r - b, r)
        q = torch.where(ge, q | (1 << i), q)
    return torch.where(neg, torch.where(r != 0, -(q + 1), -q), q)


def floor_div(a: torch.Tensor, b) -> torch.Tensor:
    """floor(a / b), b > 0, exact on every device."""
    if device_divides_exactly(a.device):
        return torch.div(a, b, rounding_mode="floor")
    return serial_floor_div(a, b)


def mul_pow2(x: torch.Tensor, s) -> torch.Tensor:
    """x * 2^s; s an int or a non-negative int64 tensor."""
    if isinstance(s, int):
        return x * (1 << s) if s > 0 else x
    return x * pow2(s)


def round_shift(x: torch.Tensor, s) -> torch.Tensor:
    """x / 2^s rounded half up, as (x + 2^(s-1)) >> s with the arithmetic
    shift every platform gives a signed integer; s an int or a
    non-negative int64 tensor broadcast against x."""
    if isinstance(s, int):
        if s <= 0:
            return x
        return (x + (1 << (s - 1))) >> s
    half = torch.where(s > 0, pow2((s - 1).clamp(min=0)), torch.zeros_like(s))
    return (x + half) >> s


def shift_signed(x: torch.Tensor, s: torch.Tensor) -> torch.Tensor:
    """x * 2^s for an int64 tensor s of either sign (rounded when s < 0)."""
    return torch.where(s >= 0, mul_pow2(x, s.clamp(min=0)), round_shift(x, (-s).clamp(min=0)))


def isqrt(n: torch.Tensor) -> torch.Tensor:
    """Integer square root of non-negative int64 values: Newton's method
    from a power of two above the root, a fixed number of steps, then a
    correction — the same path on every platform."""
    n = n.clamp(min=0)
    r = pow2((bitlen(n) + 1) >> 1)
    safe = n.clamp(min=1)
    for _ in range(12):
        r = (r + floor_div(safe, r.clamp(min=1))) >> 1
    r = torch.where(n == 0, torch.zeros_like(r), r)
    for _ in range(2):
        r = torch.where(r * r > n, r - 1, r)
        r = torch.where((r + 1) * (r + 1) <= n, r + 1, r)
    return r


def iexp(x: torch.Tensor, in_bits: int) -> torch.Tensor:
    """e^x for x <= 0 given with in_bits fraction bits, with FP fraction
    bits: x = -z ln2 + r, e^x = 2^-z e^r, and e^r by a Taylor polynomial
    of r/16 squared four times."""
    ln2 = fixedmath.to_q(fixedmath.ln2_fixed(), in_bits)
    x = x.clamp(max=0)
    z = floor_div(-x, ln2)
    r = x + z * ln2  # in (-ln2, 0]
    p = mul_pow2(r, FP - in_bits) if FP >= in_bits else round_shift(r, in_bits - FP)
    p = round_shift(p, 4)  # r / 16
    one = 1 << FP
    p2 = round_shift(p * p, FP)
    p3 = round_shift(p2 * p, FP)
    p4 = round_shift(p3 * p, FP)
    e = one + p + floor_div(p2, 2) + floor_div(p3, 6) + floor_div(p4, 24)
    for _ in range(4):
        e = round_shift(e * e, FP)
    return floor_div(e, pow2(z.clamp(max=62)))


def isigmoid(x: torch.Tensor, in_bits: int) -> torch.Tensor:
    """sigmoid(x) with FP fraction bits, from e^-|x| / (1 + e^-|x|)."""
    e = iexp(-x.abs(), in_bits)
    one = 1 << FP
    neg = floor_div(mul_pow2(e, FP), one + e)
    return torch.where(x >= 0, one - neg, neg)


# ----------------------------------------------------------------------
# quantised weights
# ----------------------------------------------------------------------


def merged_weight(module: nn.Module) -> np.ndarray:
    """The float32 weight [out, in] of a linear layer with its LoRA delta
    merged in a fixed order: numpy elementwise operations, IEEE, unfused,
    so the same bytes come out on every CPU."""
    if isinstance(module, LoRALayer):
        base = module.base
        if not isinstance(base, nn.Linear):
            raise IntegerDoorError(f"the integer door computes nn.Linear layers, not {type(base).__name__}")
        w = base.weight.detach().to(torch.float32).cpu().numpy()
        a = module.lora_A.detach().to(torch.float32).cpu().numpy()
        b = module.lora_B.detach().to(torch.float32).cpu().numpy()
        delta = np.zeros_like(w, dtype=np.float32)
        for k in range(a.shape[0]):
            prod = np.multiply(b[:, k : k + 1], a[k : k + 1, :], dtype=np.float32)
            delta = np.add(delta, prod, dtype=np.float32)
        delta = np.multiply(delta, np.float32(module.scaling), dtype=np.float32)
        return np.add(w, delta, dtype=np.float32)
    if not isinstance(module, nn.Linear):
        raise IntegerDoorError(f"the integer door computes nn.Linear layers, not {type(module).__name__}")
    return module.weight.detach().to(torch.float32).cpu().numpy()


def base_linear(module: nn.Module) -> nn.Linear:
    """The nn.Linear under a module the door computes: the layer itself, or
    the base of a LoRA layer."""
    base = module.base if isinstance(module, LoRALayer) else module
    if not isinstance(base, nn.Linear):
        raise IntegerDoorError(f"the integer door computes nn.Linear layers, not {type(base).__name__}")
    return base


def linear_bias(module: nn.Module):
    base = base_linear(module)
    return None if base.bias is None else base.bias.detach().to(torch.float32).cpu().numpy()


class QLinear:
    """A linear layer in integer form: int8 weights (per output channel,
    symmetric), a per-channel multiplier and shift that bring the
    accumulator back to F fraction bits, and a fixed-point bias."""

    def __init__(self, weight: np.ndarray, bias, dev: torch.device):
        n, k = weight.shape
        if k % 8:
            raise IntegerDoorError(f"a linear layer's input width {k} is not a multiple of 8")
        self.n, self.k = n, k
        self.n_pad = max(32, (n + 7) // 8 * 8)
        # Quantise in blocks of rows, in float32: the largest layer of a 7B
        # model (its vocabulary projection) would otherwise need gigabytes
        # of temporaries. Elementwise, unfused, IEEE: the same bytes on any
        # CPU; float32 holds every value of a float32 or bfloat16 weight.
        scale = np.empty(n, dtype=np.float64)
        wt = np.zeros((k, self.n_pad), dtype=np.int8)
        for start in range(0, n, QUANT_ROWS):
            block = weight[start : start + QUANT_ROWS].astype(np.float32, copy=False)
            amax = np.abs(block).max(axis=1)
            s = np.where(amax > 0, amax / np.float32(127.0), np.float32(1.0)).astype(np.float32)
            q = np.rint(block / s[:, None])
            if np.abs(q).max() > 127:
                raise IntegerDoorError("weight quantisation left the int8 range")
            wt[:, start : start + len(s)] = q.T.astype(np.int8)
            scale[start : start + len(s)] = s
        mant, exp = np.frexp(scale)
        mult = np.rint(mant * float(1 << WQ)).astype(np.int64)
        rshift = (WQ - exp).astype(np.int64)
        if rshift.min() < 0 or rshift.max() > 62:
            raise IntegerDoorError("a weight scale is outside the door's range")
        self.wt = torch.from_numpy(wt).to(dev)
        self.mult = torch.from_numpy(mult).to(dev)
        self.rshift = torch.from_numpy(rshift).to(dev)
        self.scale = scale  # float64 per output channel; only the logits use it
        self.bias = None
        if bias is not None:
            b = np.rint(bias.astype(np.float64) * float(1 << F)).astype(np.int64)
            self.bias = torch.from_numpy(b).to(dev)

    def accumulate(self, q: torch.Tensor, act_bits: int) -> torch.Tensor:
        """Σ q w over the input, exact, as int64 [m, n_pad], for activations
        quantised to act_bits bits (two int8 halves above 7)."""
        if act_bits <= 7:
            return int_mm(q.to(torch.int8), self.wt)
        lo = ((q + 128) & 255) - 128
        hi = floor_div(q - lo, 256)
        return int_mm(hi.to(torch.int8), self.wt) * 256 + int_mm(lo.to(torch.int8), self.wt)

    def forward(self, q: torch.Tensor, shift: torch.Tensor, act_bits: int) -> torch.Tensor:
        """Activations from quantize_act -> the layer's output with F
        fraction bits, [m, n]."""
        acc = guard(self.accumulate(q, act_bits)[:, : self.n], 40, "a GEMM accumulator")
        y = round_shift(acc * self.mult.unsqueeze(0), self.rshift.unsqueeze(0))
        y = mul_pow2(y, shift)
        if self.bias is not None:
            y = y + self.bias.unsqueeze(0)
        return guard(y, OUT_BITS, "a linear layer's output")


def int_mm(a: torch.Tensor, b: torch.Tensor) -> torch.Tensor:
    """a [m, k] int8 times b [k, n] int8 as int64, exact: torch._int_mm
    where it exists (CPU, CUDA), an int32 matmul elsewhere (MPS). The CUDA
    kernel wants m > 16 and k, n multiples of 8: rows are padded."""
    m = a.shape[0]
    m_pad = max(32, (m + 7) // 8 * 8)
    if m_pad != m:
        a = torch.cat([a, torch.zeros((m_pad - m, a.shape[1]), dtype=torch.int8, device=a.device)])
    a = a.contiguous()
    try:
        out = torch._int_mm(a, b)
    except NotImplementedError:
        out = a.to(torch.int32) @ b.to(torch.int32)
    return out[:m].to(torch.int64)


def quantize_act(x: torch.Tensor, bits: int) -> tuple:
    """Quantise F-fraction-bit activations per row to `bits` bits with a
    power-of-two scale: returns (q, shift) with x ~ q * 2^shift."""
    amax = x.abs().amax(dim=-1, keepdim=True)
    shift = (bitlen(amax) - bits).clamp(min=0)
    lim = (1 << bits) - 1
    q = round_shift(x, shift).clamp(-lim, lim)
    return q, shift


# ----------------------------------------------------------------------
# the rotary embedding the model uses
# ----------------------------------------------------------------------


def rotary_base(cfg) -> Fraction:
    """The base of a model's rotary embedding, read from where its
    transformers keeps it: `rope_parameters` (transformers 5) or
    `rope_theta` with `rope_scaling` (before). Nothing is assumed: a config
    that names no base, a scaled or partial rotary embedding, or one that
    varies by layer is refused, never defaulted — transformers 5 moved the
    base out of `rope_theta`, and a default of 10000 in its place computed
    Qwen2.5 (base 1000000) with the wrong tables, exactly, on every device
    (scripts/hardware-test/integer-door, run 20261014T012445Z)."""
    params = getattr(cfg, "rope_parameters", None)
    if params is None:
        if not hasattr(cfg, "rope_theta"):
            raise IntegerDoorError("the model's config names no rotary base")
        scaling = dict(getattr(cfg, "rope_scaling", None) or {})
        params = {"rope_theta": cfg.rope_theta, "rope_type": scaling.pop("rope_type", scaling.pop("type", "default")), **scaling}
        partial = getattr(cfg, "partial_rotary_factor", None)
        if partial is not None:
            params["partial_rotary_factor"] = partial
    if not isinstance(params, dict) or any(isinstance(v, dict) for v in params.values()):
        raise IntegerDoorError("the integer door computes one rotary embedding for every layer")
    if params.get("rope_theta") is None:
        raise IntegerDoorError("the model's config names no rotary base")
    if params.get("rope_type", "default") != "default":
        raise IntegerDoorError("the integer door computes the default rotary embedding only")
    if params.get("partial_rotary_factor", 1.0) != 1.0:
        raise IntegerDoorError("the integer door rotates the whole head")
    return Fraction(params["rope_theta"])


def check_rotary_tables(inner: nn.Module, base: Fraction, head_dim: int) -> None:
    """Refuse a model whose own rotary module does not hold the default
    tables over `base`: the door derives its tables from the config's
    base without a float, so the config and the module must agree, or the
    door would compute a model the float one is not. The comparison is a
    check, not an input — the float buffer never reaches the door."""
    rotary = getattr(inner, "rotary_emb", None)
    inv_freq = getattr(rotary, "inv_freq", None)
    if inv_freq is None:
        raise IntegerDoorError("the integer door cannot see the model's rotary tables (no rotary_emb.inv_freq)")
    if float(getattr(rotary, "attention_scaling", 1.0)) != 1.0:
        raise IntegerDoorError("the integer door computes the default rotary embedding only")
    got = inv_freq.detach().to(torch.float64).cpu().tolist()
    want = [float(base) ** (-2.0 * i / head_dim) for i in range(head_dim // 2)]
    if len(got) != len(want) or any(abs(g - w) > 1e-5 * w for g, w in zip(got, want)):
        raise IntegerDoorError("the model's rotary tables are not the default rotary embedding over the config's base")


# ----------------------------------------------------------------------
# the model
# ----------------------------------------------------------------------


class IntegerModel:
    """A Llama-family causal language model in integer form, built from a
    loaded float model (its adapter merged), run on dev."""

    def __init__(self, model, dev: torch.device, act_bits: int = ACT_BITS):
        cfg = model.config
        kind = getattr(cfg, "model_type", None)
        if kind not in ("llama", "qwen2"):
            raise IntegerDoorError(f"the integer door computes llama and qwen2 models, not {kind!r}")
        if getattr(cfg, "use_sliding_window", False):
            raise IntegerDoorError("the integer door does not compute sliding-window attention")
        if any(t != "full_attention" for t in (getattr(cfg, "layer_types", None) or [])):
            raise IntegerDoorError("the integer door computes full attention in every layer")
        if act_bits < 2 or act_bits > 14:
            raise IntegerDoorError("activation bits must be between 2 and 14")
        self.dev = dev
        self.act_bits = act_bits
        self.hidden = cfg.hidden_size
        self.heads = cfg.num_attention_heads
        self.kv_heads = getattr(cfg, "num_key_value_heads", None) or self.heads
        self.head_dim = getattr(cfg, "head_dim", None) or self.hidden // self.heads
        if self.heads % self.kv_heads:
            raise IntegerDoorError("attention heads are not a multiple of the key/value heads")
        self.eps = Fraction(cfg.rms_norm_eps)
        self.rope_base = rotary_base(cfg)
        self.vocab = cfg.vocab_size
        inner = model.model
        check_rotary_tables(inner, self.rope_base, self.head_dim)
        # The embedding stays in the model's own dtype on the CPU (a 7B
        # vocabulary in float32 would be gigabytes); a row's conversion to
        # float32 is exact for float32 and bfloat16 weights.
        self.embed = inner.embed_tokens.weight.detach().cpu()
        self.layers = []
        for layer in inner.layers:
            at, mlp = layer.self_attn, layer.mlp
            self._check_attention_shapes(at)
            self.layers.append({
                "norm1": self._gain(layer.input_layernorm.weight),
                "q": self._linear(at.q_proj),
                "k": self._linear(at.k_proj),
                "v": self._linear(at.v_proj),
                "o": self._linear(at.o_proj),
                "norm2": self._gain(layer.post_attention_layernorm.weight),
                "gate": self._linear(mlp.gate_proj),
                "up": self._linear(mlp.up_proj),
                "down": self._linear(mlp.down_proj),
            })
        self.norm = self._gain(inner.norm.weight)
        self.lm_head = self._linear(model.lm_head)
        self.eps_table = torch.tensor(fixedmath.eps_table(self.eps, F, MAX_SHIFT), dtype=torch.int64, device=dev)
        self.attn_scale = fixedmath.inv_sqrt_q(self.head_dim, FS)
        self._rope = None

    def _linear(self, module) -> QLinear:
        return QLinear(merged_weight(module), linear_bias(module), self.dev)

    def _check_attention_shapes(self, at: nn.Module) -> None:
        """Refuse a model whose projections do not have the shape the
        config's head counts imply (num_key_value_heads and head_dim are
        read with a fallback): the door would otherwise split heads at the
        wrong boundary and compute the wrong model, exactly."""
        want = {
            "q_proj": (self.heads * self.head_dim, self.hidden),
            "k_proj": (self.kv_heads * self.head_dim, self.hidden),
            "v_proj": (self.kv_heads * self.head_dim, self.hidden),
            "o_proj": (self.hidden, self.heads * self.head_dim),
        }
        for name, shape in want.items():
            got = tuple(base_linear(getattr(at, name)).weight.shape)
            if got != shape:
                raise IntegerDoorError(f"{name} has shape {got}, not the {shape} the config's heads imply")

    def _gain(self, w) -> torch.Tensor:
        g = np.rint(w.detach().to(torch.float32).cpu().numpy().astype(np.float64) * float(1 << FG)).astype(np.int64)
        return torch.from_numpy(g).to(self.dev)

    def rope(self, positions: int) -> tuple:
        """cos and sin tables [positions, head_dim] with FT fraction bits
        (the half-tables repeated, as transformers lays them out)."""
        if self._rope is None or self._rope[0].shape[0] < positions:
            cos, sin = fixedmath.rope_tables(self.rope_base, self.head_dim, positions, FT)
            c = torch.tensor(cos, dtype=torch.int64, device=self.dev)
            s = torch.tensor(sin, dtype=torch.int64, device=self.dev)
            self._rope = (torch.cat([c, c], dim=-1), torch.cat([s, s], dim=-1))
        return self._rope[0][:positions], self._rope[1][:positions]

    # --- blocks ---------------------------------------------------------

    def rmsnorm(self, x: torch.Tensor, gain: torch.Tensor) -> torch.Tensor:
        """x / sqrt(mean(x²) + eps) * gain, with F fraction bits."""
        amax = x.abs().amax(dim=-1, keepdim=True)
        shift = (bitlen(amax) - NORM_BITS).clamp(min=0)
        if int(shift.max()) > MAX_SHIFT:
            raise IntegerDoorError("a hidden state is too large to normalise")
        x1 = round_shift(x, shift)
        sumsq = guard((x1 * x1).sum(dim=-1, keepdim=True), GUARD_BITS, "a norm's sum of squares")
        ms = floor_div(sumsq + self.eps_table[shift], x.shape[-1])
        rms = isqrt(ms).clamp(min=1)
        n = floor_div(mul_pow2(x1, F), rms)  # x / rms with F fraction bits
        return round_shift(n * gain.unsqueeze(0), FG)

    def linear(self, layer: QLinear, x: torch.Tensor) -> torch.Tensor:
        q, shift = quantize_act(x, self.act_bits)
        return layer.forward(q, shift, self.act_bits)

    @staticmethod
    def _rotate_half(x: torch.Tensor) -> torch.Tensor:
        half = x.shape[-1] // 2
        return torch.cat([-x[..., half:], x[..., :half]], dim=-1)

    def attention(self, p: dict, x: torch.Tensor, t: int) -> torch.Tensor:
        q = self.linear(p["q"], x).view(t, self.heads, self.head_dim)
        k = self.linear(p["k"], x).view(t, self.kv_heads, self.head_dim)
        v = self.linear(p["v"], x).view(t, self.kv_heads, self.head_dim)
        q = guard(round_shift(q, F - FA), 26, "a query")
        k = guard(round_shift(k, F - FA), 26, "a key")
        v = guard(round_shift(v, F - FA), 24, "a value")
        cos, sin = self.rope(t)
        cos, sin = cos.unsqueeze(1), sin.unsqueeze(1)  # [t, 1, d]
        q = round_shift(q * cos + self._rotate_half(q) * sin, FT)
        k = round_shift(k * cos + self._rotate_half(k) * sin, FT)
        group = self.heads // self.kv_heads
        qh = q.permute(1, 0, 2)  # [heads, t, d]
        kh = k.repeat_interleave(group, dim=1).permute(1, 0, 2)
        vh = v.repeat_interleave(group, dim=1).permute(1, 0, 2)
        scores = (qh.unsqueeze(2) * kh.unsqueeze(1)).sum(-1)  # [heads, t, s], 2 FA fraction bits
        guard(scores, 45, "an attention score")
        scores = round_shift(scores * self.attn_scale, FS)
        causal = torch.ones((t, t), dtype=torch.bool, device=self.dev).tril().unsqueeze(0)
        scores = torch.where(causal, scores, torch.full_like(scores, -(1 << 60)))
        scores = scores - scores.amax(dim=-1, keepdim=True)
        e = torch.where(causal, iexp(scores, 2 * FA), torch.zeros_like(scores))
        total = e.sum(dim=-1, keepdim=True).clamp(min=1)
        prob = round_shift(floor_div(mul_pow2(e, FP), total), FP - FPV)  # [heads, t, s], FPV fraction bits
        ctx = (prob.unsqueeze(-1) * vh.unsqueeze(1)).sum(2)  # [heads, t, d], FPV + FA fraction bits
        ctx = round_shift(ctx, FPV + FA - F).permute(1, 0, 2).reshape(t, self.heads * self.head_dim)
        return self.linear(p["o"], ctx)

    def mlp(self, p: dict, x: torch.Tensor) -> torch.Tensor:
        gate = self.linear(p["gate"], x)
        up = self.linear(p["up"], x)
        sig = floor_div(isigmoid(mul_pow2(gate, FP - F), FP), 1 << (FP - F))  # F fraction bits
        act = round_shift(gate * sig, F)
        aq, ashift = quantize_act(act, ACT_BITS)
        uq, ushift = quantize_act(up, ACT_BITS)
        prod = guard(shift_signed(aq * uq, ashift + ushift - F), OUT_BITS, "a gated product")
        return self.linear(p["down"], prod)

    @torch.no_grad()
    def last_accumulator(self, input_ids: list) -> tuple:
        """Run the model over input_ids; returns the lm_head accumulator of
        the last position [vocab] (int64) and its activation shift: the
        logits are acc * 2^(shift - F) * scale."""
        t = len(input_ids)
        if t < 1:
            raise IntegerDoorError("empty input")
        rows = self.embed[torch.tensor(input_ids, dtype=torch.long)].to(torch.float32).numpy().astype(np.float64)
        x = torch.from_numpy(np.rint(rows * float(1 << F)).astype(np.int64)).to(self.dev)
        for p in self.layers:
            x = x + self.attention(p, self.rmsnorm(x, p["norm1"]), t)
            x = x + self.mlp(p, self.rmsnorm(x, p["norm2"]))
            guard(x, GUARD_BITS, "the residual stream")
        h = self.rmsnorm(x[-1:], self.norm)
        q, shift = quantize_act(h, self.act_bits)
        acc = self.lm_head.accumulate(q, self.act_bits)[0, : self.vocab]
        return acc, int(shift[0, 0])

    def scaled(self, acc: torch.Tensor, shift: int, index) -> np.ndarray:
        """The accumulator's entries at index as float64 logits: one IEEE
        multiplication per entry, on the CPU."""
        idx = np.asarray(index, dtype=np.int64)
        a = acc.cpu().numpy()[idx].astype(np.float64)
        return a * float(2.0 ** (shift - F)) * self.lm_head.scale[idx]

    def last_logits(self, input_ids: list, index: list) -> np.ndarray:
        """Float32 logits of the last position at the token indices given."""
        acc, shift = self.last_accumulator(input_ids)
        return self.scaled(acc, shift, index).astype("<f4")

    def argmax(self, input_ids: list) -> int:
        """The next token the integer model prefers (ties to the lowest id)."""
        acc, shift = self.last_accumulator(input_ids)
        return int(np.argmax(self.scaled(acc, shift, np.arange(self.vocab))))


def describe(act_bits: int = ACT_BITS) -> dict:
    """What the door computes, recorded in the genome beside its outputs."""
    return {
        "scheme": SCHEME,
        "weights": "int8 per output channel, symmetric; the LoRA delta merged first",
        "activations": f"{act_bits}-bit per row, power-of-two scale",
        "fraction_bits": {"hidden": F, "attention": FA, "exp": FP, "probability": FPV, "tables": FT, "gain": FG},
        "gemm": "int8 x int8 -> int32, exact",
        "nonlinearities": "integer isqrt for RMSNorm, exp by shift-and-square Taylor, integer softmax and SiLU (after I-BERT), rotary tables without a float",
    }
