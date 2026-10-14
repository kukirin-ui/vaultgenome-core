# Copyright (C) 2026 Serhii Nikolaichuk, Rodion Sorokin
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Integer-only mathematics for the integer door.

The constants and tables a transformer's forward pass needs — π, ln 2, the
logarithm of the RoPE base, the RoPE frequencies, cosines and sines, an
inverse square root — computed with Python's arbitrary-precision integers
and rounded once to fixed point. No float takes part, so every platform
produces the same table bytes by construction: this is what lets the
integer door promise the same output on any CPU or GPU.

Values are fixed-point integers with PREC fraction bits while they are
computed and are rounded to the caller's fraction bits at the end.
"""

from fractions import Fraction
from functools import lru_cache
import math

PREC = 128
ONE = 1 << PREC


def to_q(x: int, bits: int) -> int:
    """Round a PREC-bit fixed-point value to `bits` fraction bits (half up)."""
    return (x + (1 << (PREC - bits - 1))) >> (PREC - bits)


def _atan_inv(n: int) -> int:
    """atan(1/n) = Σ (-1)^k / ((2k+1) n^(2k+1))."""
    total, power, k, n2 = 0, ONE // n, 0, n * n
    while power:
        term = power // (2 * k + 1)
        total += -term if k & 1 else term
        power //= n2
        k += 1
    return total


@lru_cache(maxsize=None)
def pi_fixed() -> int:
    """π by Machin's formula."""
    return 16 * _atan_inv(5) - 4 * _atan_inv(239)


@lru_cache(maxsize=None)
def ln2_fixed() -> int:
    """ln 2 = Σ 1 / (k 2^k)."""
    total, k = 0, 1
    while True:
        term = ONE // (k << k)
        if term == 0:
            return total
        total += term
        k += 1


def ln_fixed(x: Fraction) -> int:
    """ln x for a positive rational x: x = 2^e m with m in [1, 2), then
    ln m = 2 atanh((m - 1) / (m + 1))."""
    if x <= 0:
        raise ValueError("ln of a non-positive number")
    m = (x.numerator << PREC) // x.denominator
    e = m.bit_length() - PREC - 1
    m = m >> e if e >= 0 else m << -e
    y = ((m - ONE) << PREC) // (m + ONE)
    y2 = (y * y) >> PREC
    total, power, k = 0, y, 0
    while power:
        total += power // (2 * k + 1)
        power = (power * y2) >> PREC
        k += 1
    return 2 * total + e * ln2_fixed()


def exp_fixed(x: int) -> int:
    """e^x for a fixed-point x of either sign: x = n ln2 + r with |r| <= ln2/2,
    e^x = 2^n Σ r^k / k!."""
    ln2 = ln2_fixed()
    n = (x + ln2 // 2) // ln2
    r = x - n * ln2
    negative, r = r < 0, abs(r)
    total, term, k = ONE, ONE, 1
    while term:
        term = (term * r) // (ONE * k)  # |r|^k / k!, non-negative
        total += -term if (negative and k & 1) else term
        k += 1
    if n >= 0:
        return total << n
    return (total + (1 << (-n - 1))) >> -n


def cos_sin_fixed(angle: int) -> tuple:
    """cos and sin of a fixed-point angle, by Taylor series after reducing
    the angle to (-π, π]."""
    pi = pi_fixed()
    a = angle % (2 * pi)
    if a > pi:
        a -= 2 * pi
    a2 = (a * a) >> PREC
    cos, term, k = 0, ONE, 0
    while term:
        cos += -term if k & 1 else term
        k += 1
        term = (term * a2) // (ONE * (2 * k - 1) * (2 * k))
    sin, term, k = 0, abs(a), 0
    while term:
        sin += -term if k & 1 else term
        k += 1
        term = (term * a2) // (ONE * (2 * k) * (2 * k + 1))
    return cos, (-sin if a < 0 else sin)


def inv_sqrt_q(n: int, bits: int) -> int:
    """1 / sqrt(n) with `bits` fraction bits, for a positive integer n."""
    if n <= 0:
        raise ValueError("inverse square root of a non-positive number")
    return to_q(math.isqrt((ONE * ONE) // n), bits)


def rope_tables(base: Fraction, head_dim: int, positions: int, bits: int) -> tuple:
    """The rotary tables of a model: cos and sin of position * base^(-2i/d)
    for i < d/2 and every position, as lists of rows of `bits`-bit
    fixed-point integers. Exactly what transformers computes from
    `inv_freq = 1 / base^(arange(0, d, 2) / d)`, without its float."""
    if head_dim < 2 or head_dim % 2:
        raise ValueError("head_dim must be even")
    ln_base = ln_fixed(base)
    inv_freq = [exp_fixed(-(2 * i * ln_base) // head_dim) for i in range(head_dim // 2)]
    cos_rows, sin_rows = [], []
    for pos in range(positions):
        cos_row, sin_row = [], []
        for f in inv_freq:
            c, s = cos_sin_fixed(pos * f)
            cos_row.append(to_q(c, bits))
            sin_row.append(to_q(s, bits))
        cos_rows.append(cos_row)
        sin_rows.append(sin_row)
    return cos_rows, sin_rows


def eps_table(eps: Fraction, fraction_bits: int, max_shift: int) -> list:
    """RMSNorm's epsilon at the scale of x² for every possible pre-shift of
    x: entry s is eps * 2^(2 (fraction_bits - s)), rounded."""
    out = []
    for s in range(max_shift + 1):
        scale = 2 * (fraction_bits - s)
        if scale >= 0:
            v = Fraction(eps) * (1 << scale)
        else:
            v = Fraction(eps) / (1 << -scale)
        out.append(int(v + Fraction(1, 2)) if v > 0 else 0)
    return out
