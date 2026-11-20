"""Primal uSVP / core-SVP estimate used for the security columns.

For a block size beta the attack succeeds when
    sqrt(beta) * sigma <= delta(beta)^(2*beta-d-1) * q^(m/d),   d = m+n+1,
and the core-SVP cost is 0.292*beta (classical) / 0.265*beta (quantum) bits
[Albrecht-Player-Scott 2015; Alkim et al. 2016; Bos et al. 2018].  beta is
floored at 40, the smallest block size the model is meaningful for.
As a calibration, the same function gives beta=483 (141 classical bits) for
FrodoKEM-640-like parameters (n=640, q=2^15, sigma=2.8).
"""
from math import e, pi, sqrt

BETA_FLOOR = 40


def delta(b: int) -> float:
    return ((pi * b) ** (1.0 / b) * b / (2 * pi * e)) ** (1.0 / (2 * (b - 1)))


def beta_primal(n: int, q: int, sigma: float, mmax: int | None = None) -> int:
    best = None
    step = max(1, n // 64)
    for m in range(max(n // 2, 50), (mmax or 2 * n) + 1, step):
        d = m + n + 1
        for b in range(BETA_FLOOR, min(d, 3000)):
            if sqrt(b) * sigma <= delta(b) ** (2 * b - d - 1) * q ** (m / d):
                if best is None or b < best:
                    best = b
                break
    return best


def core_svp_bits(beta: int) -> tuple[float, float]:
    return 0.292 * beta, 0.265 * beta
