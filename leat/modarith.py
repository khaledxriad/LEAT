"""Exact modular linear algebra over Z_q with 64-bit accumulators.

With q = 2^31-1 the product of two residues needs 62 bits, and a sum of
thousands of such products overflows int64.  We therefore (i) split the
full-width key matrix into two 16-bit limbs and (ii) reduce after every block of
2^15 rows, which keeps every partial sum below 2^63.  The short key matrix E
(|entries| < 2^13) needs no limb split.
"""
import numpy as np

Q = 2**31 - 1
CHUNK = 1 << 15


def split_limbs(M):
    """Split a matrix with entries in [0, 2^32) into two 16-bit limbs (int64,
    so that the kernels need no per-call type conversion)."""
    M = np.asarray(M, dtype=np.int64)
    return M & 0xFFFF, M >> 16


def vec_mat_limbs(c, M0, M1, q=Q):
    """(c @ M) mod q for c of shape (r,) with entries in [0,q) and
    M = M0 + 2^16 * M1 given as uint16 limbs of shape (r, N)."""
    c = np.asarray(c, dtype=np.int64)
    r, N = M0.shape
    acc0 = np.zeros(N, dtype=np.int64)
    acc1 = np.zeros(N, dtype=np.int64)
    for s in range(0, r, CHUNK):
        cc = c[s:s + CHUNK]
        acc0 = (acc0 + (cc @ np.asarray(M0[s:s + CHUNK], dtype=np.int64)) % q) % q
        acc1 = (acc1 + (cc @ np.asarray(M1[s:s + CHUNK], dtype=np.int64)) % q) % q
    return (acc0 + (acc1 * 65536) % q) % q


def vec_mat_small(c, E, q=Q):
    """(c @ E) mod q for a short signed integer matrix E (|E| < 2^13)."""
    c = np.asarray(c, dtype=np.int64)
    r, N = E.shape
    acc = np.zeros(N, dtype=np.int64)
    for s in range(0, r, CHUNK):
        acc = (acc + (c[s:s + CHUNK] @ np.asarray(E[s:s + CHUNK], dtype=np.int64)) % q) % q
    return acc


def vec_mat_wide(s, M, q=Q):
    """(s @ M) mod q for a full-width vector s (length n <= 2^11) by splitting
    s into two 16-bit limbs; M has entries in [0,q) and shape (n, N)."""
    s = np.asarray(s, dtype=np.int64)
    M = np.asarray(M, dtype=np.int64)
    lo, hi = s & 0xFFFF, s >> 16
    return ((lo @ M) % q + ((hi @ M) % q) * 65536) % q


def mat_mat_small_full(E, Z, q=Q):
    """(E @ Z) mod q with E short signed (2m x K) and Z full-width (K x K)."""
    E = np.asarray(E, dtype=np.int64)
    Z0, Z1 = split_limbs(Z)
    return ((E @ Z0.astype(np.int64)) % q +
            ((E @ Z1.astype(np.int64)) % q) * 65536) % q


def mat_mul_full(A, B, q=Q):
    """(A @ B) mod q for two small full-width square matrices (inner dim<=2^14)."""
    A = np.asarray(A, dtype=np.int64)
    B0, B1 = split_limbs(B)
    return ((A @ B0.astype(np.int64)) % q +
            ((A @ B1.astype(np.int64)) % q) * 65536) % q


def inv_mod(M, q=Q):
    """Inverse of a square matrix over the prime field Z_q (Gauss-Jordan).
    Raises ValueError if M is singular."""
    n = M.shape[0]
    A = np.concatenate([np.asarray(M, dtype=np.int64) % q,
                        np.eye(n, dtype=np.int64)], axis=1)
    for col in range(n):
        piv = None
        for r in range(col, n):
            if A[r, col] % q:
                piv = r
                break
        if piv is None:
            raise ValueError("singular matrix")
        if piv != col:
            A[[col, piv]] = A[[piv, col]]
        A[col] = (A[col] * pow(int(A[col, col]), q - 2, q)) % q
        f = A[:, col].copy()
        f[col] = 0
        A = (A - (f[:, None] * A[col][None, :]) % q) % q
    return A[:, n:]


def center(x, q=Q):
    """Representative of x mod q in (-q/2, q/2]."""
    x = np.asarray(x, dtype=np.int64) % q
    return np.where(x > q // 2, x - q, x)
