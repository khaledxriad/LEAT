"""Algorithms 1, 2 and 4 of the paper (setup/key issuance, encryption, user
completion) plus the local-decryption baseline.

Key generation is the *key-first shortcut* described in the paper: the short
key E is sampled first and the public matrix U is derived from it.  The result
has the same algebraic relation [A|B_C]E = U and the same sizes as the real
TrapGen/SampleLeft chain, but carries NO security claim.
"""
import hashlib
from dataclasses import dataclass

import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import modarith as ma
from .params import Params

Q = ma.Q


@dataclass
class MPK:
    params: Params
    A: np.ndarray            # (n, m)
    B: np.ndarray            # (ell, n, m)
    U: np.ndarray            # (n, K)


@dataclass
class Ciphertext:
    ctid: bytes
    S: frozenset
    c_A: np.ndarray          # (m,)
    c_j: np.ndarray          # (ell, m)
    c_0: np.ndarray          # (K,)
    h: bytes
    dem: bytes
    nonce: bytes


@dataclass
class UserKey:
    user: str
    clause: tuple
    Z: np.ndarray            # (K, K)  stays with the user
    TK: np.ndarray           # (2m, K) goes to the enclave only


def _gauss(rng, sigma, shape):
    return np.rint(rng.normal(0.0, sigma, shape)).astype(np.int64)


def kdf(mu_bits, ctid):
    mu = np.packbits(np.asarray(mu_bits, dtype=np.uint8)).tobytes()
    return HKDF(hashes.SHA256(), 32, salt=None, info=b"LEAT-KDF|" + ctid).derive(mu)


def commit(kappa, ctid):
    return hashlib.sha256(kappa + ctid).digest()


def ad_of(ctid, S):
    return ctid + b"|" + bytes(sorted(S))


def setup_keyfirst(params: Params, clause, rng):
    """Return (mpk, E) where E is the short key of the clause (key-first)."""
    n, m, K, ell = params.n, params.m, params.K, params.ell
    A = rng.integers(0, Q, (n, m), dtype=np.int64)
    B = rng.integers(0, Q, (ell, n, m), dtype=np.int64)
    E = _gauss(rng, params.sigma_E, (2 * m, K))
    BC = B[list(clause)].sum(axis=0) % Q
    M = np.concatenate([A, BC], axis=1)                       # n x 2m
    U = np.stack([ma.vec_mat_small(M[i], E) for i in range(n)])  # n x K
    return MPK(params, A, B, U), E


def issue_key(params: Params, E, user, clause, rng):
    """Blind E: TK = E Z^{-1} mod q (Algorithm 1, KeyGen)."""
    K = params.K
    while True:
        Z = rng.integers(0, Q, (K, K), dtype=np.int64)
        try:
            Zinv = ma.inv_mod(Z)
            break
        except ValueError:
            continue
    TK = ma.mat_mat_small_full(E, Zinv)
    return UserKey(user, tuple(clause), Z, TK)


def encrypt(mpk: MPK, S, payload: bytes, ctid: bytes, rng, mu=None):
    p = mpk.params
    n, m, K, k, ell = p.n, p.m, p.K, p.k, p.ell
    S = frozenset(S)
    if mu is None:
        mu = rng.integers(0, 2, K, dtype=np.uint8)
    kappa = kdf(mu, ctid)
    h = commit(kappa, ctid)
    x = np.array([0 if j in S else 1 for j in range(ell)], dtype=np.int64)
    s = rng.integers(0, Q, n, dtype=np.int64)
    # s^T G : entry i*k+t is s_i * 2^t, remaining columns zero
    sG = np.zeros(m, dtype=np.int64)
    sG[:n * k] = ((s[:, None] * (1 << np.arange(k, dtype=np.int64))[None, :]) % Q).reshape(-1)
    e_A = _gauss(rng, p.sigma0, m)
    c_A = (ma.vec_mat_wide(s, mpk.A) + e_A) % Q
    c_j = np.empty((ell, m), dtype=np.int64)
    for j in range(ell):
        base = ma.vec_mat_wide(s, mpk.B[j])
        c_j[j] = (base + x[j] * sG + _gauss(rng, p.sigma0, m)) % Q
    e0 = _gauss(rng, p.sigma0, K)
    c_0 = (ma.vec_mat_wide(s, mpk.U) + e0 + mu.astype(np.int64) * (Q // 2)) % Q
    nonce = rng.bytes(12)
    dem = AESGCM(kappa).encrypt(nonce, payload, ad_of(ctid, S))
    return Ciphertext(ctid, S, c_A, c_j, c_0, h, dem, nonce)


def round_mu(v):
    lo, hi = -(-Q // 4), (3 * Q) // 4
    return ((v >= lo) & (v <= hi)).astype(np.uint8)


def finish(ct: Ciphertext, v):
    """Rounding, key re-derivation, commitment check and DEM decryption."""
    mu_hat = round_mu(v)
    kappa = kdf(mu_hat, ct.ctid)
    if commit(kappa, ct.ctid) != ct.h:
        return None
    try:
        return AESGCM(kappa).decrypt(ct.nonce, ct.dem, ad_of(ct.ctid, ct.S))
    except Exception:
        return None


def user_finish(ct: Ciphertext, t, Z):
    """Algorithm 4 after the AEAD record has been opened: K^2 MACs."""
    v = (ct.c_0 - ma.vec_mat_limbs(t, *ma.split_limbs(Z))) % Q
    return finish(ct, v)


def local_decrypt(mpk: MPK, ct: Ciphertext, E, clause):
    """Baseline: decapsulate locally with the short key E."""
    c_C = ct.c_j[list(clause)].sum(axis=0) % Q
    cc = np.concatenate([ct.c_A, c_C])
    v = (ct.c_0 - ma.vec_mat_small(cc, E)) % Q
    return finish(ct, v), v


def noise_ratio(v, mu):
    """max_i |centred(v_i - mu_i*floor(q/2))| / (q/4)."""
    eta = ma.center(v - mu.astype(np.int64) * (Q // 2))
    return float(np.max(np.abs(eta)) / (Q / 4))
