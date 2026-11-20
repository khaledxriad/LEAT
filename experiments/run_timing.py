"""Timing experiments (single thread, median of repeated runs).

A. functional-scale pipeline (n = 64..384): encryption, enclave kernel, enclave
   service time under the boundary model, full user side, local decryption, unseal.
B. kernel benchmark with random data up to n = 1344 (the kernels are data
   independent); the user-side LEAT column is the K x K product only.
C. clause-size sweep at n = 64.   D. attribute-universe sweep at n = 64.
"""
import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common import median_time, write_csv  # noqa: E402
from leat import Params, setup_keyfirst, issue_key, scheme, local_decrypt  # noqa: E402
from leat import modarith as ma  # noqa: E402
from leat.enclave import AttestationAuthority, Enclave, UserSession, model_time  # noqa: E402


def build(n, w, ell=16, seed=7):
    rng = np.random.default_rng(seed + n + w)
    clause = tuple(range(w))
    p = Params(n=n, ell=ell)
    mpk, E = setup_keyfirst(p, clause, rng)
    aa, plat = AttestationAuthority(), os.urandom(32)
    enc = Enclave(aa.vk, plat)
    uk = issue_key(p, E, "u", clause, rng)
    enc.install("u", uk.TK, clause)
    us = UserSession("u", plat)
    pub, quote = enc.handshake(us.pub, "u")
    us.complete(pub, quote)
    return rng, p, mpk, E, enc, uk, us, clause


def measure(n, w=4, ell=16, reps=5):
    rng, p, mpk, E, enc, uk, us, clause = build(n, w, ell)
    S = set(clause) | {ell - 1}
    ct = scheme.encrypt(mpk, S, b"x" * 32, b"id", rng)
    t_enc = median_time(lambda: scheme.encrypt(mpk, S, b"x" * 32, b"id", rng), reps)
    ker = []
    for _ in range(reps + 1):
        enc.transform("u", ct)
        ker.append(enc.last_kernel_s)
    t_ker = float(np.median(ker[1:]))
    rec = enc.transform("u", ct)

    def user_leat():
        t, c0 = us.open(rec, ct.ctid, enc.epoch)
        scheme.user_finish(ct, t, uk.Z)
    t_user = median_time(user_leat, reps)
    t_local = median_time(lambda: local_decrypt(mpk, ct, E, clause), reps)

    def unseal():
        enc.evict("u")
        enc.unseal("u")
    t_unseal = median_time(unseal, 3)
    return dict(enc=t_enc, ker=t_ker, model=model_time(t_ker), user=t_user,
                local=t_local, unseal=t_unseal, p=p)


def kernel_only(n, reps=3):
    p = Params(n=n)
    rng = np.random.default_rng(n)
    r2 = 2 * p.m
    TK0 = rng.integers(0, 1 << 16, (r2, p.K), dtype=np.int64)
    TK1 = rng.integers(0, 1 << 15, (r2, p.K), dtype=np.int64)
    E = rng.integers(-3000, 3000, (r2, p.K), dtype=np.int64)
    cc = rng.integers(0, ma.Q, r2, dtype=np.int64)
    Z0 = rng.integers(0, 1 << 16, (p.K, p.K), dtype=np.int64)
    Z1 = rng.integers(0, 1 << 15, (p.K, p.K), dtype=np.int64)
    t = rng.integers(0, ma.Q, p.K, dtype=np.int64)
    ker = median_time(lambda: ma.vec_mat_limbs(cc, TK0, TK1), reps)
    loc = median_time(lambda: ma.vec_mat_small(cc, E), reps)
    usr = median_time(lambda: ma.vec_mat_limbs(t, Z0, Z1), 20)
    return p, ker, loc, usr


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--functional", type=int, nargs="+", default=[64, 128, 256, 384])
    ap.add_argument("--scale", type=int, nargs="+", default=[256, 512, 768, 1024, 1344])
    a = ap.parse_args()
    ms = lambda x: round(x * 1e3, 3)  # noqa: E731

    rows = []
    for n in a.functional:
        r = measure(n)
        p = r["p"]
        rows.append([n, p.m, ms(r["enc"]), ms(r["ker"]), ms(r["model"]),
                     ms(r["user"]), ms(r["local"]), round(r["local"] / r["user"]),
                     ms(r["unseal"])])
        print(rows[-1], flush=True)
    write_csv("timing_functional.csv",
              ["n", "m", "enc_ms", "edge_kernel_ms", "edge_enclave_model_ms",
               "user_leat_ms", "user_local_ms", "speedup", "unseal_ms"], rows)

    rows = []
    for n in a.scale:
        p, ker, loc, usr = kernel_only(n)
        rows.append([n, p.m, ms(ker), ms(model_time(ker)), ms(loc), ms(usr),
                     round(p.tk_bytes() / 2**20, 1)])
        print(rows[-1], flush=True)
    write_csv("timing_scale.csv",
              ["n", "m", "edge_kernel_ms", "edge_enclave_model_ms", "user_local_ms",
               "user_leat_ms", "tk_MiB"], rows)

    rows = []
    for w in (1, 2, 4, 8, 12, 16):
        r = measure(64, w=w)
        rows.append([w, ms(r["ker"]), ms(r["user"]), ms(r["local"]),
                     round(r["p"].local_download_bytes(w) / 1024, 1),
                     round(Params.leat_download_bytes() / 1024, 2)])
        print(rows[-1], flush=True)
    write_csv("timing_w.csv", ["w", "edge_kernel_ms", "user_leat_ms", "user_local_ms",
                               "local_download_KiB", "leat_download_KiB"], rows)

    rows = []
    for ell in (4, 8, 16, 24, 32):
        r = measure(64, ell=ell)
        rows.append([ell, ms(r["enc"]), round(r["p"].ct_bytes() / 1024, 1)])
        print(rows[-1], flush=True)
    write_csv("timing_ell.csv", ["ell", "encryption_ms", "ciphertext_KiB"], rows)
