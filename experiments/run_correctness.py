"""Table: functional correctness (60 trials per dimension by default).

Every trial encrypts a fresh random 256-bit key for a random attribute set and
decrypts it through the full path (enclave -> user) and locally.  The negative
test removes one required attribute and expects rejection both by the enclave's
policy check and, with the check bypassed, by the commitment check.
"""
import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common import write_csv  # noqa: E402
from leat import Params, setup_keyfirst, issue_key, scheme, local_decrypt  # noqa: E402
from leat import modarith as ma  # noqa: E402
from leat.enclave import AttestationAuthority, Enclave, UserSession  # noqa: E402

CLAUSE = (1, 4, 6, 9)


def run(n, trials, seed):
    rng = np.random.default_rng(seed)
    p = Params(n=n)
    mpk, E = setup_keyfirst(p, CLAUSE, rng)
    aa, plat = AttestationAuthority(), os.urandom(32)
    enc = Enclave(aa.vk, plat)
    uk = issue_key(p, E, "u", CLAUSE, rng)
    enc.install("u", uk.TK, CLAUSE)
    us = UserSession("u", plat)
    enc_pub, quote = enc.handshake(us.pub, "u")
    us.complete(enc_pub, quote)
    ok_leat = ok_local = neg_ok = 0
    worst = 0.0
    for i in range(trials):
        extra = rng.choice([j for j in range(p.ell) if j not in CLAUSE],
                           rng.integers(0, 6), replace=False).tolist()
        S = set(CLAUSE) | set(extra)
        mu = rng.integers(0, 2, p.K, dtype=np.uint8)
        msg = os.urandom(32)
        ct = scheme.encrypt(mpk, S, msg, b"c%d" % i, rng, mu=mu)
        # noise of the local decapsulation
        out, v = local_decrypt(mpk, ct, E, CLAUSE)
        worst = max(worst, scheme.noise_ratio(v, mu))
        ok_local += out == msg
        rec = enc.transform("u", ct)
        t, c0 = us.open(rec, ct.ctid, enc.epoch)
        ok_leat += scheme.user_finish(ct, t, uk.Z) == msg
        # negative test
        S2 = S - {int(rng.choice(CLAUSE))}
        ct2 = scheme.encrypt(mpk, S2, msg, b"n%d" % i, rng, mu=mu)
        r1 = enc.transform("u", ct2)
        r2 = enc.transform("u", ct2, force=True)
        t2, _ = us.open(r2, ct2.ctid, enc.epoch)
        neg_ok += (r1 is None and scheme.user_finish(ct2, t2, uk.Z) is None
                   and local_decrypt(mpk, ct2, E, CLAUSE)[0] is None)
    return [n, trials, ok_leat, ok_local, round(worst, 4), neg_ok]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, nargs="+", default=[64, 128, 256, 384])
    ap.add_argument("--trials", type=int, default=60)
    ap.add_argument("--seed", type=int, default=2026)
    a = ap.parse_args()
    rows = []
    for n in a.n:
        r = run(n, a.trials, a.seed + n)
        print(r, flush=True)
        rows.append(r)
    write_csv("correctness.csv",
              ["n", "trials", "leat_ok", "local_ok", "worst_noise_over_q4",
               "negative_rejected"], rows)
