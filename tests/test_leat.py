"""Functional tests: correctness, verifiability, revocation and rollback."""
import os
import unittest

import numpy as np

from leat import Params, setup_keyfirst, issue_key, encrypt, local_decrypt
from leat import scheme, modarith as ma
from leat.enclave import AttestationAuthority, Enclave, UserSession

CLAUSE = (1, 3, 5, 7)


def build(n=64, seed=1):
    rng = np.random.default_rng(seed)
    p = Params(n=n)
    mpk, E = setup_keyfirst(p, CLAUSE, rng)
    aa = AttestationAuthority()
    plat = os.urandom(32)
    enc = Enclave(aa.vk, plat)
    uk = issue_key(p, E, "alice", CLAUSE, rng)
    enc.install("alice", uk.TK, CLAUSE)
    us = UserSession("alice", plat)
    pub, quote = enc.handshake(us.pub, "alice")
    us.complete(pub, quote)
    return rng, p, mpk, E, aa, enc, uk, us


def run_access(enc, us, uk, ct, force=False):
    rec = enc.transform("alice", ct, force=force)
    if rec is None:
        return None
    opened = us.open(rec, ct.ctid, enc.epoch)
    if opened is None:
        return None
    t, c0 = opened
    return scheme.user_finish(ct, t, uk.Z)


class TestLEAT(unittest.TestCase):
    def setUp(self):
        self.rng, self.p, self.mpk, self.E, self.aa, self.enc, self.uk, self.us = build()

    def test_blinding_cancels(self):
        # TK Z = E (mod q) on a random probe vector
        x = self.rng.integers(0, ma.Q, self.uk.TK.shape[0], dtype=np.int64)
        lhs = ma.vec_mat_limbs(ma.vec_mat_limbs(x, *ma.split_limbs(self.uk.TK)),
                               *ma.split_limbs(self.uk.Z))
        rhs = ma.vec_mat_small(x, self.E)
        self.assertTrue(np.array_equal(lhs, rhs))

    def test_correct_and_noise(self):
        for i in range(5):
            S = set(CLAUSE) | set(self.rng.choice(16, 3, replace=False).tolist())
            msg = os.urandom(64)
            ct = scheme.encrypt(self.mpk, S, msg, b"id%d" % i, self.rng)
            self.assertEqual(run_access(self.enc, self.us, self.uk, ct), msg)
            self.assertEqual(local_decrypt(self.mpk, ct, self.E, CLAUSE)[0], msg)

    def test_missing_attribute_rejected(self):
        S = set(CLAUSE) - {5}
        ct = scheme.encrypt(self.mpk, S, b"secret", b"neg", self.rng)
        self.assertIsNone(run_access(self.enc, self.us, self.uk, ct))
        self.assertIsNone(run_access(self.enc, self.us, self.uk, ct, force=True))
        self.assertIsNone(local_decrypt(self.mpk, ct, self.E, CLAUSE)[0])

    def test_malicious_result_detected(self):
        ct = scheme.encrypt(self.mpk, set(CLAUSE), b"m", b"v", self.rng)
        t, c0 = self.us.open(self.enc.transform("alice", ct), ct.ctid, self.enc.epoch)
        t_bad = (t + 12345) % ma.Q          # even a perturbation of one word
        t_bad[0] = (t_bad[0] + ma.Q // 3) % ma.Q
        self.assertIsNone(scheme.user_finish(ct, t_bad, self.uk.Z))

    def test_revocation_and_rollback(self):
        ct = scheme.encrypt(self.mpk, set(CLAUSE), b"m", b"r", self.rng)
        old_blob = self.enc.sealed_blob("alice")
        self.assertEqual(run_access(self.enc, self.us, self.uk, ct), b"m")
        self.assertTrue(self.enc.apply_certificate(self.aa.revoke(["alice"])))
        self.assertIsNone(run_access(self.enc, self.us, self.uk, ct))
        self.enc.restore_blob("alice", old_blob)       # host replays old blob
        self.assertIsNone(run_access(self.enc, self.us, self.uk, ct))
        new_ct = scheme.encrypt(self.mpk, set(CLAUSE), b"n", b"r2", self.rng)
        self.assertIsNone(run_access(self.enc, self.us, self.uk, new_ct))

    def test_stale_or_forged_certificate(self):
        cert = self.aa.revoke(["bob"])
        self.assertTrue(self.enc.apply_certificate(cert))
        self.assertFalse(self.enc.apply_certificate(cert))      # replay
        bad = (cert[0] + 1, cert[1], cert[2], cert[3])
        self.assertFalse(self.enc.apply_certificate(bad))       # forged

    def test_download_size(self):
        ct = scheme.encrypt(self.mpk, set(CLAUSE), b"m", b"s", self.rng)
        nonce, blob = self.enc.transform("alice", ct)
        self.assertEqual(len(nonce) + len(blob), Params.leat_download_bytes())


if __name__ == "__main__":
    unittest.main()
