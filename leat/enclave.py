"""Software emulation of the attested enclave and the attribute authority.

The enclave is a Python object whose state is name-mangled and only reachable
through its methods.  Attestation is modelled with an HMAC "quote" under a
platform key; sealing is AES-GCM under a key derived from (identity, epoch,
monotonic counter).  Timing of the enclave boundary is *modelled*
(see ``model_time``), not measured on SGX/TrustZone hardware.
"""
import hashlib
import hmac
import struct
import time

import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey,
                                                              X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import modarith as ma

BOUNDARY_CYCLES = 8000          # modelled per-call enclave transition cost
CPU_HZ = 2.1e9
MEM_ENC_FACTOR = 1.15           # modelled memory-encryption factor on kernel time


def model_time(kernel_s: float) -> float:
    """Enclave service time = 1.15 x kernel time + one boundary crossing."""
    return MEM_ENC_FACTOR * kernel_s + BOUNDARY_CYCLES / CPU_HZ


def _raw(pub):
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _hkdf(key, info, length=32):
    return HKDF(hashes.SHA256(), length, salt=None, info=info).derive(key)


class AttestationAuthority:
    """The attribute authority (AA): signs epoch certificates."""

    def __init__(self):
        self._sk = Ed25519PrivateKey.generate()
        self.vk = self._sk.public_key()
        self.epoch = 0
        self.revoked = set()

    def revoke(self, users):
        self.epoch += 1
        self.revoked |= set(users)
        digest = hashlib.sha256(",".join(sorted(self.revoked)).encode()).digest()
        msg = struct.pack(">Q", self.epoch) + ",".join(sorted(users)).encode() + b"|" + digest
        return self.epoch, sorted(users), digest, self._sk.sign(msg)


class Enclave:
    def __init__(self, vk_AA, platform_key: bytes, measurement=b"LEAT-enclave-v1"):
        self.__vk = vk_AA
        self.__platform = platform_key
        self.measurement = measurement
        self.__tk = {}            # resident key shares: user -> (TK0, TK1, clause)
        self.__sealed = {}        # sealed blobs on "untrusted" media
        self.__rev = set()
        self.__epoch = 0
        self.__counter = 0
        self.__sessions = {}
        self.last_kernel_s = 0.0

    # ---- attestation and attested channel -----------------------------------
    def handshake(self, user_pub_raw: bytes, user):
        sk = X25519PrivateKey.generate()
        pub = _raw(sk.public_key())
        quote = hmac.new(self.__platform, self.measurement + pub + user_pub_raw,
                         hashlib.sha256).digest()
        shared = sk.exchange(X25519PublicKey.from_public_bytes(user_pub_raw))
        self.__sessions[user] = _hkdf(shared, b"LEAT-session|" + user.encode())
        return pub, quote

    # ---- provisioning and sealing ---------------------------------------------
    def __seal_key(self):
        return _hkdf(self.__platform, b"seal|" + self.measurement +
                     struct.pack(">QQ", self.__epoch, self.__counter))

    def install(self, user, TK, clause):
        TK0, TK1 = ma.split_limbs(TK)
        self.__tk[user] = (TK0, TK1, tuple(clause))
        self.__seal_one(user)

    def __seal_one(self, user):
        TK0, TK1, clause = self.__tk[user]
        blob = TK0.astype(np.uint16).tobytes() + TK1.astype(np.uint16).tobytes()
        nonce = struct.pack(">QQ", self.__epoch, self.__counter)[:12]
        ct = AESGCM(self.__seal_key()).encrypt(nonce, blob, user.encode())
        self.__sealed[user] = (nonce, ct, TK0.shape, clause)

    def evict(self, user):
        self.__tk.pop(user, None)

    def unseal(self, user):
        """Bring a sealed share back into enclave memory."""
        nonce, ct, shape, clause = self.__sealed[user]
        blob = AESGCM(self.__seal_key()).decrypt(nonce, ct, user.encode())
        half = shape[0] * shape[1] * 2
        TK0 = np.frombuffer(blob[:half], dtype=np.uint16).reshape(shape).astype(np.int64)
        TK1 = np.frombuffer(blob[half:], dtype=np.uint16).reshape(shape).astype(np.int64)
        self.__tk[user] = (TK0, TK1, clause)

    def sealed_blob(self, user):
        return self.__sealed[user]

    def restore_blob(self, user, blob):
        """What a malicious host can do: put back an old sealed blob."""
        self.__sealed[user] = blob

    def resident(self):
        return set(self.__tk)

    # ---- Algorithm 3: transformation ------------------------------------------
    def transform(self, user, ct, force=False):
        """Return the AEAD record carrying (t, c_0), or None (the bottom symbol)."""
        if user in self.__rev:
            return None
        if user not in self.__tk:
            if user not in self.__sealed:
                return None
            self.unseal(user)
        TK0, TK1, clause = self.__tk[user]
        if not force and not set(clause) <= set(ct.S):
            return None
        t0 = time.perf_counter()
        c_C = ct.c_j[list(clause)].sum(axis=0) % ma.Q
        cc = np.concatenate([ct.c_A, c_C])
        t = ma.vec_mat_limbs(cc, TK0, TK1)
        self.last_kernel_s = time.perf_counter() - t0
        payload = t.astype("<u4").tobytes() + ct.c_0.astype("<u4").tobytes()
        nonce = hashlib.sha256(ct.ctid + user.encode()).digest()[:12]
        ad = user.encode() + ct.ctid + struct.pack(">Q", self.__epoch)
        return nonce, AESGCM(self.__sessions[user]).encrypt(nonce, payload, ad)

    # ---- Algorithm 5: revocation ------------------------------------------------
    def apply_certificate(self, cert):
        epoch, users, digest, sig = cert
        msg = struct.pack(">Q", epoch) + ",".join(sorted(users)).encode() + b"|" + digest
        try:
            self.__vk.verify(sig, msg)
        except InvalidSignature:
            return False
        if epoch <= self.__epoch:
            return False
        for u in users:
            self.__tk.pop(u, None)
            self.__sealed.pop(u, None)
            self.__rev.add(u)
        self.__epoch = epoch
        self.__counter += 1
        for u in list(self.__tk):            # re-seal the remaining shares
            self.__seal_one(u)
        return True

    @property
    def epoch(self):
        return self.__epoch


class UserSession:
    """User side of the attested channel and of Algorithm 4's AEAD opening."""

    def __init__(self, user, platform_key, measurement=b"LEAT-enclave-v1"):
        self.user = user
        self.__platform = platform_key
        self.measurement = measurement
        self.__sk = X25519PrivateKey.generate()
        self.pub = _raw(self.__sk.public_key())
        self.key = None

    def complete(self, enclave_pub, quote):
        want = hmac.new(self.__platform, self.measurement + enclave_pub + self.pub,
                        hashlib.sha256).digest()
        if not hmac.compare_digest(want, quote):
            raise ValueError("attestation failed")
        shared = self.__sk.exchange(X25519PublicKey.from_public_bytes(enclave_pub))
        self.key = _hkdf(shared, b"LEAT-session|" + self.user.encode())

    def open(self, record, ctid, epoch):
        nonce, ct = record
        ad = self.user.encode() + ctid + struct.pack(">Q", epoch)
        try:
            raw = AESGCM(self.key).decrypt(nonce, ct, ad)
        except Exception:
            return None
        a = np.frombuffer(raw, dtype="<u4").astype(np.int64)
        return a[:256], a[256:]
