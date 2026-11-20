"""Cost of the non-lattice protocol steps and of revocation (measured)."""
import os
import sys

import numpy as np
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common import median_time, write_csv  # noqa: E402
from leat.enclave import AttestationAuthority, Enclave, UserSession  # noqa: E402

ms = lambda x: round(x * 1e3, 3)  # noqa: E731
plat = os.urandom(32)
aa = AttestationAuthority()
enc = Enclave(aa.vk, plat)


def handshake():
    us = UserSession("u", plat)
    pub, quote = enc.handshake(us.pub, "u")
    us.complete(pub, quote)


def epoch_cert():
    a = AttestationAuthority()
    e = Enclave(a.vk, plat)
    users = ["user%03d" % i for i in range(100)]
    cert = a.revoke(users)
    assert e.apply_certificate(cert)


# sign + verify + state update (the enclave holds no large shares here: the cost
# of the certificate does not depend on the number of stored ciphertexts)
def epoch_only():
    a = AttestationAuthority()
    e = Enclave(a.vk, plat)
    users = ["user%03d" % i for i in range(100)]
    cert = a.revoke(users)
    return e, cert


key, nonce, data = AESGCM.generate_key(256), os.urandom(12), os.urandom(1 << 20)
aead = AESGCM(key)
blob = aead.encrypt(nonce, data, None)
sk = ec.generate_private_key(ec.SECP256R1())
peer = ec.generate_private_key(ec.SECP256R1()).public_key()

rows = [
    ["Attested-channel handshake (X25519 + HKDF + quote check)", ms(median_time(handshake, 50))],
    ["Epoch certificate: Ed25519 sign + verify + state update (100 revoked users)",
     ms(median_time(epoch_cert, 50))],
    ["AES-256-GCM encrypt 1 MiB payload", ms(median_time(lambda: aead.encrypt(nonce, data, None), 50))],
    ["AES-256-GCM decrypt 1 MiB payload", ms(median_time(lambda: aead.decrypt(nonce, blob, None), 50))],
    ["P-256 scalar multiplication (ECDH, OpenSSL)", ms(median_time(lambda: sk.exchange(ec.ECDH(), peer), 200))],
]
for r in rows:
    print(r)
write_csv("protocol.csv", ["step", "time_ms"], rows)
