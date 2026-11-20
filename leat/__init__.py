"""LEAT: Lattice-based Edge-Attested Transformation (research prototype).

The package implements the algorithms of the paper in plain Python/NumPy so that
every table can be re-derived.  It is a *research prototype*: the enclave is
emulated in software and key generation uses a key-first shortcut, so nothing
here should be used to protect real data.
"""
from .params import Params, Q
from .scheme import (setup_keyfirst, issue_key, encrypt, user_finish,
                     local_decrypt, noise_ratio)
from .enclave import Enclave, AttestationAuthority

__all__ = ["Params", "Q", "setup_keyfirst", "issue_key", "encrypt",
           "user_finish", "local_decrypt", "noise_ratio", "Enclave",
           "AttestationAuthority"]
__version__ = "1.0.0"
