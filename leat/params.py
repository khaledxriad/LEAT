"""Parameter sets and closed-form size/noise formulas (all from the paper)."""
from dataclasses import dataclass
from math import ceil, log2, sqrt

Q = 2**31 - 1          # prime modulus used by the functional-scale prototype
KBITS = 256            # length of the encapsulated key (columns of U)


@dataclass(frozen=True)
class Params:
    n: int                  # LWE dimension
    q: int = Q              # prime modulus
    ell: int = 16           # attribute universe size
    sigma0: float = 3.2     # LWE error width
    tau: float = 8.0        # tail factor of the noise bound
    K: int = KBITS

    @property
    def k(self) -> int:     # bits per residue, ceil(log2 q)
        return ceil(log2(self.q))

    @property
    def m(self) -> int:     # m = 2nk
        return 2 * self.n * self.k

    @property
    def sigma_E(self) -> float:   # key-sampling width 4*sqrt(nk)
        return 4.0 * sqrt(self.n * self.k)

    def noise_bound(self, w: int) -> float:
        """T(w) of Lemma 2 (decryption-noise bound for clause size w)."""
        return (self.tau * self.sigma0 * self.sigma_E *
                sqrt(2 * self.m * (1 + w)) + self.tau * self.sigma0)

    def correct(self, w: int) -> bool:
        return self.q / 4 > self.noise_bound(w) + 1

    # ---- sizes in bytes (residues are bit-packed to k bits) -----------------
    def ct_bytes(self) -> float:
        return ((1 + self.ell) * self.m * self.k + self.K * self.k) / 8

    def local_download_bytes(self, w: int) -> float:
        return ((1 + w) * self.m * self.k + self.K * self.k) / 8

    def tk_bytes(self, packed: bool = False) -> float:
        bits = self.k if packed else 32
        return 2 * self.m * self.K * bits / 8

    def z_bytes(self, packed: bool = False) -> float:
        bits = self.k if packed else 32
        return self.K * self.K * bits / 8

    def e_bytes(self) -> float:          # key E stored with 16-bit entries
        return 2 * self.m * self.K * 2

    @staticmethod
    def leat_download_bytes() -> int:
        """Proposition 1: 2*K*ceil(k/8) + 12-byte nonce + 16-byte tag."""
        return 2 * KBITS * 4 + 28


def smallest_modulus_bits(n: int, w: int, tau: float = 8.0,
                          sigma0: float = 3.2, kmax: int = 40) -> int:
    """Smallest k such that q=2^k-1 satisfies q/4 > T(w)+1 (projection rule)."""
    for k in range(10, kmax):
        p = Params(n=n, q=2**k - 1, sigma0=sigma0, tau=tau)
        if p.correct(w):
            return k
    raise ValueError("no modulus found")
