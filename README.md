# LEAT: Lattice-Based Edge-Attested Transformation

Reference implementation and experiment code for the paper
**"LEAT: Lattice-Based Edge-Attested Transformation for Attribute-Based Encryption"**
by Khaled Riad (Computer Science Department, College of Computer Sciences & Information Technology,
King Faisal University, Al-Ahsa, Saudi Arabia; kriad@kfu.edu.sa).

> **Research prototype. Not for production use.** The enclave is emulated in software, key generation
> uses a key-first shortcut that carries no security claim, and the small dimensions (n = 64 to 384) are
> for functional and timing studies only; they do not reach 128-bit security.

## Table of contents

1. [Description](#description)
2. [Dataset information](#dataset-information)
3. [Code information](#code-information)
4. [Requirements](#requirements)
5. [Usage instructions](#usage-instructions)
6. [Methodology](#methodology)
7. [Reproducibility notes](#reproducibility-notes)
8. [Citation](#citation)
9. [License and contribution guidelines](#license-and-contribution-guidelines)

## Description

Lattice-based attribute-based encryption (ABE) resists quantum attacks, but its decryption is too heavy
for phones, wearables, and vehicle units. LEAT (Lattice-based Edge-Attested Transformation) is a lattice
key-policy ABE (KP-ABE) scheme with an AND-clause encoding that moves the long computation to an
attested edge enclave:

* The attribute authority blinds the short decryption key `E` into a transformation key `TK = E·Z⁻¹`.
* The enclave (a trusted execution environment, TEE) holds `TK` and computes the long matrix product.
* The user unblinds with a 256×256 multiply-accumulate step and checks a commitment, so a malicious
  or faulty enclave is detected.
* Revocation is a signed epoch certificate that makes the enclave erase one key share; stored
  ciphertexts are not re-encrypted.

This repository contains the scheme, the emulated enclave, a core-SVP security estimator, unit tests,
and the scripts that generate every number in the paper's tables.

## Dataset information

There is no external dataset. All inputs are synthetic and generated at run time with fresh random keys,
attribute sets, and payloads. The outputs are the CSV files in `results/`:

| File | Content | Produced by |
|---|---|---|
| `params.csv`, `core_svp_q31.csv` | Parameter sets, noise bound, core-SVP bits (classical/quantum) | `run_analytic.py` |
| `projection.csv` | Projection to a 128-bit classical level (smallest correct modulus per n) | `run_analytic.py` |
| `sizes.csv`, `capacity.csv` | Ciphertext, key, and download sizes; enclave capacity | `run_analytic.py` |
| `revocation.csv` | Re-encryption vs. epoch-certificate revocation | `run_analytic.py` |
| `e2e.csv`, `pairing_model.csv` | End-to-end latency model; pairing-scheme cost model | `run_analytic.py` |
| `correctness.csv` | 60 trials per dimension: LEAT and local decryption, worst noise ratio to q/4, rejected negative tests | `run_correctness.py` |
| `timing_functional.csv`, `timing_scale.csv`, `timing_w.csv`, `timing_ell.csv` | Measured encryption, enclave kernel, and user-side times | `run_timing.py` |
| `protocol.csv` | Attested handshake and epoch-certificate timings | `run_protocol.py` |

Column names are in the first row of each file. Times are milliseconds unless the name says otherwise.
Timing files come from a reference run on a shared two-core cloud container with one thread; see
[Reproducibility notes](#reproducibility-notes).

## Code information

```
LEAT/
├── leat/
│   ├── params.py      Parameters (q = 2^31-1, k = 31, m = 2nk), noise bound T(w), size formulas,
│   │                  smallest modulus meeting the correctness bound
│   ├── estimator.py   Primal uSVP core-SVP estimator (calibrated on Frodo-640)
│   ├── modarith.py    Exact modular matrix arithmetic on int64 using 16-bit limb splitting
│   ├── scheme.py      Setup, key issuing, encryption, transformation, decryption, blinding
│   └── enclave.py     Emulated enclave: sealing, attestation quote, epoch certificates, user session
├── tests/test_leat.py Seven unit tests
├── experiments/       run_correctness.py, run_timing.py, run_protocol.py, run_analytic.py,
│                      run_all.sh, common.py
├── results/           CSV outputs and a README
├── requirements.txt
├── CITATION.cff
└── LICENSE
```

The unit tests check that blinding cancels, that decryption is correct within the noise bound, that a
missing attribute is rejected, that a tampered enclave result is detected, that revocation and rollback
behave correctly, that stale or forged epoch certificates are refused, and that the user download size
is as modeled.

## Requirements

* Python 3.10 or later (developed with 3.13)
* `numpy` (tested with 2.5.3)
* `cryptography` (tested with 50.0.1), used for X25519, HKDF, Ed25519, HMAC, and AES-GCM

Install:

```bash
git clone [Shared Later]
cd LEAT
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage instructions

1. **Run the tests** (about 20 seconds):

   ```bash
   python3 -m unittest discover -s tests -v
   ```

2. **Regenerate all results** (about 10 to 20 minutes on a laptop-class CPU). The CSVs in `results/` are
   overwritten:

   ```bash
   bash experiments/run_all.sh
   ```

   Or run one script at a time, from the repository root:

   ```bash
   python3 experiments/run_correctness.py   # correctness.csv
   python3 experiments/run_timing.py        # timing_*.csv
   python3 experiments/run_protocol.py      # protocol.csv
   python3 experiments/run_analytic.py      # params, sizes, projection, revocation, e2e, ...
   ```

3. **Use the library directly:**

   ```python
   import sys; sys.path.insert(0, ".")
   from leat.params import Params, smallest_modulus_bits
   from leat.estimator import beta_primal, core_svp_bits

   p = Params(n=64)
   print(p.m, p.noise_bound(w=4), p.correct(4))     # dimension, noise bound, correctness check

   p256 = Params(n=256)
   beta = beta_primal(256, p256.q, p256.sigma0)
   print(core_svp_bits(beta))                        # (classical bits, quantum bits)
   ```

   See `tests/test_leat.py` for a complete encrypt, transform, and decrypt flow with the emulated enclave.

## Methodology

1. **Parameters.** `q = 2^31 - 1`, `k = 31`, `m = 2nk`, `σ0 = 3.2`, `σ_E = 4√(nk)`, tail factor `τ = 8`,
   `K = 256`, `ℓ = 16` attributes. Correctness requires `q/4 > T(w) + 1` with
   `T(w) = τσ0σ_E√(2m(1+w)) + τσ0`.
2. **Key generation.** The prototype samples the short key `E` first and derives the public matrix from
   it (key-first shortcut). It is a functional stand-in and carries no security claim.
3. **Blinding.** A random invertible `Z` gives `TK = E·Z⁻¹`; `Z` stays with the user.
4. **Encryption.** A random 256-bit key material is encoded in the LWE ciphertext; the payload is
   protected with AES-GCM under a key derived by HKDF, binding the ciphertext identifier and attributes.
5. **Transformation.** The enclave computes the long product with `TK` using exact int64 arithmetic
   (16-bit limb splitting, row chunking). Enclave time is modeled as `1.15 × kernel + 8000 cycles` at 2.1 GHz.
6. **User step.** The user multiplies by `Z` (256² multiply-accumulates), rounds, derives the key, and
   verifies the commitment; a bad result is rejected.
7. **Revocation.** The authority signs an epoch certificate (Ed25519); the enclave verifies it,
   updates state, and erases the revoked share.
8. **Security estimate.** Primal uSVP attack, core-SVP model (0.292β classical, 0.265β quantum bits per
   block size β, floored at 40). The estimator reproduces the Frodo-640 reference (β ≈ 483).
9. **Evaluation.** Correctness (60 trials per dimension plus negative tests), timing medians over
   repeated runs, and analytic size, capacity, projection, and revocation models.

## Reproducibility notes

* Timings depend on the machine. `results/timing_*.csv` and `results/protocol.csv` are a reference run;
  regenerate them on your own hardware before quoting them.
* Analytic outputs (sizes, core-SVP bits, projections, revocation and end-to-end models) are deterministic.
* Correctness runs use random keys and attribute sets, so the worst-noise column varies slightly by seed;
  all trials must still pass.
* Archived release: Zenodo **[Shared Later]**.

## Citation

If you use this code, please cite the paper (see also `CITATION.cff`):

```bibtex
@article{riad2026leat,
  author  = {Riad, Khaled},
  title   = {{LEAT}: Lattice-Based Edge-Attested Transformation for Attribute-Based Encryption},
  year    = {2026},
  note    = {Manuscript under review. Code: [Shared Later]. Zenodo: [Shared Later]}
}
```

## License and contribution guidelines

Released under the MIT License (see `LICENSE`). Issues and pull requests are welcome. Please keep
changes small, add or update a test in `tests/` for any behavior change, and make sure
`python3 -m unittest discover -s tests` passes before submitting. Do not use this prototype to protect
real data.
