"""Deterministic tables: parameters, sizes, projection, capacity, revocation and
latency models.  Measured inputs (encryption time, kernel times) are read from
results/timing_*.csv, so run run_timing.py first for the model-based tables.
"""
import os
import sys
from math import log2

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from common import read_csv, write_csv  # noqa: E402
from leat import Params  # noqa: E402
from leat.estimator import beta_primal, core_svp_bits  # noqa: E402
from leat.params import smallest_modulus_bits  # noqa: E402

KiB, MiB = 1024, 2**20
W_EVAL = 4          # clause size used in the evaluation tables and the projection

# ---- Table: parameter sets -------------------------------------------------------
rows = []
for n in (64, 128, 256, 384):
    p = Params(n=n)
    b = beta_primal(n, p.q, p.sigma0)
    cl, qu = core_svp_bits(b)
    rows.append([n, p.m, round(p.sigma_E), b, round(cl, 1), round(qu, 1),
                 round(log2(p.noise_bound(8)), 1),
                 round(p.noise_bound(8) / (p.q / 4), 4)])
write_csv("params.csv", ["n", "m", "sigma_E", "beta", "core_svp_classical",
                         "core_svp_quantum", "log2_T_w8", "T_w8_over_q4"], rows)

# ---- Table: core-SVP at q = 2^31-1 for the larger dimensions ---------------------
rows = []
for n in (256, 384, 512, 768, 1024, 1088, 1344):
    b = beta_primal(n, 2**31 - 1, 3.2)
    rows.append([n, b, round(core_svp_bits(b)[0], 1)])
write_csv("core_svp_q31.csv", ["n", "beta", "core_svp_classical"], rows)

# ---- Table: storage and communication sizes (w = 4, ell = 16) ----------------------
rows = []
for n in (64, 128, 256, 384):
    p = Params(n=n)
    rows.append([n, round(p.ct_bytes() / KiB), round(p.local_download_bytes(W_EVAL) / KiB),
                 round(Params.leat_download_bytes() / KiB, 2), round(p.e_bytes() / MiB, 1),
                 round(p.tk_bytes() / MiB, 2), round(p.z_bytes() / KiB)])
write_csv("sizes.csv", ["n", "ciphertext_KiB", "local_download_KiB", "leat_download_KiB",
                        "E_MiB", "TK_MiB", "Z_KiB"], rows)

# ---- Table: 128-bit projection (smallest modulus meeting Lemma 2 for w = 4) ---------
rows = []
for n in (256, 512, 768, 1024, 1088, 1152):
    k = smallest_modulus_bits(n, W_EVAL)
    p = Params(n=n, q=2**k - 1)
    cl = core_svp_bits(beta_primal(n, p.q, p.sigma0))[0]
    rows.append([n, k, p.m, round(cl, 1), round(p.ct_bytes() / MiB, 2),
                 round(p.tk_bytes(packed=True) / MiB, 1), round(p.z_bytes(packed=True) / KiB, 1),
                 round(2 * p.m * p.K / 1e6, 1), round(p.K ** 2 / 1e6, 3)])
write_csv("projection.csv", ["n", "log2_q", "m", "core_svp_classical", "ciphertext_MiB",
                             "TK_MiB", "Z_KiB", "edge_MMAC", "user_MMAC"], rows)

# ---- Tables that depend on measured timings ------------------------------------------
try:
    func = read_csv("timing_functional.csv")
    scale = read_csv("timing_scale.csv")
except FileNotFoundError:
    sys.exit("run run_timing.py first for the model-based tables")
f = {int(r["n"]): r for r in func}
s = {int(r["n"]): r for r in scale}

# capacity: 93 MiB of protected memory
rows = []
for n in (64, 128, 256, 384):
    tk = Params(n=n).tk_bytes() / MiB
    t_res = float(f[n]["edge_enclave_model_ms"])
    t_uns = t_res + float(f[n]["unseal_ms"])
    rows.append([n, round(tk, 2), int(93 // tk), round(1e3 / t_res, 1), round(1e3 / t_uns, 1)])
write_csv("capacity.csv", ["n", "TK_MiB", "shares_resident_in_93MiB", "req_per_s_resident",
                           "req_per_s_unseal"], rows)

# revocation: re-encryption is modelled with the measured encryption time at n = 64
enc64_ms = float(f[64]["enc_ms"])
proto = {r["step"]: float(r["time_ms"]) for r in read_csv("protocol.csv")} \
    if os.path.exists(os.path.join(os.path.dirname(__file__), "..", "results", "protocol.csv")) else {}
epoch_ms = next((v for k_, v in proto.items() if k_.startswith("Epoch certificate")), float("nan"))
rows = [[N, round(enc64_ms * N / 1e3, 2), epoch_ms] for N in (10, 100, 1000, 10000, 100000)]
write_csv("revocation.csv", ["N_stored", "reencryption_s_model", "leat_epoch_update_ms"], rows)

# end-to-end latency: 20 ms round trip, w = 4
RTT = 20.0
rows = []
for n, edge, user_leat, user_local in (
        (64, float(f[64]["edge_enclave_model_ms"]), float(f[64]["user_leat_ms"]),
         float(f[64]["user_local_ms"])),
        (1024, float(s[1024]["edge_enclave_model_ms"]), float(s[1024]["user_leat_ms"]),
         float(s[1024]["user_local_ms"]))):
    p = Params(n=n)
    for mbit in (1, 5, 20, 100):
        leat = RTT + edge + user_leat + Params.leat_download_bytes() * 8 / (mbit * 1e3)
        loc = RTT + p.local_download_bytes(W_EVAL) * 8 / (mbit * 1e3) + user_local
        rows.append([n, mbit, round(leat, 1), round(loc, 1), round(loc / leat, 2)])
write_csv("e2e.csv", ["n", "Mbit_per_s", "leat_ms", "local_ms", "local_over_leat"], rows)

# pairing-based models (assumed unit costs, not measurements)
PAIR, GT = 1.50, 0.50
rows = [[w, (2 * w + 1) * PAIR + w * GT, 3 * GT, GT] for w in (2, 4, 8, 16, 32)]
write_csv("pairing_model.csv", ["w", "BSW07_ms", "Lai_ms", "GHW11_ms"], rows)
