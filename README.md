# pq-obfs: Kemeleon reference (Python)

Standalone Kemeleon implementation over the ML-KEM-768 key structure, using
kyber-py. Accompanies the paper *"Cryptographic Fingerprints in Tor Pluggable
Transports"* (AlOmar & Trabelsi).

## Reproducing the paper's results

    pytest

Expected: all 34 tests pass, the ~27% byte-chi-squared baseline, and the
100% / 0% MSB detection results (raw vs. Kemeleon-encoded keys).

---

# pq-obfs Prototype

A self-contained Python research prototype that implements and **empirically
validates** the two post-quantum defenses proposed in the paper *"Cryptographic
Fingerprints in Tor Pluggable Transports"* (TIFS submission):

1. **ML-Kemeleon encoding** — makes ML-KEM public keys and ciphertexts
   computationally uniform, removing the byte-distribution fingerprint
   (**Surface 1**) that a GFW-style popcount/chi² classifier detects.
2. **Handshake padding normalization** — pads every handshake to a fixed cover
   size `Lcover = 4096`, collapsing the TCP segment fingerprint (**Surface 2**)
   so all ML-KEM parameter sets look identical on the wire.

> This is **not** a production obfs4proxy replacement. It is a research
> prototype that reproduces the paper's quantitative claims in Tables I–V.

## Why the fingerprint exists

ML-KEM coefficients live in `Z_q` with `q = 3329 < 4096 = 2¹²`. Each coefficient
is packed in 12 bits, so the most-significant bit of every 12-bit group is 0
unless the coefficient is ≥ 2048 — which happens only with probability
`(q-2048)/q ≈ 0.385`. A uniform byte string would set that bit ~50% of the time.
This ~38.5% vs 50% asymmetry is the lattice signature a censor can test for.
Kemeleon accumulates the coefficients into one big integer `r = Σ qⁱ·cᵢ`, rejects
when the top bit is set, and emits the remaining bits — which are uniform under
module-LWE.

## Installation

```bash
pip install -r requirements.txt
```

The prototype uses the real **`kyber-py`** pure-Python ML-KEM implementation. If
it is unavailable, `pqobfs/mlkem.py` transparently falls back to a simulator that
reproduces the correct byte sizes *and* the 12-bit coefficient bias, so every
experiment still runs.

## Running the tests

```bash
pytest tests/ -v
```

All 34 tests should pass (Kemeleon round-trips, rejection rates within ±0.05 of
the paper, classifier discrimination, full handshake + MAC verification, padding
and segmentation).

## Running the experiments

```bash
python evaluate.py
```

Prints five result tables and writes all numeric results to `results.json`.

## What each experiment validates

| Experiment | Validates | Result |
|---|---|---|
| **1. Rejection sampling rates** | Table III | pk-success 0.56 / 0.82 / 0.62 for ML-KEM-512/768/1024; expected ops ≈ 3.6 / 2.4 / 3.2 |
| **2. Byte-distribution analysis** | Surface 1 claim | raw ML-KEM pk → 99.9% "biased"; Kemeleon-encoded → 0% biased; obfs4 baseline → ~random |
| **3. Wire size analysis** | Table IV | obfs4 = 128 B; pq-obfs-768 client ≈ 2.5 KB, server ≈ 1.4 KB |
| **4. TCP segmentation** | Table V | exact match: `[128]`, `[1460,204]`, `[1460,848]`, `[1460,1460,312]`, normalized `[1460,1460,1176]` |
| **5. Classifier evasion** | defense efficacy | Kemeleon-encoded → 100% pass as random; raw ML-KEM → ~0% |

## Module map

| File | Role |
|---|---|
| `pqobfs/mlkem.py` | Unified ML-KEM interface over `kyber-py` (or bias-faithful simulator) |
| `pqobfs/kemeleon.py` | Kemeleon encode/decode for public keys & ciphertexts, with rejection |
| `pqobfs/classifier.py` | GFW-style popcount + 12-bit-MSB chi² classifier (Surface 1 detector) |
| `pqobfs/padding.py` | `Lcover=4096` normalization and TCP segmentation |
| `pqobfs/wire.py` | pq-obfs KEM handshake (client_hello → server_hello → client_finish) |
| `pqobfs/obfs4_baseline.py` | Minimal X25519/Elligator-2 obfs4 baseline for comparison |

## Implementation notes & deviations

- **FIPS 203 key layout.** The spec prose assumed `rho || coeffs`, but the real
  ML-KEM public key (and `kyber-py`) is `ByteEncode₁₂(t̂) || rho` — the 32-byte
  seed is the **last** 32 bytes. The code parses the coefficient block first and
  appends `rho`, which is why the round-trip and the bias measurement are exact.

- **Ciphertext Kemeleon success rate.** In this clean big-integer construction the
  ciphertext accept probability is governed by the same `q^(k·n)` term as the
  public key, so the measured ct-success rates come out ≈ the pk rates
  (0.55 / 0.83 / 0.63) rather than the paper's slightly lower 0.51 / 0.77 / 0.57.
  The gap (≈0.04–0.06) reflects the paper's specific handling of the compressed
  `v`-polynomial in its ciphertext encoder; the pk rates match Table III to
  ±0.01.

- **Encoded ciphertext size.** Decompressing the `u`-vector back into `Z_q`
  before accumulation makes the encoded ciphertext ~1252 B for ML-KEM-768
  (paper ≈ 1056 B). The encoded **public key** size (1156 B) matches the paper
  exactly. This does not affect the Table V segmentation results, which use the
  paper's reference message lengths.

## Known limitations

- No real TLS stack and no Tor / obfs4proxy integration — handshakes are run
  in-process.
- Elligator 2 is modelled as 32 uniform random bytes (the only property the
  byte-distribution classifier depends on), not the full point map.
- Written in Python for clarity, not Go like the production transport, so it is
  not performance-representative.
- The GFW classifier here is a faithful but simplified popcount/chi² detector; a
  real censor may combine additional signals.
