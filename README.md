# pq-obfs: Kemeleon reference (Python)

Standalone Python research prototype accompanying the paper *"Cryptographic
Fingerprints in Tor Pluggable Transports: A Vulnerability Analysis and
Post-Quantum Defense Framework"* (AlOmar & Trabelsi, 2026). It validates the
**statistical** claims of the paper: the ML-KEM byte-distribution fingerprint,
its detection, and its removal by Kemeleon encoding.

The **authoritative wire-format implementation is the Go/lyrebird repo**
(`pqobfs-lyrebird`); this Python layer uses a simplified wire model and is not
byte-for-byte identical to the deployed transport (see *Scope* below).

## Reproducing the paper's results

    pip install -r requirements.txt
    pytest tests/ -v        # 34 tests
    python evaluate.py      # prints the result tables

Verified output (kyber-py real ML-KEM backend):
- **Rejection rates (pk):** ML-KEM-512/768/1024 = 0.56 / 0.82 / 0.62 (paper Table III).
- **MSB detection:** raw ML-KEM-768 pk → ~100% flagged; Kemeleon-encoded → 0%; obfs4 baseline → ~random.
- **Classifier evasion:** Kemeleon-encoded → 100% pass as random; raw ML-KEM → 0%.

These reproduce the paper's core finding: the bit-level MSB signal is present in
raw keys and removed by Kemeleon.

## Why the fingerprint exists

ML-KEM coefficients live in Z_q with q = 3329 < 4096 = 2¹². Each coefficient is
packed in 12 bits, so the most-significant bit of each 12-bit group is 0 unless
the coefficient is ≥ 2048, which happens with probability ≈ 0.385 rather than
0.5. That ~38.5% vs 50% asymmetry is the lattice signature. Kemeleon accumulates
the coefficients into one integer, rejects when the top bits are set, and emits
the remainder, which is uniform under module-LWE.

## Scope and known deviations from the Go path

This is a research prototype, not a production obfs4proxy replacement:
- **Wire model is simplified.** The Python layer normalizes to L_cover = 4096
  and reports segment profiles under that model; the deployed Go transport adds
  a trailing 16-byte MAC (4096 + 16 = 4112 on the wire), giving the paper's
  authoritative profile (1460, 1460, 1192). The Go repo is authoritative for all
  exact wire/segment numbers.
- **Ciphertext encoding** in this clean big-integer construction differs from
  the paper's compressed-polynomial handling, so encoded-ciphertext sizes and
  ct-rejection rates differ slightly; the **public-key** sizes and rates match
  the paper.
- No real TLS/Tor/obfs4proxy integration; handshakes run in-process.
- Elligator 2 is modelled as 32 uniform random bytes (the only property the
  byte-distribution classifier depends on).
- Written in Python for clarity, not performance-representative.

## Module map

| File | Role |
|---|---|
| `pqobfs/mlkem.py` | ML-KEM interface over kyber-py |
| `pqobfs/kemeleon.py` | Kemeleon encode/decode with rejection |
| `pqobfs/classifier.py` | popcount + 12-bit-MSB detector (Surface 1) |
| `pqobfs/padding.py` | L_cover normalization and TCP segmentation |
| `pqobfs/wire.py` | pq-obfs KEM handshake |
| `pqobfs/obfs4_baseline.py` | X25519/Elligator-2 baseline for comparison |
