"""pq-obfs research prototype.

Implements and empirically validates the two post-quantum defenses from
"Cryptographic Fingerprints in Tor Pluggable Transports":
  1. ML-Kemeleon encoding (byte-distribution fingerprint defense)
  2. Handshake padding normalization (size fingerprint defense)
"""

__version__ = "0.1.0"
