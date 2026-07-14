"""Deterministic packet hashing — a stand-in for real Sigstore signing.

The real Build Machine signs packets with Sigstore (Cosign/Rekor). Here we
demonstrate the property that matters for that step: packet *integrity*. We
compute a SHA-256 over a canonical (sorted-key) JSON encoding of the packet, so
the same packet always hashes to the same value and any change to any field
changes the hash. Verification recomputes the hash and compares.
"""

from __future__ import annotations

import hashlib
import json

HASH_FIELD = "packet_hash"


def canonical_json(packet):
    """Serialise a packet deterministically: sorted keys, compact separators."""
    return json.dumps(packet, sort_keys=True, separators=(",", ":"))


def compute_hash(packet):
    """Return the SHA-256 hex digest of the packet's canonical JSON.

    The ``packet_hash`` field itself is excluded from the digest so that
    signing and verifying operate over the exact same payload.
    """
    payload = {key: value for key, value in packet.items() if key != HASH_FIELD}
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def sign(packet):
    """Return a copy of ``packet`` with a ``packet_hash`` field added."""
    signed = dict(packet)
    signed[HASH_FIELD] = compute_hash(packet)
    return signed


def verify(signed_packet):
    """Recompute the hash of a signed packet and compare it to the embedded one.

    Returns
    -------
    tuple(bool, str, str)
        ``(is_valid, claimed_hash, recomputed_hash)``.
    """
    claimed = signed_packet.get(HASH_FIELD)
    recomputed = compute_hash(signed_packet)
    return claimed == recomputed, claimed, recomputed
