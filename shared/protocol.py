"""
shared/protocol.py
Serialization helpers for the EHLS wire protocol (JSON + binary segments).

Packet signing
──────────────
Every post-handshake packet is signed with HMAC-SHA256 using the session key
(derived independently on both sides from the MIP hash + nonce + timestamp —
see :func:`shared.crypto.derive_session_key`).  The signature is placed in
``ProtocolPacket.signature`` and covers the canonical JSON of every other
field, sorted and UTF-8 encoded.

Signing a packet that already has a ``signature`` field overwrites it; the
existing value is ignored by the canonicaliser.  Verification is constant-time
via :func:`hmac.compare_digest`.

Signatures authenticate packets to a holder of the session key. They do not
by themselves enforce freshness, ordering, or endpoint identity. Receivers must
track session state and sequence numbers. The identity-derived key mode is not
secret if all its derivation inputs are known; an authenticated transport is
required for handshake data and the X25519 public-key exchange.
"""

from __future__ import annotations
import base64
import hmac
import json
from typing import Any

from .crypto import compute_keyed_checksum, verify_keyed_checksum
from .models import ProtocolPacket, EncryptedSegment


__all__ = [
    "build_packet",
    "deserialize_packet",
    "deserialize_segment",
    "serialize_packet",
    "serialize_segment",
    "sign_packet",
    "verify_packet",
]


# ── Canonical form for signing ────────────────────────────────────────────────

def _canonical_bytes(packet: ProtocolPacket) -> bytes:
    """
    Return the canonical UTF-8 JSON form of *packet* used as HMAC input.
    The signature field is always omitted from the canonical form so that
    the same bytes produce the same tag regardless of prior signing state.
    """
    data = packet.model_dump(mode="json", exclude={"signature"})
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_packet(packet: ProtocolPacket, session_key: bytes) -> ProtocolPacket:
    """
    Compute HMAC-SHA256 over the canonical packet form and store it in
    ``packet.signature``.  Returns the same packet for call-chain convenience.
    """
    if not session_key:
        raise ValueError("sign_packet: session_key must not be empty")
    tag = compute_keyed_checksum(session_key, _canonical_bytes(packet))
    packet.signature = tag
    return packet


def verify_packet(packet: ProtocolPacket, session_key: bytes) -> bool:
    """
    Return ``True`` iff *packet.signature* is a valid HMAC-SHA256 tag
    produced by :func:`sign_packet` with the same *session_key*.

    Missing or empty signature → ``False``.
    """
    if not session_key:
        return False
    if not packet.signature:
        return False
    return verify_keyed_checksum(
        session_key, _canonical_bytes(packet), packet.signature
    )


# ── Packet serialisation ──────────────────────────────────────────────────────

def serialize_packet(packet: ProtocolPacket) -> bytes:
    """Serialize a ProtocolPacket to UTF-8 JSON bytes."""
    return packet.model_dump_json().encode("utf-8")


def deserialize_packet(raw: bytes) -> ProtocolPacket:
    return ProtocolPacket.model_validate_json(raw)


def serialize_segment(seg: EncryptedSegment) -> bytes:
    """
    Segments contain raw bytes fields; we base64-encode them for JSON transport.
    """
    d = seg.model_dump()
    d["ciphertext"] = base64.b64encode(d["ciphertext"]).decode()
    d["iv"] = base64.b64encode(d["iv"]).decode()
    return json.dumps(d).encode("utf-8")


def deserialize_segment(raw: bytes) -> EncryptedSegment:
    d = json.loads(raw)
    d["ciphertext"] = base64.b64decode(d["ciphertext"])
    d["iv"] = base64.b64decode(d["iv"])
    return EncryptedSegment(**d)


def build_packet(
    ptype: str,
    session_id: str | None = None,
    machine_id: str | None = None,
    **payload: Any,
) -> ProtocolPacket:
    from .models import PacketType
    return ProtocolPacket(
        packet_type=PacketType(ptype),
        session_id=session_id,
        machine_id=machine_id,
        payload=payload,
    )