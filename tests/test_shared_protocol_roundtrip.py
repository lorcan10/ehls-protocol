"""
tests/test_shared_protocol_roundtrip.py

Property-style round-trip tests for the cross-embodiment wire format.

The basic round-trip — every PacketType survives serialize → deserialize
— is already pinned in tests/test_shared_protocol.py.  This file is the
hardening layer: it pushes randomly-generated payloads, edge-case sizes,
and signed/verify cycles through the same code paths.  All three
embodiments (gateway agent, sealed interposer, on-device handler) speak
this format, so a regression here would fan out to every implementer.

Random inputs are seeded so failures are deterministically reproducible
(no hypothesis dep — keeps the test tier dep-free; the existing
parametrize-and-seeded-random pattern in tests/property/ is the model).

Properties pinned:

  1. Every PacketType round-trips with a non-trivial payload — keys,
     ints, floats, nested dicts, list-of-strings, unicode strings,
     None values — without field drift.

  2. sign_packet(...) → serialize → deserialize → verify_packet(...)
     is a closed cycle: the deserialized packet verifies under the
     same session key.

  3. EncryptedSegment round-trips at sizes spanning the realistic
     range (1 B to ~1 MB ciphertext).  base64 framing must not lose
     bytes at boundary sizes.

  4. Tampering with the on-the-wire JSON in specific ways either
     raises during deserialize or produces a packet whose signature
     fails to verify — never silently mutates payload.
"""

from __future__ import annotations

import base64
import json
import os
import random

import pytest

from shared.crypto import (
    compute_keyed_checksum,
    encrypt_segment,
)
from shared.kdf_constants import HKDF_INFO_SESSION_KEY
from shared.models import (
    EncryptedSegment,
    PacketType,
    ProtocolPacket,
)
from shared.protocol import (
    build_packet,
    deserialize_packet,
    deserialize_segment,
    serialize_packet,
    serialize_segment,
    sign_packet,
    verify_packet,
)


# ── Payload generation ───────────────────────────────────────────────


def _random_payload(rng: random.Random, depth: int = 0) -> dict:
    """Build a random JSON-safe payload dict.

    Mixes scalars, nested dicts, and lists.  Bounded depth keeps the
    generator finite; the shape is broad enough that any
    serialization shortcut that drops, reorders, or coerces fields
    will surface as a comparison mismatch.
    """
    n_keys = rng.randint(0, 6)
    out: dict[str, object] = {}
    for i in range(n_keys):
        key = f"k{i}_{rng.randint(0, 9999):04d}"
        choice = rng.choice([
            "int", "float", "bool", "none", "str",
            "unicode", "list", "nested", "empty",
        ])
        if choice == "int":
            out[key] = rng.randint(-(2 ** 32), 2 ** 32)
        elif choice == "float":
            out[key] = rng.uniform(-1e6, 1e6)
        elif choice == "bool":
            out[key] = rng.choice([True, False])
        elif choice == "none":
            out[key] = None
        elif choice == "str":
            out[key] = "".join(rng.choices("abcdefghij_-0123456789", k=rng.randint(0, 24)))
        elif choice == "unicode":
            out[key] = rng.choice(["café", "ümläut", "日本語", "🔧🖨️", "“quoted”"])
        elif choice == "list":
            out[key] = [rng.randint(0, 100) for _ in range(rng.randint(0, 5))]
        elif choice == "nested" and depth < 2:
            out[key] = _random_payload(rng, depth + 1)
        elif choice == "empty":
            out[key] = rng.choice([{}, [], "", 0])
        else:
            out[key] = 0
    return out


# ── Property 1: every PacketType survives a rich-payload round-trip ──


@pytest.mark.parametrize("seed", list(range(10)))
@pytest.mark.parametrize("ptype", list(PacketType))
def test_packet_roundtrip_with_random_payload(ptype: PacketType, seed: int):
    """For each PacketType × 10 seeded payloads, the deserialized
    packet matches the original on every field that should
    round-trip.  Catches a regression where (e.g.) the canonical
    JSON encoder drops None values or coerces unicode."""
    rng = random.Random(f"{ptype.value}-{seed}")
    payload = _random_payload(rng)
    pkt = build_packet(
        ptype,
        session_id=f"sess-{rng.randint(0, 1_000_000):06d}",
        machine_id=f"mach-{rng.randint(0, 1_000_000):06d}",
        **payload,
    )
    restored = deserialize_packet(serialize_packet(pkt))
    assert restored.packet_type == pkt.packet_type
    assert restored.session_id == pkt.session_id
    assert restored.machine_id == pkt.machine_id
    assert restored.payload == pkt.payload
    # Pydantic regenerates timestamp at default-factory time when not
    # serialised; serialize_packet emits the live timestamp, so this
    # MUST equal across the round-trip.
    assert restored.timestamp == pkt.timestamp


# ── Property 2: sign / serialize / deserialize / verify is closed ────


@pytest.mark.parametrize("seed", list(range(10)))
@pytest.mark.parametrize("ptype", list(PacketType))
def test_signed_packet_roundtrip_verifies(ptype: PacketType, seed: int):
    """The wire format is HMAC-signed (Claim 12B / shared/protocol.py).
    The closed cycle that an embodiment depends on is:

        sign(pkt, k) → serialize(pkt) → deserialize(...) → verify(pkt, k)

    If any link in that chain drops a signed-over field, mutates a
    timestamp, or normalises a string, verification fails and the
    embodiment loses authentication.  Pinning the closed cycle here
    catches that class of regression for every PacketType.
    """
    rng = random.Random(f"signed-{ptype.value}-{seed}")
    key = bytes(rng.randint(0, 255) for _ in range(32))
    pkt = build_packet(
        ptype,
        session_id=f"sess-{rng.randint(0, 1_000_000):06d}",
        machine_id=f"mach-{rng.randint(0, 1_000_000):06d}",
        **_random_payload(rng),
    )
    sign_packet(pkt, key)
    restored = deserialize_packet(serialize_packet(pkt))
    assert verify_packet(restored, key) is True

    # Wrong key must fail.
    other_key = bytes((b + 1) % 256 for b in key)
    assert verify_packet(restored, other_key) is False


def test_unsigned_packet_does_not_verify():
    """A packet with no signature must not accidentally verify under
    any key.  Belt-and-braces against a `None == ""` style bug."""
    pkt = build_packet(PacketType.HEARTBEAT, session_id="x")
    assert pkt.signature is None
    assert verify_packet(pkt, b"k" * 32) is False


# ── Property 3: EncryptedSegment round-trips across realistic sizes ──


@pytest.mark.parametrize(
    "plaintext_size",
    [
        0,         # empty plaintext is legal — slicer can emit a no-op segment
        1,         # one-byte boundary
        15,        # < AES block
        16,        # exactly one AES block
        17,        # one block + 1
        4096,      # typical filesystem page
        16_384,    # one segment for a few small layers
        262_144,   # 256 KiB — large layer
        1_048_576, # 1 MiB — pathological-large segment, exercises base64
    ],
)
def test_encrypted_segment_roundtrip(plaintext_size: int):
    plaintext = os.urandom(plaintext_size)
    key = b"k" * 32
    ciphertext, iv, checksum = encrypt_segment(plaintext, key)
    seg = EncryptedSegment(
        segment_index=plaintext_size % 17,
        layer_start=0,
        layer_end=1,
        ciphertext=ciphertext,
        iv=iv,
        checksum=checksum,
        total_segments=99,
    )
    raw = serialize_segment(seg)
    restored = deserialize_segment(raw)
    assert restored.ciphertext == seg.ciphertext
    assert restored.iv == seg.iv
    assert restored.checksum == seg.checksum
    assert restored.segment_index == seg.segment_index
    assert restored.layer_start == seg.layer_start
    assert restored.layer_end == seg.layer_end
    assert restored.total_segments == seg.total_segments


# ── Property 4: tampering surfaces, never silently mutates ───────────


class TestTamperedWireBytes:
    """Three classes of on-the-wire tamper must not produce a silently-
    accepted, payload-mutated packet."""

    def _signed_pkt(self) -> tuple[ProtocolPacket, bytes]:
        key = b"s" * 32
        pkt = build_packet(
            PacketType.SEGMENT_ACK,
            session_id="sess-tamper",
            segment_index=42,
        )
        sign_packet(pkt, key)
        return pkt, key

    def test_payload_byte_flip_fails_signature(self):
        pkt, key = self._signed_pkt()
        raw = serialize_packet(pkt)
        as_dict = json.loads(raw)
        as_dict["payload"]["segment_index"] = 999  # tamper
        tampered = json.dumps(as_dict).encode("utf-8")
        restored = deserialize_packet(tampered)
        # Deserialize succeeds — that's expected.  But verify_packet
        # must fail under the original key.
        assert verify_packet(restored, key) is False

    def test_signature_byte_flip_fails(self):
        pkt, key = self._signed_pkt()
        raw = serialize_packet(pkt)
        as_dict = json.loads(raw)
        sig: str = as_dict["signature"]
        flipped = ("0" if sig[0] != "0" else "1") + sig[1:]
        as_dict["signature"] = flipped
        tampered = json.dumps(as_dict).encode("utf-8")
        restored = deserialize_packet(tampered)
        assert verify_packet(restored, key) is False

    def test_truncated_signature_fails(self):
        pkt, key = self._signed_pkt()
        raw = serialize_packet(pkt)
        as_dict = json.loads(raw)
        as_dict["signature"] = as_dict["signature"][:-4]
        tampered = json.dumps(as_dict).encode("utf-8")
        restored = deserialize_packet(tampered)
        assert verify_packet(restored, key) is False

    def test_dropped_signature_field_fails(self):
        pkt, key = self._signed_pkt()
        raw = serialize_packet(pkt)
        as_dict = json.loads(raw)
        as_dict.pop("signature", None)
        tampered = json.dumps(as_dict).encode("utf-8")
        restored = deserialize_packet(tampered)
        assert restored.signature is None
        assert verify_packet(restored, key) is False

    def test_unknown_packet_type_rejected_at_deserialize(self):
        """An attacker who supplies a packet_type not in the enum
        must fail at deserialize, not survive into engine routing."""
        raw = json.dumps({
            "packet_type": "definitely_not_a_real_type",
            "payload": {},
            "timestamp": 1.0,
        }).encode("utf-8")
        with pytest.raises(Exception):
            deserialize_packet(raw)


# ── Sanity: the serializer is JSON, not pickle/repr ──────────────────


def test_wire_format_is_json():
    """Forward-compat invariant: third-party gateway implementers
    parse the wire bytes as JSON.  Pickle / repr / msgpack would
    break that contract.  A regression here would fan out to every
    embodiment author — pin it once at the format level."""
    pkt = build_packet(PacketType.ENROLL_REQUEST, mip={"cpu_id": "X"})
    raw = serialize_packet(pkt)
    parsed = json.loads(raw)
    assert isinstance(parsed, dict)
    assert parsed["packet_type"] == "enroll_request"


def test_segment_wire_format_is_json_with_b64():
    """Segment binary fields are base64 strings on the wire — not
    raw bytes embedded in a binary container.  Same forward-compat
    rationale as the packet test above."""
    plaintext = b"hello"
    key = b"k" * 32
    ciphertext, iv, checksum = encrypt_segment(plaintext, key)
    seg = EncryptedSegment(
        segment_index=0, layer_start=0, layer_end=1,
        ciphertext=ciphertext, iv=iv, checksum=checksum,
        total_segments=1,
    )
    raw = serialize_segment(seg)
    parsed = json.loads(raw)
    assert isinstance(parsed["ciphertext"], str)
    assert isinstance(parsed["iv"], str)
    base64.b64decode(parsed["ciphertext"])
    base64.b64decode(parsed["iv"])
