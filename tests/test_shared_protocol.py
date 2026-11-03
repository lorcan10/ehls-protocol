"""
tests/test_shared_protocol.py
Tests for shared/protocol.py
"""

import base64
import json
import pytest
from shared.models import PacketType, ProtocolPacket, EncryptedSegment
from shared.protocol import (
    build_packet,
    serialize_packet,
    deserialize_packet,
    serialize_segment,
    deserialize_segment,
)


class TestBuildPacket:
    def test_build_sets_packet_type(self):
        pkt = build_packet(PacketType.ENROLL_REQUEST)
        assert pkt.packet_type == PacketType.ENROLL_REQUEST

    def test_build_sets_session_id(self):
        pkt = build_packet(PacketType.HEARTBEAT, session_id="sess-123")
        assert pkt.session_id == "sess-123"

    def test_build_sets_machine_id(self):
        pkt = build_packet(PacketType.HANDSHAKE_REQUEST, machine_id="mach-abc")
        assert pkt.machine_id == "mach-abc"

    def test_build_puts_kwargs_in_payload(self):
        pkt = build_packet(PacketType.ENROLL_REQUEST, foo="bar", count=42)
        assert pkt.payload["foo"] == "bar"
        assert pkt.payload["count"] == 42

    def test_build_with_string_packet_type(self):
        pkt = build_packet("enroll_request")
        assert pkt.packet_type == PacketType.ENROLL_REQUEST

    def test_build_default_session_id_is_none(self):
        pkt = build_packet(PacketType.ENROLL_REQUEST)
        assert pkt.session_id is None


class TestPacketSerialization:
    def test_serialize_returns_bytes(self):
        pkt = build_packet(PacketType.HEARTBEAT, session_id="s1")
        raw = serialize_packet(pkt)
        assert isinstance(raw, bytes)

    def test_serialize_is_valid_json(self):
        pkt = build_packet(PacketType.HEARTBEAT, session_id="s1")
        raw = serialize_packet(pkt)
        data = json.loads(raw)
        assert data["packet_type"] == "heartbeat"

    def test_deserialize_roundtrip(self):
        pkt = build_packet(
            PacketType.JOB_START_REQUEST,
            session_id="sess-999",
            job_file="model.stl",
            profile_name="default",
        )
        raw = serialize_packet(pkt)
        restored = deserialize_packet(raw)
        assert restored.packet_type == PacketType.JOB_START_REQUEST
        assert restored.session_id == "sess-999"
        assert restored.payload["job_file"] == "model.stl"
        assert restored.payload["profile_name"] == "default"

    def test_deserialize_invalid_json_raises(self):
        with pytest.raises(Exception):
            deserialize_packet(b"not json")

    def test_deserialize_missing_packet_type_raises(self):
        with pytest.raises(Exception):
            deserialize_packet(b'{"session_id": "x"}')

    def test_all_packet_types_survive_roundtrip(self):
        for pt in PacketType:
            pkt = build_packet(pt)
            raw = serialize_packet(pkt)
            restored = deserialize_packet(raw)
            assert restored.packet_type == pt


class TestSegmentSerialization:
    @pytest.fixture
    def sample_segment(self, session_key):
        from shared.crypto import encrypt_segment
        plaintext = b"G1 X10 Y10 E1.0\nG1 X20 Y20 E2.0\n"
        ciphertext, iv, checksum = encrypt_segment(plaintext, session_key)
        return EncryptedSegment(
            segment_index=0,
            layer_start=0,
            layer_end=2,
            ciphertext=ciphertext,
            iv=iv,
            checksum=checksum,
            total_segments=5,
        )

    def test_serialize_segment_returns_bytes(self, sample_segment):
        raw = serialize_segment(sample_segment)
        assert isinstance(raw, bytes)

    def test_serialize_segment_base64_encodes_binary(self, sample_segment):
        raw = serialize_segment(sample_segment)
        data = json.loads(raw)
        # ciphertext and iv should be base64 strings, not raw bytes
        assert isinstance(data["ciphertext"], str)
        assert isinstance(data["iv"], str)
        # Should be valid base64
        base64.b64decode(data["ciphertext"])
        base64.b64decode(data["iv"])

    def test_deserialize_segment_roundtrip(self, sample_segment, session_key):
        from shared.crypto import decrypt_segment
        raw = serialize_segment(sample_segment)
        restored = deserialize_segment(raw)
        assert restored.segment_index == sample_segment.segment_index
        assert restored.total_segments == sample_segment.total_segments
        assert restored.ciphertext == sample_segment.ciphertext
        assert restored.iv == sample_segment.iv
        assert restored.checksum == sample_segment.checksum

    def test_deserialized_segment_decryptable(self, sample_segment, session_key):
        from shared.crypto import decrypt_segment
        raw = serialize_segment(sample_segment)
        restored = deserialize_segment(raw)
        plaintext = decrypt_segment(
            restored.ciphertext, restored.iv, session_key, restored.checksum
        )
        assert b"G1 X10 Y10" in plaintext

    def test_serialize_segment_has_segment_index_key(self, sample_segment):
        raw = serialize_segment(sample_segment)
        data = json.loads(raw)
        assert "segment_index" in data
