"""Receiver-boundary tests: authorization, ordering, integrity and cleanup."""
import json
import pytest
from examples.local_stream import DemoReceiver, delivery
from shared.protocol import deserialize_packet, serialize_packet, sign_packet, verify_packet

KEY = b"k" * 32


def test_ack_is_signed_after_managed_buffer_release(monkeypatch):
    from shared.secure_memory import SecureBuffer
    releases = []
    original = SecureBuffer.release

    def release(self):
        original(self)
        if self._released:
            assert bytes(self._buf) == bytes(self.size)
            releases.append(True)

    monkeypatch.setattr(SecureBuffer, "release", release)
    receiver = DemoReceiver("session", KEY, lock_memory=False)
    ack = deserialize_packet(receiver.receive(delivery("session", 0, KEY, b"; demo\n", 2)))
    assert releases
    assert verify_packet(ack, KEY)
    assert ack.payload == {"segment_index": 0, "simulated": True}
    assert receiver.expected_index == 1


def test_duplicate_rejected_without_advancing_state():
    receiver = DemoReceiver("session", KEY, lock_memory=False)
    wire = delivery("session", 0, KEY, b"; demo\n", 2)
    receiver.receive(wire)
    with pytest.raises(ValueError, match="index"):
        receiver.receive(wire)
    assert receiver.expected_index == 1


@pytest.mark.parametrize("session,index,key", [
    ("other-session", 0, KEY), ("session", 1, KEY), ("session", 0, b"z" * 32),
])
def test_session_order_or_signature_mismatch_rejected(session, index, key):
    receiver = DemoReceiver("session", KEY, lock_memory=False)
    with pytest.raises(ValueError):
        receiver.receive(delivery(session, index, key, b"; demo\n", 2))
    assert receiver.expected_index == 0


def test_ciphertext_tampering_rejected_even_with_valid_envelope_signature():
    receiver = DemoReceiver("session", KEY, lock_memory=False)
    packet = deserialize_packet(delivery("session", 0, KEY, b"; demo\n", 2))
    segment = packet.payload["segment"]
    segment["checksum"] = "0" * 64
    with pytest.raises(ValueError, match="Integrity"):
        receiver.receive(serialize_packet(sign_packet(packet, KEY)))
    assert receiver.expected_index == 0


def test_executor_failure_wipes_buffer_and_does_not_ack(monkeypatch):
    from shared.secure_memory import SecureBuffer
    observed = []
    original = SecureBuffer.release

    def release(self):
        original(self)
        observed.append(bytes(self._buf))

    monkeypatch.setattr(SecureBuffer, "release", release)
    receiver = DemoReceiver("session", KEY, lock_memory=False)
    with pytest.raises(ValueError, match="executor"):
        receiver.receive(delivery("session", 0, KEY, b"unexpected", 1))
    assert observed and all(data == bytes(len(data)) for data in observed)
    assert receiver.expected_index == 0
