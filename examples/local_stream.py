"""Local, in-process protocol demonstration; never connects to hardware."""
from __future__ import annotations

import argparse
import json
import uuid

from shared.crypto import (
    compute_bip_hash, compute_mip_hash, decrypt_segment, derive_session_key_ecdh,
    encrypt_segment, generate_ephemeral_keypair, generate_nonce, segment_aad,
)
from shared.identity_artefacts import canonical_mip_bytes
from shared.models import BehaviouralBaseline, EncryptedSegment, MachineIdentityProfile, PacketType
from shared.protocol import (
    build_packet, deserialize_packet, deserialize_segment, serialize_packet,
    serialize_segment, sign_packet, verify_packet,
)
from shared.secure_memory import SecureBuffer


class DemoReceiver:
    """Illustrates caller-owned ordering and wipe-before-ACK discipline.

    The simulated executor checks bytes only; it does not prove physical execution.
    Authentication of the handshake is supplied by the caller in a deployment.
    """
    def __init__(self, session_id: str, key: bytes, *, lock_memory: bool = True):
        self.session_id = session_id
        self.key = key
        self.expected_index = 0
        self.lock_memory = lock_memory

    def receive(self, raw: bytes) -> bytes:
        packet = deserialize_packet(raw)
        if not verify_packet(packet, self.key):
            raise ValueError("Invalid packet signature")
        if packet.session_id != self.session_id or packet.packet_type != PacketType.SEGMENT_DELIVERY:
            raise ValueError("Unexpected session or packet type")
        segment = deserialize_segment(json.dumps(packet.payload["segment"]).encode())
        if segment.segment_index != self.expected_index:
            raise ValueError("Unexpected segment index (duplicate or out of order)")
        # AES-GCM ciphertext includes a 16-byte authentication tag.
        with SecureBuffer(max(1, len(segment.ciphertext) - 16), use_mlock=self.lock_memory) as buffer:
            plaintext = decrypt_segment(
                segment.ciphertext, segment.iv, self.key, segment.checksum,
                aad=segment_aad(self.session_id, self.expected_index),
            )
            try:
                buffer.write(plaintext)
                if not buffer.read().startswith(b"; demo"):
                    raise ValueError("Simulated executor rejected the segment")
            finally:
                # Dropping this reference cannot guarantee erasure of Python bytes.
                del plaintext
        # The context has wiped and released the managed buffer before this ACK.
        self.expected_index += 1
        ack = build_packet(PacketType.SEGMENT_ACK, session_id=self.session_id,
                           segment_index=segment.segment_index, simulated=True)
        return serialize_packet(sign_packet(ack, self.key))


def delivery(session_id: str, index: int, key: bytes, plaintext: bytes, total: int) -> bytes:
    ciphertext, iv, checksum = encrypt_segment(plaintext, key, aad=segment_aad(session_id, index))
    segment = EncryptedSegment(segment_index=index, layer_start=index, layer_end=index,
                               ciphertext=ciphertext, iv=iv, checksum=checksum, total_segments=total)
    packet = build_packet(PacketType.SEGMENT_DELIVERY, session_id=session_id,
                          segment=json.loads(serialize_segment(segment)))
    return serialize_packet(sign_packet(packet, key))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-memory-lock", action="store_true",
                        help="Run a development simulation with unlocked buffers")
    args = parser.parse_args()
    mip = MachineIdentityProfile(cpu_id="demo-machine", firmware_version="demo-1", board_serial="demo-board")
    baseline = BehaviouralBaseline(enrolment_challenge_id="synthetic", ramp_rate_c_per_s=1,
        overshoot_c=0, steady_state_avg_c=40, final_x=0, final_y=0, final_z=0, motion_duration_s=1)
    mip_hash = compute_mip_hash(canonical_mip_bytes(mip))
    bip_hash = compute_bip_hash(baseline.model_dump_json().encode())
    server_private, server_public = generate_ephemeral_keypair()
    gateway_private, gateway_public = generate_ephemeral_keypair()
    nonce = generate_nonce(32)
    server_key = derive_session_key_ecdh(server_private, gateway_public, mip_hash, bip_hash, nonce)
    gateway_key = derive_session_key_ecdh(gateway_private, server_public, mip_hash, bip_hash, nonce)
    if server_key != gateway_key:
        raise RuntimeError("Session key agreement failed")
    del server_private, gateway_private
    session_id = str(uuid.uuid4())
    receiver = DemoReceiver(session_id, gateway_key, lock_memory=not args.no_memory_lock)
    print("EHLS local simulation: synthetic identity; no network or printer connection")
    print("X25519 + HKDF session keys agree")
    if args.no_memory_lock:
        print("Development mode: memory locking disabled")
    for index in range(3):
        plaintext = f"; demo segment {index}\nG1 X{index} Y{index}\n".encode()
        wire = delivery(session_id, index, server_key, plaintext, total=3)
        del plaintext
        ack = deserialize_packet(receiver.receive(wire))
        if (not verify_packet(ack, server_key) or ack.session_id != session_id
                or ack.packet_type != PacketType.SEGMENT_ACK
                or ack.payload.get("segment_index") != index):
            raise RuntimeError("Invalid segment acknowledgement")
        print(f"Segment {index}: authenticated, decrypted, simulated execution, managed buffer wiped, ACK verified")
    try:
        receiver.receive(wire)
    except ValueError as exc:
        print(f"Duplicate rejected: {exc}")
    else:
        raise RuntimeError("Replay was accepted")
    del server_key, gateway_key, receiver
    print("Simulation complete; Python key-reference deletion is not verified secure erasure")


if __name__ == "__main__":
    main()
