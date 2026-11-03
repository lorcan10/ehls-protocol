"""Bounded, in-memory simulation using the real EHLS cryptographic primitives."""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

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
from shared.secure_memory import SecureBuffer, SecureBufferLockError

TERMINAL = {"completed", "cancelled", "failed"}


class SimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    segment_count: int = Field(default=5, ge=1, le=100)
    interval_ms: int = Field(default=250, ge=10, le=5000)


class SessionView(BaseModel):
    session_id: str
    adapter: Literal["simulator"] = "simulator"
    status: Literal["queued", "streaming", "completed", "cancelled", "failed"] = "queued"
    total_segments: int
    completed_segments: int = 0
    progress: float = 0
    memory_lock_requested: bool
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    last_event: str = "Simulation queued"
    error: str | None = None


@dataclass
class _Session:
    view: SessionView
    cancel: asyncio.Event = field(default_factory=asyncio.Event)
    task: asyncio.Task | None = None


class SessionCapacityError(RuntimeError):
    pass


class SimulationManager:
    """Single-process session ownership. No instructions or keys in snapshots.

    Session records expire after an hour once terminal. At most 100 records and
    four active simulations are retained. There is no persistence or resumption.
    """
    def __init__(self, *, memory_lock: bool = True, max_sessions: int = 100,
                 max_active: int = 4, retention_seconds: float = 3600):
        self.memory_lock = memory_lock
        self.max_sessions = max_sessions
        self.max_active = max_active
        self.retention_seconds = retention_seconds
        self._sessions: dict[str, _Session] = {}

    def _prune(self):
        now = time.time()
        expired = [sid for sid, record in self._sessions.items()
                   if record.view.status in TERMINAL
                   and now - record.view.updated_at >= self.retention_seconds]
        for sid in expired:
            del self._sessions[sid]

    def create(self, request: SimulationRequest) -> SessionView:
        self._prune()
        active = sum(r.view.status not in TERMINAL for r in self._sessions.values())
        if active >= self.max_active:
            raise SessionCapacityError("Too many active simulations; wait for one to finish")
        if len(self._sessions) >= self.max_sessions:
            terminal = [(r.view.updated_at, sid) for sid, r in self._sessions.items()
                        if r.view.status in TERMINAL]
            if not terminal:
                raise SessionCapacityError("Session capacity reached")
            del self._sessions[min(terminal)[1]]
        view = SessionView(session_id=str(uuid.uuid4()), total_segments=request.segment_count,
                           memory_lock_requested=self.memory_lock)
        record = _Session(view=view)
        self._sessions[view.session_id] = record
        record.task = asyncio.create_task(self._run(record, request))
        return view.model_copy(deep=True)

    def get(self, session_id: str) -> SessionView:
        self._prune()
        return self._sessions[session_id].view.model_copy(deep=True)

    def cancel(self, session_id: str) -> SessionView:
        self._prune()
        record = self._sessions[session_id]
        if record.view.status not in TERMINAL:
            record.cancel.set()
            self._update(record, last_event="Cancellation requested; waiting for buffer cleanup")
        return record.view.model_copy(deep=True)

    def _update(self, record, **changes):
        for name, value in changes.items():
            setattr(record.view, name, value)
        record.view.updated_at = time.time()

    async def _run(self, record: _Session, request: SimulationRequest):
        try:
            # Synthetic enrollment: no physical identity or network handshake.
            mip = MachineIdentityProfile(cpu_id="ehls-simulator", firmware_version="sim-1")
            baseline = BehaviouralBaseline(enrolment_challenge_id="synthetic", ramp_rate_c_per_s=1,
                overshoot_c=0, steady_state_avg_c=40, final_x=0, final_y=0, final_z=0, motion_duration_s=1)
            mip_hash = compute_mip_hash(canonical_mip_bytes(mip))
            bip_hash = compute_bip_hash(baseline.model_dump_json().encode())
            sender_private, sender_public = generate_ephemeral_keypair()
            receiver_private, receiver_public = generate_ephemeral_keypair()
            nonce = generate_nonce()
            sender_key = derive_session_key_ecdh(sender_private, receiver_public, mip_hash, bip_hash, nonce)
            receiver_key = derive_session_key_ecdh(receiver_private, sender_public, mip_hash, bip_hash, nonce)
            del sender_private, receiver_private
            sid = record.view.session_id
            self._update(record, status="streaming", last_event="Synthetic identity bound; session keys established")
            expected_index = 0
            for index in range(request.segment_count):
                if record.cancel.is_set():
                    self._update(record, status="cancelled", last_event="Simulation cancelled; no segment pending")
                    return
                plaintext = f"; EHLS synthetic segment {index}\nG1 X{index} Y{index}\n".encode()
                aad = segment_aad(sid, index)
                ciphertext, iv, checksum = encrypt_segment(plaintext, sender_key, aad=aad)
                del plaintext
                segment = EncryptedSegment(segment_index=index, layer_start=index, layer_end=index,
                    ciphertext=ciphertext, iv=iv, checksum=checksum, total_segments=request.segment_count)
                packet = build_packet(PacketType.SEGMENT_DELIVERY, session_id=sid,
                                      segment=json.loads(serialize_segment(segment)))
                wire = serialize_packet(sign_packet(packet, sender_key))
                received = deserialize_packet(wire)
                if (not verify_packet(received, receiver_key) or received.session_id != sid
                        or received.packet_type != PacketType.SEGMENT_DELIVERY):
                    raise ValueError("Invalid delivery envelope")
                received_segment = deserialize_segment(json.dumps(received.payload["segment"]).encode())
                if received_segment.segment_index != expected_index:
                    raise ValueError("Invalid delivery sequence")
                cancelled = False
                # Lock before decrypting; cleanup also runs on cancellation/failure.
                with SecureBuffer(len(received_segment.ciphertext) - 16, use_mlock=self.memory_lock) as buffer:
                    plaintext = decrypt_segment(received_segment.ciphertext, received_segment.iv,
                        receiver_key, received_segment.checksum, aad=segment_aad(sid, expected_index))
                    try:
                        buffer.write(plaintext)
                        if not buffer.read().startswith(b"; EHLS synthetic segment "):
                            raise ValueError("Simulator rejected instruction bytes")
                    finally:
                        del plaintext
                    try:
                        await asyncio.wait_for(record.cancel.wait(), timeout=request.interval_ms / 1000)
                        cancelled = True
                    except asyncio.TimeoutError:
                        pass
                if cancelled:
                    self._update(record, status="cancelled", last_event="Simulation cancelled; working buffer wiped")
                    return
                # ACK is deliberately created only after managed-buffer release.
                ack = sign_packet(build_packet(PacketType.SEGMENT_ACK, session_id=sid,
                                  segment_index=index, simulated=True), receiver_key)
                received_ack = deserialize_packet(serialize_packet(ack))
                if (not verify_packet(received_ack, sender_key) or received_ack.session_id != sid
                        or received_ack.packet_type != PacketType.SEGMENT_ACK
                        or received_ack.payload.get("segment_index") != index):
                    raise ValueError("Invalid acknowledgement")
                expected_index += 1
                self._update(record, completed_segments=expected_index,
                             progress=100 * expected_index / request.segment_count,
                             last_event=f"Segment {index}: simulated execution, buffer wiped, signed ACK verified")
            self._update(record, status="completed", last_event="Simulation completed; all managed buffers released")
        except SecureBufferLockError:
            self._update(record, status="failed", error="memory_lock_failed",
                         last_event="OS refused memory locking. See the development setup guide.")
        except asyncio.CancelledError:
            self._update(record, status="cancelled", last_event="Service stopping; working buffer released")
            raise
        except Exception:
            self._update(record, status="failed", error="simulation_failed",
                         last_event="Simulation failed; no further segments will be processed")

    async def close(self):
        tasks = []
        for record in self._sessions.values():
            if record.task and not record.task.done():
                record.cancel.set()
                tasks.append(record.task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._sessions.clear()
