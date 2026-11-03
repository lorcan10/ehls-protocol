"""
shared/models.py
Pydantic data models for the entire EHLS protocol.
"""

from __future__ import annotations
import time
import uuid
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


__all__ = [
    # Enums
    "SessionState",
    "PacketType",
    # Identity
    "MachineIdentityProfile",
    "EnrollmentRecord",
    # Commanded challenge (Claims 4-8)
    "DiagnosticChallenge",
    "ChallengeResponse",
    "BehaviouralBaseline",
    # Adaptive control (Claim 15)
    "AdaptivePolicy",
    # Session
    "SessionRecord",
    # Wire-protocol
    "ProtocolPacket",
    "EncryptedSegment",
    # Telemetry
    "MachineTelemetry",
    "TelemetryAlert",
    # Quality certificate
    "QualityCertificate",
]


# ─── Enumerations ────────────────────────────────────────────────────────────

class SessionState(str, Enum):
    PENDING = "pending"
    AUTHENTICATED = "authenticated"
    STREAMING = "streaming"
    PAUSED = "paused"
    COMPLETED = "completed"
    TERMINATED = "terminated"
    ERROR = "error"


class PacketType(str, Enum):
    ENROLL_REQUEST = "enroll_request"
    ENROLL_RESPONSE = "enroll_response"
    HANDSHAKE_REQUEST = "handshake_request"
    HANDSHAKE_RESPONSE = "handshake_response"
    SEGMENT_DELIVERY = "segment_delivery"
    SEGMENT_ACK = "segment_ack"
    TELEMETRY_UPDATE = "telemetry_update"
    ADAPTIVE_ADJUSTMENT = "adaptive_adjustment"
    HALT_COMMAND = "halt_command"
    SESSION_END = "session_end"
    SESSION_END_ACK = "session_end_ack"
    HEARTBEAT = "heartbeat"
    RECONNECT_REQUEST = "reconnect_request"
    RECONNECT_RESPONSE = "reconnect_response"
    ERROR_REPORT = "error_report"
    JOB_START_REQUEST = "job_start_request"
    JOB_START_RESPONSE = "job_start_response"
    # Commanded-challenge exchange (patent Claims 4–8 / Entry 7).  Server
    # issues a DIAGNOSTIC_CHALLENGE to the gateway within the response
    # payload of ENROLL_RESPONSE, HANDSHAKE_RESPONSE, or RECONNECT_RESPONSE.
    # Gateway executes it on the manufacturing device and submits a
    # CHALLENGE_RESULT with measured telemetry; server verifies against
    # the enrolled baseline before issuing session_key / ack.
    DIAGNOSTIC_CHALLENGE = "diagnostic_challenge"
    CHALLENGE_RESULT = "challenge_result"
    CHALLENGE_VERIFIED = "challenge_verified"


# ─── Machine Identity ────────────────────────────────────────────────────────

class MachineIdentityProfile(BaseModel):
    """Composite hardware fingerprint of a manufacturing machine."""
    cpu_id: str
    firmware_version: str
    board_serial: Optional[str] = None
    motor_signatures: dict[str, float] = Field(default_factory=dict)
    thermal_baselines: dict[str, float] = Field(default_factory=dict)
    timing_characteristics: dict[str, float] = Field(default_factory=dict)
    encoder_responses: dict[str, float] = Field(default_factory=dict)
    collected_at: float = Field(default_factory=time.time)


class EnrollmentRecord(BaseModel):
    """Stored record for an enrolled machine."""
    machine_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    mip_hash: str
    mip_snapshot: MachineIdentityProfile
    enrolled_at: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    active: bool = True
    # Active-challenge baseline captured during enrolment (Claims 4–8 /
    # Entry 7).  Stored once and reused to verify every subsequent
    # session's challenge response against tolerance bounds.  Null for
    # legacy machines enrolled before the challenge mechanism existed.
    behavioural_baseline: Optional["BehaviouralBaseline"] = None
    # SHA-256 of the canonical-JSON BehaviouralBaseline, computed when
    # the baseline is set and persisted alongside it.  Fed as a required
    # input to HKDF when deriving every per-session key (Claim 12A) so
    # the key is bound to the active behavioural fingerprint as well as
    # the passive MIP.  Empty string for legacy / pre-challenge records;
    # production session derivation rejects empty values at the crypto
    # layer.
    bip_hash: str = ""


# ─── Commanded diagnostic challenge (patent Claims 4–8 / Entry 7) ───────────

class DiagnosticChallenge(BaseModel):
    """A server-issued commanded-challenge specification.

    The server generates one of these on every enrolment, handshake, and
    reconnect.  The gateway executes the specified physical operations
    on the manufacturing device and returns the resulting telemetry as
    a :class:`ChallengeResponse`.  Randomising the parameters between
    sessions prevents replay of a previously-captured response (Claim 4).
    """
    challenge_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    # Phase tag — "enrolment", "handshake", or "reconnect".  The server
    # uses this to route the eventual CHALLENGE_RESULT into the right
    # post-verification action (capture baseline / issue session key /
    # rotate session key).
    phase: str = "handshake"
    # Thermal operation: nozzle target (°C).  Bounded to a safe,
    # non-operating range so the challenge itself cannot damage the
    # hot-end or extrude filament.
    nozzle_target_c: float
    nozzle_dwell_s: float = 20.0
    # Motion operation: XY endpoint (mm from origin).  Bounded inside
    # the printer's bed.  The gateway homes first, then traverses.
    motion_endpoint_x: float
    motion_endpoint_y: float
    motion_feedrate_mm_per_min: float = 3000.0
    # Tolerance bands for the server's post-verification comparison.
    # Fields match :class:`BehaviouralBaseline` column names.
    tolerance: dict[str, float] = Field(default_factory=lambda: {
        "ramp_rate_pct":       0.75,   # 75% relative divergence on heating rate
        "overshoot_c":         15.0,   # absolute °C — real printers with fans vary widely
        "steady_state_avg_c":  20.0,   # absolute °C — covers active-cooling settling band
        "final_position_mm":   3.0,    # absolute mm per axis
        "motion_duration_pct": 0.50,   # 50% relative divergence
    })
    issued_at: float = Field(default_factory=time.time)


class ChallengeResponse(BaseModel):
    """Gateway's measured response after executing a
    :class:`DiagnosticChallenge`.  Fed to the server's challenge
    verifier; the verifier's pass/fail verdict gates the phase's
    continuation (session key issue / baseline capture / key rotation).
    """
    challenge_id: str
    # Thermal response fields
    ramp_rate_c_per_s: float
    overshoot_c: float
    steady_state_avg_c: float
    thermal_sample_count: int
    # Motion response fields
    final_x: float
    final_y: float
    final_z: float
    motion_duration_s: float
    # Metadata
    executed_at: float = Field(default_factory=time.time)


class BehaviouralBaseline(BaseModel):
    """The canonical challenge response captured at enrolment — stored
    on the :class:`EnrollmentRecord` and reused for every subsequent
    session's tolerance-based verification."""
    enrolment_challenge_id: str
    ramp_rate_c_per_s: float
    overshoot_c: float
    steady_state_avg_c: float
    final_x: float
    final_y: float
    final_z: float
    motion_duration_s: float
    captured_at: float = Field(default_factory=time.time)


# ─── Per-job adaptive policy (patent Claim 15) ──────────────────────────────

class AdaptivePolicy(BaseModel):
    """IP-owner-specified adaptive-control parameters for a specific
    job.  Loaded from a sidecar JSON alongside the encrypted geometry
    vault file; NEVER supplied by the gateway operator (Claim 15:
    "adjustment parameters are governed by parameters specified by
    the intellectual property owner of the three-dimensional geometry,
    not by the operator of the manufacturing device").

    When a vault entry has no ``<name>.adaptive_policy.json``
    sidecar, the server's config-wide defaults apply and the policy
    is functionally the legacy behaviour.

    Fields:
      - ``temp_drift_threshold_c``: magnitude of nozzle temperature
        deviation that triggers feed-rate / extrusion adjustment.
      - ``safety_temp_max_c``: hard ceiling above which the session
        halts.  Usually left at 280 °C but exposable so materials
        with higher processing temperatures (e.g. PEEK, ULTEM) can
        extend it within the machine's physical limit.
      - ``feed_rate_factor_bounds``: (min, max) clamp for the
        multiplicative feed-rate adjustment applied pre-encryption.
      - ``extrusion_factor_bounds``: clamp for extrusion multiplier.
      - ``temperature_offset_bounds``: clamp for additive nozzle
        temperature offsets.
    """
    temp_drift_threshold_c: float = 5.0
    safety_temp_max_c: float = 280.0
    feed_rate_factor_bounds: tuple[float, float] = (0.5, 1.5)
    extrusion_factor_bounds: tuple[float, float] = (0.7, 1.5)
    temperature_offset_bounds: tuple[float, float] = (-20.0, 20.0)


# ─── Session ─────────────────────────────────────────────────────────────────

class SessionRecord(BaseModel):
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    machine_id: str
    state: SessionState = SessionState.PENDING
    session_key_id: str = ""
    created_at: float = Field(default_factory=time.time)
    last_activity: float = Field(default_factory=time.time)
    last_confirmed_segment: int = -1
    total_segments: int = 0
    job_file: str = ""


# ─── Protocol Packets ────────────────────────────────────────────────────────

class ProtocolPacket(BaseModel):
    packet_type: PacketType
    session_id: Optional[str] = None
    machine_id: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)
    payload: dict[str, Any] = Field(default_factory=dict)
    signature: Optional[str] = None


class EncryptedSegment(BaseModel):
    segment_index: int
    layer_start: int
    layer_end: int
    ciphertext: bytes
    iv: bytes
    checksum: str
    total_segments: int


# ─── Telemetry ───────────────────────────────────────────────────────────────

class MachineTelemetry(BaseModel):
    """Full or partial machine state snapshot."""
    timestamp: float = Field(default_factory=time.time)
    is_delta: bool = False
    fields: dict[str, Any] = Field(default_factory=dict)


class TelemetryAlert(BaseModel):
    alert_type: str  # "temperature_drift", "vibration_anomaly", "position_error", "safety_critical"
    severity: str  # "info", "warning", "critical"
    field: str
    expected_value: Any
    actual_value: Any
    timestamp: float = Field(default_factory=time.time)


# ─── Quality Certificate ─────────────────────────────────────────────────────

class QualityCertificate(BaseModel):
    certificate_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    machine_id: str
    job_file: str
    start_time: float
    end_time: float
    total_segments: int
    telemetry_summary: dict[str, Any] = Field(default_factory=dict)
    alerts_during_job: list[TelemetryAlert] = Field(default_factory=list)
    adaptive_adjustments_count: int = 0
    final_status: str = "completed"
    # ── Patent-claim-23 evidence fields ─────────────────────────────────────
    # IV hash chain: SHA-256 over the ordered concatenation of every
    # per-segment encryption IV delivered during the session.  Any segment
    # reorder / insert / omit produces a different hash, so the certificate
    # records the exact encrypted-segment sequence as a tamper-evident
    # commitment even though the instructions themselves are destroyed.
    iv_chain_hash: str = ""
    iv_count: int = 0
    # Per-segment telemetry correlation.  Each entry is
    # ``{"segment_index": int, "sample_count": int, "<field>": {"min",
    # "max", "avg"}, ...}`` covering telemetry observed while that segment
    # was in flight (between send and ACK).  Required by claim 23(a)(ii).
    per_segment_telemetry: list[dict[str, Any]] = Field(default_factory=list)
    # Structured adjustment log.  Each entry is
    # ``{"segment_index": int, "triggered_at": float, "trigger":
    # {alert_type, field, actual_value}, "adjustments": {...}}`` — the
    # per-segment "what got changed and why" record required by claim 17.
    adjustment_log: list[dict[str, Any]] = Field(default_factory=list)
    # Signature algorithm identifier.  "sha256" is the legacy unkeyed hash
    # retained for backwards-compat snapshots; "hmac-sha256" is the
    # patent-compliant keyed signature whose key is derived from
    # (session_key, mip_hash) via HKDF (see claim 23(b) final clause);
    # "ed25519" is the Claim 26A alternative for relying-party
    # verification without session secrets.
    signature_algorithm: str = "sha256"
    signature: str = ""
    # Key identifier for Ed25519 signatures (Claim 26A).  Empty for
    # HMAC and SHA-256 modes.  Verifiers look up the matching public
    # key from the published key registry by this identifier.
    signature_key_id: str = ""