"""
shared/identity_artefacts.py
Canonical home for the two machine-identity artefacts the patent
distinguishes (Claim 9):

* **MIP** — Machine Identity Profile.  *Passive* identifiers (model
  id, firmware version, board serial, idle thermal baselines,
  motion-planner parameters).  Re-verifiable without commanding any
  motion: the gateway snapshots the live MIP from one telemetry
  frame and the cloud engine compares it to the enrolled MIP.

* **BIP** — Behavioural Identity Profile.  *Active*, commanded-
  challenge response feature vector (ramp rate, overshoot,
  steady-state, final XYZ, motion duration, ...).  Captured once at
  enrolment (``BehaviouralBaseline``) and used for tolerance-banded
  challenge-response verification (Claim 4) and as an HKDF input
  binding the session key to the device's measured response
  (Claim 12A).

The two artefacts serve distinct roles and **must not be conflated**
in code: a passive MIP re-verification step (e.g. on reconnect)
runs without any BIP data; an active challenge step uses the
stored BIP and never consults the live MIP for tolerance bands.

The actual Pydantic models live in ``shared/models.py`` for backwards
compatibility with the existing 50+ import sites.  This module
re-exports them under both their canonical long names and the
patent-cited short aliases (``MIP``, ``BIP``), and provides a
free-function MIP-only verifier so callers can do passive
verification without holding a SessionManager instance.

Patent reference: ``docs/PATENT_IMPLEMENTATION_GUIDE.md`` §2 Claim 9.
"""

from __future__ import annotations

from typing import Iterable, Optional

from shared.models import (
    BehaviouralBaseline,
    EnrollmentRecord,
    MachineIdentityProfile,
)


# Default exact-match field list for the two-tier comparison.  Patent
# Claim 5 names these as the immutable identifiers that must match
# byte-for-byte; the relative-divergence tolerance applies only to the
# numeric MIP groups (motor signatures, thermal baselines, timing
# characteristics, encoder responses).  Deployments can override the
# list when constructing a MipComparator (server/mip_comparator.py).
DEFAULT_EXACT_MATCH_FIELDS: tuple[str, ...] = ("cpu_id", "firmware_version")


# ── Short aliases ─────────────────────────────────────────────────────
#
# The patent text uses ``MIP`` and ``BIP``; these aliases let new code
# read closer to the spec.  Existing imports of the long names continue
# to work — they're the same class object.

MIP = MachineIdentityProfile
"""Alias for :class:`MachineIdentityProfile` matching the patent's
``MIP`` shorthand."""

BIP = BehaviouralBaseline
"""Alias for :class:`BehaviouralBaseline` matching the patent's
``BIP`` shorthand."""


# ── MIP-only re-verification ──────────────────────────────────────────
#
# Pulled out of SessionManager.verify_mip so callers that don't need
# full session state (reconnect handlers, dry-run audits, debug CLI)
# can run the same comparison without instantiating SessionManager.
# SessionManager.verify_mip is now a thin wrapper around this.


def verify_mip_only(
    live_mip: MachineIdentityProfile,
    enrolled_mip: MachineIdentityProfile,
    tolerance: float = 0.15,
    exact_match_fields: Optional[Iterable[str]] = None,
) -> tuple[bool, float]:
    """Compare ``live_mip`` against ``enrolled_mip`` using only passive
    identifiers.  No BIP / behavioural-baseline data is consulted.

    Two-tier comparison (Claim 5):

    * **Exact-match required** for every field in ``exact_match_fields``
      (defaults to ``("cpu_id", "firmware_version")`` per the patent's
      preferred-embodiment values).  Any mismatch returns
      ``(False, 1.0)`` immediately.
    * **Relative-divergence threshold** for the numeric field groups
      (``motor_signatures``, ``thermal_baselines``,
      ``timing_characteristics``, ``encoder_responses``).  The
      average relative divergence across all numeric fields must be
      ``≤ tolerance`` for verification to pass.

    Parameters
    ----------
    live_mip, enrolled_mip:
        The two MIPs to compare.
    tolerance:
        Maximum average relative divergence permitted across the
        numeric tier.  Default 0.15 per the v5 priority filing's
        preferred-embodiment value.
    exact_match_fields:
        Names of MIP attributes that must match byte-for-byte.  Each
        name must be a top-level attribute of
        :class:`MachineIdentityProfile`.  Default
        :data:`DEFAULT_EXACT_MATCH_FIELDS` — deployments that need a
        narrower or wider exact-match list (e.g. additional ``board_serial``)
        construct a :class:`server.mip_comparator.MipComparator` with
        a custom list and call its ``compare`` method.

    Returns
    -------
    (is_match, divergence)
        ``is_match`` is ``True`` iff both tiers pass.
        ``divergence`` is the average relative divergence in [0, 1];
        ``1.0`` indicates a hard failure on an exact-match field.

    This function is the canonical MIP-only path required by Claim 9
    ("MIP re-verifiable without motion").  It is deterministic and
    side-effect-free, so it can be safely called from non-async
    contexts (audit tools, CLI helpers).
    """
    fields = tuple(exact_match_fields) if exact_match_fields is not None else DEFAULT_EXACT_MATCH_FIELDS
    for field_name in fields:
        if not hasattr(enrolled_mip, field_name):
            raise AttributeError(
                f"Exact-match field {field_name!r} is not a MachineIdentityProfile attribute"
            )
        if getattr(live_mip, field_name) != getattr(enrolled_mip, field_name):
            return False, 1.0

    total_fields = 0
    total_divergence = 0.0

    for group_attr in (
        "motor_signatures",
        "thermal_baselines",
        "timing_characteristics",
        "encoder_responses",
    ):
        enrolled_dict = getattr(enrolled_mip, group_attr)
        live_dict = getattr(live_mip, group_attr)
        for key, enrolled_val in enrolled_dict.items():
            total_fields += 1
            live_val = live_dict.get(key)
            if live_val is None:
                total_divergence += 1.0
                continue
            if enrolled_val == 0:
                if live_val != 0:
                    total_divergence += 1.0
                continue
            relative_diff = abs(live_val - enrolled_val) / abs(enrolled_val)
            total_divergence += min(relative_diff, 1.0)

    avg_div = total_divergence / total_fields if total_fields else 0.0
    return avg_div <= tolerance, avg_div


# ── Convenience accessors ─────────────────────────────────────────────


def canonical_mip_bytes(mip: MachineIdentityProfile) -> bytes:
    """Return the canonical UTF-8 JSON bytes used as the MIP-hash input.

    Hashes only the *truly immutable* identity tier — Claim 5's
    "exact-match required" fields:

    * ``cpu_id``
    * ``firmware_version``
    * ``board_serial``

    The numeric groups (``motor_signatures``, ``thermal_baselines``,
    ``timing_characteristics``, ``encoder_responses``) are
    intentionally excluded.  They're sampled from telemetry at
    enrolment time and drift between reboots — current bed
    temperature, current nozzle temperature, current planner state,
    etc.  Claim 5's two-tier comparator already treats those as the
    relative-divergence tier (handled by ``verify_mip_only``); they
    have no business in the identity hash.

    PR #77's earlier attempt only excluded ``collected_at`` and left
    the numeric groups in, which on the K1C still produced a fresh
    hash on every boot (telemetry snapshots vary).  Hash drift →
    new ``machine_id`` per enrolment → orphaned platform DB rows
    and orphaned certificates.

    Patent reference: Claim 9 (MIP re-verifiability without motion)
    explicitly requires the identity hash to be reproducible from a
    fresh telemetry snapshot.  Only the exact-match-required fields
    satisfy that property in practice.
    """
    import json
    immutable = {
        "cpu_id":           mip.cpu_id,
        "firmware_version": mip.firmware_version,
        "board_serial":     mip.board_serial,
    }
    return json.dumps(immutable, sort_keys=True).encode("utf-8")


def has_baseline(record: EnrollmentRecord) -> bool:
    """``True`` iff the enrolment record carries a captured BIP.

    Pre-challenge / legacy records have ``behavioural_baseline=None``
    and ``bip_hash=""``; production records have both fields
    populated.  Callers that need to know whether challenge
    verification can run consult this helper rather than reading the
    raw fields.
    """
    return record.behavioural_baseline is not None and bool(record.bip_hash)


__all__ = [
    "MachineIdentityProfile",
    "BehaviouralBaseline",
    "EnrollmentRecord",
    "MIP",
    "BIP",
    "DEFAULT_EXACT_MATCH_FIELDS",
    "canonical_mip_bytes",
    "verify_mip_only",
    "has_baseline",
]
