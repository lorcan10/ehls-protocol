"""
shared/kdf_constants.py
Single source of truth for the EHLS protocol's domain-separation
constants and wire-format identifiers.

The four constants in this module are preferred-embodiment values
called out in the patent (see ``docs/PATENT_IMPLEMENTATION_GUIDE.md``
§3.1, §3.2, §3.3, §3.5). Changing any of them is a wire-protocol
event that breaks compatibility with every previously-issued
certificate and every other endpoint.  Do not change a value here
without a matching entry in ``docs/CRYPTO_CHANGE_LOG.md``.

**No other module is permitted to define these constants.** A CI
guard at ``tests/security/test_kdf_constants_isolation.py`` walks
the source tree on every test run and fails if any other Python
file contains a hard-coded ``b"EHLS-session-..."``,
``b"EHLS-cert-..."``, or ``EHLS-v1|`` literal.
"""

from __future__ import annotations


# ── HKDF info parameter constants ─────────────────────────────────────────
#
# Each constant is the ``info`` argument fed to HKDF-SHA256 when
# deriving a key for a specific purpose.  Domain separation requires
# every purpose to have a distinct, non-empty ``info`` string so a
# session key cannot be confused for a certificate-signing key by an
# adversary who somehow obtains both derivations' inputs.
#
# Adding a new constant requires:
#   1. A new symbol in this module with a docstring stating the purpose.
#   2. A ``CRYPTO_CHANGE_LOG.md`` entry recording the new constant and
#      its derivation context.
#   3. The constant value MUST be unique across all entries here.

HKDF_INFO_SESSION_KEY: bytes = b"EHLS-session-v1"
"""HKDF info for the per-session AES-256-GCM encryption key.

Derived in ``shared/crypto.derive_session_key`` from
``MIP_hash || BIP_hash || nonce || str(timestamp)``.  Patent reference: Claims 10, 10B."""

HKDF_INFO_CERT_SIGNING: bytes = b"EHLS-cert-v1"
"""HKDF info for the quality-certificate HMAC-SHA256 signing key.

Derived in ``server.quality_certificate`` from
``session_key || MIP_hash`` with empty salt.  Patent reference:
Claims 24, 26."""


# ── AAD prefix for per-segment AES-256-GCM ────────────────────────────────
#
# The Additional Authenticated Data tied to every encrypted segment is
# constructed as::
#
#     AAD_VERSION_PREFIX + session_id.encode() + b"|" + str(segment_index).encode()
#
# i.e. ``b"EHLS-v1|<session_id>|<segment_index>"``.  Any modification
# of the prefix invalidates the AEAD tag of every previously-issued
# segment and is therefore a wire-protocol break.

AAD_VERSION_PREFIX: bytes = b"EHLS-v1|"
"""Version-tagged prefix used in the AAD of every encrypted segment.

Patent reference: Claim 12."""


# ── Wire-format protocol version ──────────────────────────────────────────

WIRE_VERSION: int = 0x01
"""Single-byte protocol version stamped on every ``EncryptedSegmentPacket``.

Bumping this is a hard-fork event; gateways and cloud engines on
mismatched versions cannot interoperate.  Patent reference:
``PATENT_IMPLEMENTATION_GUIDE.md`` §3.2 wire format."""


# ── Helper: AAD construction ─────────────────────────────────────────────
#
# Centralised so every call site uses the exact same layout.  The
# previous implementation used ``f"EHLS-v1|{session_id}|{segment_index}"``
# inline in ``shared/crypto.py``; that string literal has now moved here.

def build_segment_aad(session_id: str, segment_index: int) -> bytes:
    """Return the AAD bytes for a per-segment AES-256-GCM operation.

    Layout: ``AAD_VERSION_PREFIX || session_id || "|" || segment_index``.

    Both endpoints must reconstruct the AAD identically, with the
    expected ``segment_index`` value, before the AEAD tag will verify.
    """
    return AAD_VERSION_PREFIX + session_id.encode("utf-8") + b"|" + str(segment_index).encode("utf-8")


__all__ = [
    "HKDF_INFO_SESSION_KEY",
    "HKDF_INFO_CERT_SIGNING",
    "AAD_VERSION_PREFIX",
    "WIRE_VERSION",
    "build_segment_aad",
]
