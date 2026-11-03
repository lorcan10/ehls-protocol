"""
shared/crypto.py
Cryptographic utilities: HKDF key derivation, AES-256-GCM encrypt/decrypt,
hashing, and integrity checksums.
"""

from __future__ import annotations
import hashlib
import hmac
import os
import secrets
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.backends import default_backend

from shared.kdf_constants import (
    HKDF_INFO_SESSION_KEY,
    build_segment_aad,
)


__all__ = [
    # Hashing
    "sha256_hash",
    "compute_mip_hash",
    "compute_bip_hash",
    "compute_checksum",
    "compute_keyed_checksum",
    "verify_keyed_checksum",
    # Key derivation
    "generate_nonce",
    "derive_session_key",
    "generate_ephemeral_keypair",
    "derive_session_key_ecdh",
    # AES-GCM segments
    "segment_aad",
    "encrypt_segment",
    "decrypt_segment",
]


# ─── Hashing ─────────────────────────────────────────────────────────────────

def sha256_hash(data: bytes) -> str:
    """Return hex-encoded SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def compute_mip_hash(mip_json: bytes) -> str:
    """Hash a serialised Machine Identity Profile."""
    return sha256_hash(mip_json)


def compute_bip_hash(bip_json: bytes) -> str:
    """Hash a serialised Behavioural Identity Profile (BehaviouralBaseline).

    Both endpoints must hash the same canonical JSON byte sequence so
    their independent HKDF derivations produce identical session keys.
    Pydantic's ``model_dump_json`` is the canonical serializer used
    here; call sites should always feed
    ``baseline.model_dump_json().encode("utf-8")``.

    Patent reference: Claim 12A binds the active behavioural-baseline
    fingerprint into the per-session HKDF input alongside the passive
    MIP hash, so the session key is a function of the device's active
    response as well as its passive identifiers.
    """
    return sha256_hash(bip_json)


def compute_checksum(data: bytes) -> str:
    """HMAC-SHA256 integrity checksum using a zero-key (actual key applied at higher layer)."""
    return hmac.new(b'\x00' * 32, data, hashlib.sha256).hexdigest()


def compute_keyed_checksum(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_keyed_checksum(key: bytes, data: bytes, expected: str) -> bool:
    return hmac.compare_digest(compute_keyed_checksum(key, data), expected)


# ─── Key Derivation ──────────────────────────────────────────────────────────

def generate_nonce(length: int = 32) -> bytes:
    """Cryptographically secure random nonce."""
    return secrets.token_bytes(length)


def derive_session_key(
    mip_hash: str,
    bip_hash: str,
    nonce: bytes,
    timestamp: float,
    info: bytes = HKDF_INFO_SESSION_KEY,
    key_length: int = 32,
) -> bytes:
    """Derive a one-time session key using HKDF-SHA256.

    IKM layout (Claim 10, 12A):

        mip_hash_bytes || bip_hash_bytes || nonce || timestamp_bytes

    ``bip_hash`` is the SHA-256 of the device's enrolled
    :class:`BehaviouralBaseline` (see :func:`compute_bip_hash`) and is
    a required input — Claim 12A binds the active behavioural
    fingerprint into the key alongside the passive MIP hash.  Tests
    that don't enrol a baseline can pass an explicit
    ``"0" * 64`` placeholder; production paths must always pass the
    real value computed at enrolment time.

    Both endpoints must compute the same ``mip_hash``, ``bip_hash``,
    ``nonce``, and ``timestamp`` to derive the same key — the key
    itself is never transmitted (Claim 10).
    """
    if not isinstance(bip_hash, str) or len(bip_hash) == 0:
        raise ValueError(
            "bip_hash is required (Claim 12A); pass the SHA-256 of the "
            "enrolled BehaviouralBaseline JSON, or an explicit placeholder "
            "for test paths"
        )
    ikm = (
        mip_hash.encode("utf-8")
        + bip_hash.encode("utf-8")
        + nonce
        + str(timestamp).encode("utf-8")
    )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=nonce,
        info=info,
        backend=default_backend(),
    )
    return hkdf.derive(ikm)


# ─── X25519 / ECDH alternative (Claim 10A) ──────────────────────────────────
#
# The HMAC-mode derivation above (derive_session_key) binds the key
# to the device's identity hashes + a fresh nonce; both endpoints
# derive the same key independently because they share the same
# inputs.  The downside is no forward secrecy — anyone who later
# obtains MIP_hash + BIP_hash + nonce + timestamp can recompute
# every historical session key.
#
# Claim 10A names X25519/ECDH as the alternative: each endpoint
# generates an ephemeral keypair per session, exchanges public
# keys over the (TLS-protected) handshake, and derives the shared
# secret via X25519 scalar multiplication.  Only the live process
# memories ever hold the private keys; once destroyed, no future
# attacker can recover the session key from the network capture.
#
# The MIP+BIP hashes still feed HKDF — the X25519 shared secret is
# concatenated WITH the identity hashes, not in place of them.
# This preserves Claim 12A's behavioural-fingerprint binding even
# in the forward-secret mode.


def generate_ephemeral_keypair() -> tuple[X25519PrivateKey, bytes]:
    """Generate an ephemeral X25519 keypair for one session handshake.

    Returns ``(private_key, public_key_bytes)``.  The private key
    must remain in volatile memory of its owning endpoint and be
    destroyed immediately after the shared secret is derived; the
    32-byte public-key bytes are sent across the wire in the
    handshake response.

    Patent reference: Claim 10A, ``PATENT_IMPLEMENTATION_GUIDE.md`` §3.1.
    """
    priv = X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub_bytes


def derive_session_key_ecdh(
    own_private_key: X25519PrivateKey,
    peer_public_key_bytes: bytes,
    mip_hash: str,
    bip_hash: str,
    nonce: bytes,
    info: bytes = HKDF_INFO_SESSION_KEY,
    key_length: int = 32,
) -> bytes:
    """Derive a forward-secret session key via X25519 + HKDF-SHA256
    (Claim 10A).

    IKM layout::

        shared_secret || mip_hash_bytes || bip_hash_bytes

    where ``shared_secret`` is the 32-byte output of
    ``X25519(own_priv, peer_pub)``.  The MIP and BIP hashes are
    concatenated AFTER the shared secret so the key is bound to
    the specific authenticated device (Claim 12A) — replicating an
    X25519 keypair without the matching identity profile produces
    a different session key.

    The ``nonce`` parameter is fed in as the HKDF salt — same
    layout as :func:`derive_session_key` — so the two modes drop
    into a unified handshake without the gateway needing to know
    which mode the operator selected at config time (other than
    which derive function to call).

    Parameters
    ----------
    own_private_key:
        This endpoint's ephemeral X25519 private key from
        :func:`generate_ephemeral_keypair`.
    peer_public_key_bytes:
        The 32-byte raw-encoded public key the peer sent in its
        handshake message.  Raises :class:`ValueError` if not
        exactly 32 bytes.
    mip_hash, bip_hash:
        Same identity hashes as the HMAC-mode derivation.  Both
        required; non-empty.
    nonce:
        Fresh per-session nonce (≥32 bytes recommended) — feeds
        HKDF salt.
    info, key_length:
        HKDF parameters — defaults match :func:`derive_session_key`.

    Returns
    -------
    bytes
        32-byte derived session key (or ``key_length`` bytes if
        overridden).  Both endpoints derive the same value.
    """
    if not isinstance(peer_public_key_bytes, (bytes, bytearray)):
        raise ValueError(
            "peer_public_key_bytes must be bytes (32-byte raw X25519 key)"
        )
    if len(peer_public_key_bytes) != 32:
        raise ValueError(
            f"peer_public_key_bytes must be exactly 32 bytes, got "
            f"{len(peer_public_key_bytes)}"
        )
    if not isinstance(bip_hash, str) or len(bip_hash) == 0:
        raise ValueError(
            "bip_hash is required (Claim 12A); pass the SHA-256 of the "
            "enrolled BehaviouralBaseline JSON, or an explicit placeholder "
            "for test paths"
        )

    peer_pub = X25519PublicKey.from_public_bytes(bytes(peer_public_key_bytes))
    shared_secret = own_private_key.exchange(peer_pub)

    ikm = (
        shared_secret
        + mip_hash.encode("utf-8")
        + bip_hash.encode("utf-8")
    )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=nonce,
        info=info,
        backend=default_backend(),
    )
    return hkdf.derive(ikm)


# ─── AES-256-GCM Encryption ──────────────────────────────────────────────────

def segment_aad(session_id: str, segment_index: int) -> bytes:
    """
    Canonical Additional Authenticated Data (AAD) for a G-code segment.

    Binding ``session_id`` and ``segment_index`` into the AES-GCM auth tag
    means the segment's metadata is cryptographically pinned to its
    ciphertext. The decrypting side must know — and supply — the *same*
    session_id and segment_index, otherwise the GCM tag check fails and
    decryption raises. This defeats:

      * **replay** of a previously captured segment (its index has already
        been consumed, so the gateway's expected AAD differs);
      * **cross-session injection** of a segment captured from a different
        print job (different session_id → different AAD → tag fails);
      * **index tampering** on the wire (the plain-text ``segment_index``
        on the ``EncryptedSegment`` envelope is now only a hint; the
        authoritative index is the one bound into the AAD).

    The exact byte layout lives in
    :func:`shared.kdf_constants.build_segment_aad` — the single source
    of truth for the AAD format.  This function is a thin alias kept
    for source-level backwards compatibility with existing call sites.
    """
    return build_segment_aad(session_id, segment_index)


def encrypt_segment(
    plaintext: bytes,
    key: bytes,
    aad: bytes | None = None,
) -> Tuple[bytes, bytes, str]:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Returns (ciphertext, iv, checksum_hex).

    ``aad`` is optional Additional Authenticated Data bound into the GCM
    auth tag. For G-code segments, callers should supply the output of
    :func:`segment_aad` to pin segment_index + session_id to the ciphertext.
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")
    iv = os.urandom(12)  # 96-bit nonce for GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, aad)
    # HMAC checksum also covers AAD, so a caller that supplies the wrong
    # AAD trips the outer integrity check before AESGCM.decrypt is called.
    checksum = compute_keyed_checksum(key, iv + ciphertext + (aad or b""))
    return ciphertext, iv, checksum


def decrypt_segment(
    ciphertext: bytes,
    iv: bytes,
    key: bytes,
    checksum: str,
    aad: bytes | None = None,
) -> bytes:
    """
    Verify integrity then decrypt.
    Raises ValueError on checksum mismatch or decryption failure.

    If ``aad`` was supplied at encrypt time, the same bytes must be
    supplied here; a mismatch fails both the HMAC checksum and the GCM
    auth tag.
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")
    if not verify_keyed_checksum(key, iv + ciphertext + (aad or b""), checksum):
        raise ValueError("Integrity checksum mismatch — segment may be tampered")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, aad)
