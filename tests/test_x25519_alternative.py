"""
tests/test_x25519_alternative.py
Claim 10A coverage: X25519 / ECDH alternative session-key mode.

The default HMAC-mode derivation (derive_session_key) binds the
session key to MIP_hash + BIP_hash + nonce + timestamp; both
endpoints derive the same key by sharing the same inputs.  No
forward secrecy: anyone who later obtains the inputs can recompute
every historical session key.

Claim 10A's X25519/ECDH mode adds forward secrecy via ephemeral
keypairs.  The MIP+BIP hashes still feed HKDF — the shared secret
is *concatenated* with the identity hashes, not in place of them —
so the device binding (Claim 12A) is preserved even in the
forward-secret mode.

Tested properties:

  * Both endpoints derive the same key from each other's public keys.
  * Different MIP / BIP hashes produce different keys (binding
    preserved despite the X25519 layer).
  * Different nonces produce different keys (per-session
    distinctness preserved).
  * Wrong peer public key → different shared secret → different
    key.
  * Each fresh ephemeral keypair produces an unrelated session
    key (forward secrecy).
  * Public-key bytes are exactly 32 bytes (raw X25519 encoding).
  * Type / length guards on peer_public_key_bytes.
"""

from __future__ import annotations

import pytest

from shared.crypto import (
    derive_session_key,
    derive_session_key_ecdh,
    generate_ephemeral_keypair,
    generate_nonce,
)


# ── Ephemeral keypair generation ─────────────────────────────────────


class TestEphemeralKeypair:
    def test_returns_private_key_and_32_byte_public_bytes(self):
        priv, pub = generate_ephemeral_keypair()
        assert pub is not None
        assert isinstance(pub, bytes)
        assert len(pub) == 32

    def test_each_call_returns_distinct_keypair(self):
        """Forward secrecy hinges on every session getting a fresh
        keypair.  The cryptography library's CSPRNG should never
        produce identical pairs."""
        _, pub_a = generate_ephemeral_keypair()
        _, pub_b = generate_ephemeral_keypair()
        assert pub_a != pub_b


# ── Two-endpoint key agreement ──────────────────────────────────────


class TestKeyAgreement:
    def test_both_endpoints_derive_same_key(self):
        """The whole point — gateway and server independently derive
        identical session keys from each other's public keys."""
        gw_priv, gw_pub = generate_ephemeral_keypair()
        srv_priv, srv_pub = generate_ephemeral_keypair()
        nonce = generate_nonce(32)
        mip, bip = "a" * 64, "b" * 64

        gw_key = derive_session_key_ecdh(gw_priv, srv_pub, mip, bip, nonce)
        srv_key = derive_session_key_ecdh(srv_priv, gw_pub, mip, bip, nonce)

        assert gw_key == srv_key
        assert len(gw_key) == 32

    def test_different_nonce_produces_different_key(self):
        gw_priv, _ = generate_ephemeral_keypair()
        _, srv_pub = generate_ephemeral_keypair()
        mip, bip = "a" * 64, "b" * 64

        k1 = derive_session_key_ecdh(gw_priv, srv_pub, mip, bip, generate_nonce(32))
        k2 = derive_session_key_ecdh(gw_priv, srv_pub, mip, bip, generate_nonce(32))
        assert k1 != k2

    def test_custom_key_length(self):
        gw_priv, _ = generate_ephemeral_keypair()
        _, srv_pub = generate_ephemeral_keypair()
        nonce = generate_nonce(32)
        key_64 = derive_session_key_ecdh(
            gw_priv, srv_pub, "a" * 64, "b" * 64, nonce, key_length=64,
        )
        assert len(key_64) == 64


# ── Identity binding preserved in ECDH mode ──────────────────────────


class TestIdentityBinding:
    """Even with ECDH the session key is bound to MIP+BIP — Claim 12A
    persists in the forward-secret mode."""

    def test_different_mip_produces_different_key(self):
        gw_priv, _ = generate_ephemeral_keypair()
        _, srv_pub = generate_ephemeral_keypair()
        nonce = generate_nonce(32)
        bip = "b" * 64
        k1 = derive_session_key_ecdh(gw_priv, srv_pub, "a" * 64, bip, nonce)
        k2 = derive_session_key_ecdh(gw_priv, srv_pub, "x" * 64, bip, nonce)
        assert k1 != k2

    def test_different_bip_produces_different_key(self):
        gw_priv, _ = generate_ephemeral_keypair()
        _, srv_pub = generate_ephemeral_keypair()
        nonce = generate_nonce(32)
        mip = "a" * 64
        k1 = derive_session_key_ecdh(gw_priv, srv_pub, mip, "b" * 64, nonce)
        k2 = derive_session_key_ecdh(gw_priv, srv_pub, mip, "y" * 64, nonce)
        assert k1 != k2

    def test_empty_bip_rejected(self):
        gw_priv, _ = generate_ephemeral_keypair()
        _, srv_pub = generate_ephemeral_keypair()
        with pytest.raises(ValueError, match="bip_hash is required"):
            derive_session_key_ecdh(
                gw_priv, srv_pub, "a" * 64, "", generate_nonce(32),
            )


# ── Peer-public-key validation ───────────────────────────────────────


class TestPeerPublicKeyValidation:
    def test_wrong_length_raises(self):
        gw_priv, _ = generate_ephemeral_keypair()
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            derive_session_key_ecdh(
                gw_priv, b"x" * 16, "a" * 64, "b" * 64, generate_nonce(32),
            )

    def test_non_bytes_raises(self):
        gw_priv, _ = generate_ephemeral_keypair()
        with pytest.raises(ValueError, match="must be bytes"):
            derive_session_key_ecdh(
                gw_priv, "not bytes", "a" * 64, "b" * 64, generate_nonce(32),  # type: ignore[arg-type]
            )

    def test_bytearray_accepted(self):
        """bytearray as well as bytes — the X25519 backend accepts
        either."""
        gw_priv, _ = generate_ephemeral_keypair()
        _, srv_pub = generate_ephemeral_keypair()
        nonce = generate_nonce(32)
        # bytearray copy of a real public key.
        key = derive_session_key_ecdh(
            gw_priv, bytearray(srv_pub), "a" * 64, "b" * 64, nonce,
        )
        assert len(key) == 32


# ── Forward secrecy ──────────────────────────────────────────────────


class TestForwardSecrecy:
    def test_fresh_keypairs_each_session_yield_unrelated_keys(self):
        """The classical forward-secrecy property: even with
        identical MIP/BIP/nonce, fresh ephemeral keypairs produce
        a different session key.  The HMAC-mode derivation cannot
        provide this guarantee."""
        mip, bip = "a" * 64, "b" * 64
        nonce = generate_nonce(32)

        # Session 1
        gw1_priv, _ = generate_ephemeral_keypair()
        _, srv1_pub = generate_ephemeral_keypair()
        k1 = derive_session_key_ecdh(gw1_priv, srv1_pub, mip, bip, nonce)

        # Session 2 — same identity, same nonce, fresh keypairs.
        gw2_priv, _ = generate_ephemeral_keypair()
        _, srv2_pub = generate_ephemeral_keypair()
        k2 = derive_session_key_ecdh(gw2_priv, srv2_pub, mip, bip, nonce)

        assert k1 != k2

    def test_wrong_peer_pub_yields_different_key(self):
        """An attacker who replays a captured session's
        peer-public-key field but doesn't have the matching
        private key derives a different (useless) key."""
        gw_priv, _ = generate_ephemeral_keypair()
        _, real_srv_pub = generate_ephemeral_keypair()
        _, attacker_srv_pub = generate_ephemeral_keypair()
        nonce = generate_nonce(32)
        mip, bip = "a" * 64, "b" * 64

        real = derive_session_key_ecdh(gw_priv, real_srv_pub, mip, bip, nonce)
        attacker = derive_session_key_ecdh(
            gw_priv, attacker_srv_pub, mip, bip, nonce,
        )
        assert real != attacker


# ── HMAC mode and ECDH mode are independent ─────────────────────────


class TestHmacAndEcdhAreDistinct:
    def test_modes_produce_different_keys_for_same_identity(self):
        """The two modes are not interchangeable — a session
        established in HMAC mode cannot be resumed in ECDH mode and
        vice versa.  The operator-facing config selects one mode for
        the entire deployment."""
        mip, bip = "a" * 64, "b" * 64
        nonce = generate_nonce(32)

        hmac_key = derive_session_key(mip, bip, nonce, 1234567890.0)

        gw_priv, _ = generate_ephemeral_keypair()
        _, srv_pub = generate_ephemeral_keypair()
        ecdh_key = derive_session_key_ecdh(gw_priv, srv_pub, mip, bip, nonce)

        assert hmac_key != ecdh_key

    def test_both_keys_are_32_bytes(self):
        """Default key length matches between modes so downstream
        AES-256-GCM consumers don't need mode-specific size handling."""
        mip, bip = "a" * 64, "b" * 64
        nonce = generate_nonce(32)
        hmac_key = derive_session_key(mip, bip, nonce, 1234567890.0)
        gw_priv, _ = generate_ephemeral_keypair()
        _, srv_pub = generate_ephemeral_keypair()
        ecdh_key = derive_session_key_ecdh(gw_priv, srv_pub, mip, bip, nonce)
        assert len(hmac_key) == 32
        assert len(ecdh_key) == 32
