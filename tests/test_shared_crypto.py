"""
tests/test_shared_crypto.py
Tests for shared/crypto.py
"""

import pytest
from shared.crypto import (
    sha256_hash,
    compute_mip_hash,
    compute_checksum,
    compute_keyed_checksum,
    verify_keyed_checksum,
    generate_nonce,
    derive_session_key,
    encrypt_segment,
    decrypt_segment,
    segment_aad,
)


class TestHashing:
    def test_sha256_hash_returns_hex_string(self):
        result = sha256_hash(b"hello")
        assert isinstance(result, str)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_sha256_hash_deterministic(self):
        assert sha256_hash(b"hello") == sha256_hash(b"hello")

    def test_sha256_hash_differs_on_different_input(self):
        assert sha256_hash(b"hello") != sha256_hash(b"world")

    def test_compute_mip_hash(self):
        result = compute_mip_hash(b'{"cpu_id": "test"}')
        assert isinstance(result, str)
        assert len(result) == 64

    def test_compute_checksum_deterministic(self):
        assert compute_checksum(b"data") == compute_checksum(b"data")

    def test_keyed_checksum_uses_key(self):
        key1 = b"\x01" * 32
        key2 = b"\x02" * 32
        assert compute_keyed_checksum(key1, b"data") != compute_keyed_checksum(key2, b"data")

    def test_verify_keyed_checksum_ok(self):
        key = b"\xaa" * 32
        data = b"test data"
        checksum = compute_keyed_checksum(key, data)
        assert verify_keyed_checksum(key, data, checksum) is True

    def test_verify_keyed_checksum_wrong_data(self):
        key = b"\xaa" * 32
        checksum = compute_keyed_checksum(key, b"original")
        assert verify_keyed_checksum(key, b"tampered", checksum) is False

    def test_verify_keyed_checksum_wrong_key(self):
        key1 = b"\xaa" * 32
        key2 = b"\xbb" * 32
        checksum = compute_keyed_checksum(key1, b"data")
        assert verify_keyed_checksum(key2, b"data", checksum) is False


class TestNonceAndKeyDerivation:
    def test_generate_nonce_length(self):
        assert len(generate_nonce(32)) == 32
        assert len(generate_nonce(16)) == 16

    def test_generate_nonce_random(self):
        assert generate_nonce(32) != generate_nonce(32)

    def test_derive_session_key_length(self):
        nonce = generate_nonce(32)
        key = derive_session_key("a" * 64, "b" * 64, nonce, 1000.0)
        assert len(key) == 32

    def test_derive_session_key_deterministic(self):
        nonce = generate_nonce(32)
        ts = 1000.0
        mip_hash = "b" * 64
        bip_hash = "c" * 64
        key1 = derive_session_key(mip_hash, bip_hash, nonce, ts)
        key2 = derive_session_key(mip_hash, bip_hash, nonce, ts)
        assert key1 == key2

    def test_derive_session_key_differs_by_nonce(self):
        mip_hash = "c" * 64
        bip_hash = "d" * 64
        ts = 1000.0
        key1 = derive_session_key(mip_hash, bip_hash, generate_nonce(32), ts)
        key2 = derive_session_key(mip_hash, bip_hash, generate_nonce(32), ts)
        assert key1 != key2

    def test_derive_session_key_differs_by_mip(self):
        nonce = generate_nonce(32)
        ts = 1000.0
        bip_hash = "0" * 64
        key1 = derive_session_key("a" * 64, bip_hash, nonce, ts)
        key2 = derive_session_key("b" * 64, bip_hash, nonce, ts)
        assert key1 != key2


class TestAesGcm:
    def test_encrypt_decrypt_roundtrip(self, session_key):
        plaintext = b"G1 X10 Y10 Z0.2 F3000\nG1 X20 E1.0\n"
        ciphertext, iv, checksum = encrypt_segment(plaintext, session_key)
        result = decrypt_segment(ciphertext, iv, session_key, checksum)
        assert result == plaintext

    def test_encrypt_produces_different_iv_each_time(self, session_key):
        plaintext = b"hello"
        _, iv1, _ = encrypt_segment(plaintext, session_key)
        _, iv2, _ = encrypt_segment(plaintext, session_key)
        assert iv1 != iv2

    def test_ciphertext_differs_from_plaintext(self, session_key):
        plaintext = b"G28"
        ciphertext, _, _ = encrypt_segment(plaintext, session_key)
        assert ciphertext != plaintext

    def test_decrypt_wrong_key_raises(self, session_key):
        plaintext = b"G28"
        ciphertext, iv, checksum = encrypt_segment(plaintext, session_key)
        wrong_key = bytes(reversed(session_key))
        with pytest.raises((ValueError, Exception)):
            decrypt_segment(ciphertext, iv, wrong_key, checksum)

    def test_decrypt_tampered_ciphertext_raises(self, session_key):
        plaintext = b"G28"
        ciphertext, iv, checksum = encrypt_segment(plaintext, session_key)
        tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
        with pytest.raises((ValueError, Exception)):
            decrypt_segment(tampered, iv, session_key, checksum)

    def test_encrypt_wrong_key_length_raises(self):
        with pytest.raises(ValueError):
            encrypt_segment(b"test", b"short_key")

    def test_decrypt_wrong_key_length_raises(self):
        with pytest.raises(ValueError):
            decrypt_segment(b"ct", b"iv", b"short", "checksum")

    def test_large_payload(self, session_key):
        plaintext = b"G1 X10 E0.5\n" * 10000  # ~120 KB
        ciphertext, iv, checksum = encrypt_segment(plaintext, session_key)
        result = decrypt_segment(ciphertext, iv, session_key, checksum)
        assert result == plaintext


class TestSegmentAAD:
    """
    AAD binds segment_index + session_id into the AES-GCM auth tag so that
    a wire attacker cannot replay a captured segment under a different
    index or session without failing decryption.
    """

    def test_aad_roundtrip(self, session_key):
        plaintext = b"G1 X10 Y10\n"
        aad = segment_aad("sess-abc", 7)
        ciphertext, iv, checksum = encrypt_segment(plaintext, session_key, aad=aad)
        result = decrypt_segment(ciphertext, iv, session_key, checksum, aad=aad)
        assert result == plaintext

    def test_aad_differs_by_session_and_index(self):
        # Two segments that share a plaintext and key must produce
        # distinct AAD values for distinct (session_id, segment_index).
        assert segment_aad("sess-a", 0) != segment_aad("sess-b", 0)
        assert segment_aad("sess-a", 0) != segment_aad("sess-a", 1)

    def test_replay_under_different_index_rejected(self, session_key):
        """
        Capture segment 5, attempt to replay it as segment 6.
        Decrypt must fail because the AAD the gateway rebuilds does not
        match the one the server bound at encrypt time.
        """
        plaintext = b"G1 X10 Y10\n"
        aad_server = segment_aad("sess-xyz", 5)
        ciphertext, iv, checksum = encrypt_segment(plaintext, session_key, aad=aad_server)

        aad_attack = segment_aad("sess-xyz", 6)
        with pytest.raises((ValueError, Exception)):
            decrypt_segment(ciphertext, iv, session_key, checksum, aad=aad_attack)

    def test_cross_session_injection_rejected(self, session_key):
        """
        Segment captured in session A cannot be successfully decrypted
        when presented as part of session B, even at the same index.
        """
        plaintext = b"G1 X10 Y10\n"
        ciphertext, iv, checksum = encrypt_segment(
            plaintext, session_key, aad=segment_aad("session-A", 3)
        )
        with pytest.raises((ValueError, Exception)):
            decrypt_segment(
                ciphertext, iv, session_key, checksum,
                aad=segment_aad("session-B", 3),
            )

    def test_missing_aad_on_decrypt_rejected(self, session_key):
        """
        If the server encrypted with AAD, the gateway must supply the
        same AAD. Omitting it (None) must fail.
        """
        plaintext = b"G1 X10 Y10\n"
        aad = segment_aad("sess-omit", 1)
        ciphertext, iv, checksum = encrypt_segment(plaintext, session_key, aad=aad)
        with pytest.raises((ValueError, Exception)):
            decrypt_segment(ciphertext, iv, session_key, checksum, aad=None)
