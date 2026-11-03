"""
tests/security/test_secure_zero.py
Threat-T7 coverage: the buffer-destroy overwrite must actually
happen — a memory dump taken after :func:`gateway.secure_zero.secure_zero`
returns must show all-zero bytes in the buffer's region.

These tests exercise the observable post-condition that an
adversary with a memory dump would care about: bytes in the
destroyed buffer must be zero.  The tests do NOT (and cannot, in
pure Python) prove that the C compiler did not elide the call —
that property is delegated to the platform's documented primitive
selection (``RtlSecureZeroMemory`` / ``memset_s`` / ``ctypes.memset``
fallback).  What the tests CAN do is:

  1. Confirm the buffer's bytes are zero after secure_zero returns,
     even when the original payload is high-entropy (and therefore
     unlikely to "look zeroed" by accident).
  2. Confirm the platform selection logic returns a known primitive
     name on each supported OS.
  3. Confirm the multi-pass primitive performs N writes followed by
     a final zero — visible by interception of the underlying
     memmove / primitive on test instrumentation.
  4. Confirm shared.secure_memory.SecureBuffer.secure_wipe() —
     which delegates to secure_overwrite_then_zero — leaves the
     underlying buffer all-zero.

Patent reference: ``docs/PATENT_IMPLEMENTATION_GUIDE.md`` §11 WI-05,
threat T7.
"""

from __future__ import annotations

import ctypes
import platform
import secrets
from unittest.mock import patch

import pytest

from gateway.secure_zero import (
    backend_name,
    secure_overwrite_then_zero,
    secure_zero,
)
from shared.secure_memory import SecureBuffer


# ── Backend selection ────────────────────────────────────────────────


class TestBackendSelection:
    def test_backend_name_is_platform_appropriate(self):
        """One of the documented backends is active for the current
        OS.  Catches a regression where the import-time selection
        silently falls all the way through to a no-op."""
        name = backend_name()
        sysname = platform.system()
        if sysname == "Windows":
            assert name in ("RtlSecureZeroMemory", "fallback-volatile-memset")
        elif sysname in ("Linux", "Darwin", "FreeBSD"):
            assert name in ("memset_s", "fallback-volatile-memset")
        else:
            assert name == "fallback-volatile-memset"

    def test_backend_name_is_stable_across_calls(self):
        """The primitive is selected once at import; backend_name()
        must return the same value every call for the duration of
        the process."""
        assert backend_name() == backend_name()


# ── secure_zero on a ctypes.Array ────────────────────────────────────


class TestSecureZeroCtypesArray:
    def test_zeroes_a_buffer_full_of_secrets(self):
        size = 4096
        buf = (ctypes.c_char * size)()
        # Fill with high-entropy random data.
        secret = secrets.token_bytes(size)
        ctypes.memmove(ctypes.addressof(buf), secret, size)

        # Sanity: buffer holds the secret pre-zero.
        pre = bytes(buf)
        assert pre == secret

        secure_zero(buf)

        post = bytes(buf)
        assert post == b"\x00" * size, (
            "secure_zero failed to overwrite the buffer with zeros"
        )

    def test_zero_length_buffer_is_a_no_op(self):
        buf = (ctypes.c_char * 0)()
        # Should not raise.
        secure_zero(buf)
        assert bytes(buf) == b""

    def test_idempotent(self):
        size = 256
        buf = (ctypes.c_char * size)()
        ctypes.memmove(ctypes.addressof(buf), secrets.token_bytes(size), size)
        secure_zero(buf)
        secure_zero(buf)  # second call must not raise or corrupt
        assert bytes(buf) == b"\x00" * size


# ── secure_zero on a bytearray ────────────────────────────────────────


class TestSecureZeroBytearray:
    def test_zeroes_a_bytearray(self):
        ba = bytearray(secrets.token_bytes(1024))
        assert any(b != 0 for b in ba)
        secure_zero(ba)
        assert ba == bytearray(1024)

    def test_zeroes_an_empty_bytearray(self):
        ba = bytearray()
        secure_zero(ba)  # must not raise
        assert ba == bytearray()


# ── Type guards ──────────────────────────────────────────────────────


class TestTypeGuards:
    def test_rejects_immutable_bytes(self):
        with pytest.raises(TypeError):
            secure_zero(b"immutable")  # type: ignore[arg-type]

    def test_rejects_string(self):
        with pytest.raises(TypeError):
            secure_zero("string")  # type: ignore[arg-type]

    def test_rejects_readonly_memoryview(self):
        ro = memoryview(b"readonly")
        with pytest.raises(TypeError, match="writable buffer"):
            secure_zero(ro)


# ── Multi-pass primitive ─────────────────────────────────────────────


class TestSecureOverwriteThenZero:
    def test_post_state_is_all_zero_after_three_passes(self):
        size = 2048
        ba = bytearray(secrets.token_bytes(size))
        secure_overwrite_then_zero(ba, passes=3)
        assert ba == bytearray(size), (
            "multi-pass overwrite must leave the buffer all zeros"
        )

    def test_zero_passes_still_zeros_via_final_pass(self):
        """``passes=0`` should still hit the final zero pass — i.e.,
        the contract is "N+1 passes total, last one zero", not "0
        means do nothing"."""
        size = 64
        ba = bytearray(secrets.token_bytes(size))
        assert any(b != 0 for b in ba)
        secure_overwrite_then_zero(ba, passes=0)
        assert ba == bytearray(size)

    def test_negative_passes_rejected(self):
        ba = bytearray(16)
        with pytest.raises(ValueError, match="passes must be >= 0"):
            secure_overwrite_then_zero(ba, passes=-1)

    def test_pass_count_observed(self):
        """Intercept ctypes.memmove (used for the random passes) and
        the secure-zero primitive to confirm exactly N+1 writes
        happen in order: N CSPRNG passes followed by 1 zero call."""
        size = 256
        ba = bytearray(size)
        passes = 4

        from gateway import secure_zero as sz_module

        memmove_calls = 0
        primitive_calls = 0

        original_memmove = ctypes.memmove
        original_primitive = sz_module._PRIMITIVE

        def _counting_memmove(*args, **kwargs):
            nonlocal memmove_calls
            memmove_calls += 1
            return original_memmove(*args, **kwargs)

        def _counting_primitive(*args, **kwargs):
            nonlocal primitive_calls
            primitive_calls += 1
            return original_primitive(*args, **kwargs)

        with patch.object(sz_module.ctypes, "memmove", _counting_memmove), \
             patch.object(sz_module, "_PRIMITIVE", _counting_primitive):
            sz_module.secure_overwrite_then_zero(ba, passes=passes)

        assert memmove_calls == passes, (
            f"expected {passes} CSPRNG memmove calls, saw {memmove_calls}"
        )
        assert primitive_calls == 1, (
            f"expected exactly 1 final-zero primitive call, saw {primitive_calls}"
        )
        # Outside the patch context, the buffer should be zero.
        assert ba == bytearray(size)


# ── SecureBuffer integration ─────────────────────────────────────────


class TestSecureBufferDelegation:
    """SecureBuffer.secure_wipe() now delegates to
    secure_overwrite_then_zero.  The post-condition (buffer is zero)
    must still hold."""

    def test_wipe_zeroes_the_buffer(self):
        sb = SecureBuffer(size=4096, use_mlock=False, overwrite_passes=2)
        sb.write(secrets.token_bytes(4096))
        # Pre-condition: buffer holds non-zero bytes.
        pre = sb.read(length=4096)
        assert any(b != 0 for b in pre)

        sb.secure_wipe()
        post = sb.read(length=0)  # _data_length reset to 0 by wipe
        assert post == b""

        # Read raw underlying ctypes array bytes — bypassing the
        # public API's _data_length accounting — to confirm the
        # actual memory is zero.
        raw = bytes(sb._buf)
        assert raw == b"\x00" * 4096, (
            "SecureBuffer.secure_wipe failed to zero the underlying buffer"
        )

    def test_wipe_idempotent(self):
        sb = SecureBuffer(size=128, use_mlock=False, overwrite_passes=1)
        sb.write(b"x" * 128)
        sb.secure_wipe()
        sb.secure_wipe()  # second call must be a clean no-op-equivalent
        assert bytes(sb._buf) == b"\x00" * 128

    def test_release_zeroes_then_blocks_reads(self):
        """release() calls secure_wipe internally and marks the
        buffer released; subsequent reads raise."""
        sb = SecureBuffer(size=256, use_mlock=False, overwrite_passes=1)
        sb.write(b"secret payload")
        sb.release()
        # Underlying memory is zero before the buffer's gone.
        assert bytes(sb._buf) == b"\x00" * 256
        with pytest.raises(RuntimeError, match="already released"):
            sb.read(length=10)
