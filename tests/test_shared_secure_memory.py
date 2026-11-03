"""
tests/test_shared_secure_memory.py
Tests for shared/secure_memory.py
"""

import pytest
from shared.secure_memory import SecureBuffer, SecureBufferPool


class TestSecureBuffer:
    def test_write_and_read(self):
        buf = SecureBuffer(256, use_mlock=False)
        data = b"hello world"
        buf.write(data)
        assert buf.read(len(data)) == data

    def test_read_full_written_length(self):
        buf = SecureBuffer(256, use_mlock=False)
        data = b"ABCDE"
        buf.write(data)
        assert buf.read() == data

    def test_write_with_offset(self):
        buf = SecureBuffer(256, use_mlock=False)
        buf.write(b"hello")
        buf.write(b" world", offset=5)
        assert buf.read(11) == b"hello world"

    def test_overflow_raises(self):
        buf = SecureBuffer(4, use_mlock=False)
        with pytest.raises(OverflowError):
            buf.write(b"toolong")

    def test_secure_wipe_zeros_data(self):
        buf = SecureBuffer(64, use_mlock=False, overwrite_passes=1)
        buf.write(b"secret data here!!!")
        buf.secure_wipe()
        assert buf.read(64) == b"\x00" * 64

    def test_read_after_release_raises(self):
        buf = SecureBuffer(64, use_mlock=False)
        buf.write(b"data")
        buf.release()
        with pytest.raises(RuntimeError):
            buf.read(4)

    def test_write_after_release_raises(self):
        buf = SecureBuffer(64, use_mlock=False)
        buf.release()
        with pytest.raises(RuntimeError):
            buf.write(b"data")

    def test_double_release_is_safe(self):
        buf = SecureBuffer(64, use_mlock=False)
        buf.release()
        buf.release()  # must not raise

    def test_context_manager_releases(self):
        with SecureBuffer(64, use_mlock=False) as buf:
            buf.write(b"secret")
        with pytest.raises(RuntimeError):
            buf.read(6)

    def test_size_attribute(self):
        buf = SecureBuffer(1024, use_mlock=False)
        assert buf.size == 1024

    def test_mlock_failure_tolerated_when_not_strict(self):
        """Non-strict mode (the pre-Claim-3 behaviour, retained for
        unprivileged CI) must not crash on lock failure — it logs a
        warning and proceeds unlocked."""
        buf = SecureBuffer(64, use_mlock=True, strict=False)
        buf.write(b"test")
        assert buf.read(4) == b"test"
        buf.release()


class TestSecureBufferPool:
    def test_acquire_returns_buffer(self):
        pool = SecureBufferPool(64, pool_count=2, use_mlock=False)
        buf = pool.acquire()
        assert isinstance(buf, SecureBuffer)
        pool.return_buffer(buf)

    def test_acquire_and_return_cycle(self):
        pool = SecureBufferPool(64, pool_count=2, use_mlock=False)
        buf = pool.acquire()
        buf.write(b"secret")
        pool.return_buffer(buf)
        # After return, buffer should be wiped — re-acquire and verify zeros
        buf2 = pool.acquire()
        assert buf2.read(6) == b"\x00" * 6
        pool.return_buffer(buf2)

    def test_acquire_beyond_pool_allocates_new(self):
        pool = SecureBufferPool(64, pool_count=1, use_mlock=False)
        buf1 = pool.acquire()
        buf2 = pool.acquire()  # pool empty, should allocate new
        assert isinstance(buf2, SecureBuffer)
        pool.return_buffer(buf1)
        pool.return_buffer(buf2)

    def test_release_all(self):
        pool = SecureBufferPool(64, pool_count=3, use_mlock=False)
        pool.release_all()
        # After release_all, pool is empty; acquire should still work (new allocation)
        buf = pool.acquire()
        assert isinstance(buf, SecureBuffer)
        buf.release()

    def test_multiple_acquire_return_cycles(self):
        pool = SecureBufferPool(128, pool_count=4, use_mlock=False)
        bufs = [pool.acquire() for _ in range(4)]
        for i, buf in enumerate(bufs):
            buf.write(f"secret-{i}".encode())
        for buf in bufs:
            pool.return_buffer(buf)
        # All returned; pool should have 4 available
        assert len(pool._available) == 4


# ── Patent Claim 3: fail-closed memory locking ──────────────────────────────

class _AlwaysFailBackend:
    """In-memory fake backend that reports lock failure on every
    call.  Used by the fail-closed tests to simulate an mlock /
    VirtualLock rejection without involving the OS.

    SecureBuffer now routes through MemoryLockBackend (PR #44 follow-up
    wiring), so the lock-failure simulation injects a fake backend
    rather than monkey-patching the obsolete module-level _mlock
    helper."""

    name = "always_fail_for_test"
    available = True

    def lock(self, addr: int, size: int) -> bool:
        return False

    def unlock(self, addr: int, size: int) -> None:
        pass


class _AlwaysOkBackend:
    """Counterpart fake — every lock succeeds."""

    name = "always_ok_for_test"
    available = True

    def lock(self, addr: int, size: int) -> bool:
        return True

    def unlock(self, addr: int, size: int) -> None:
        pass


class TestStrictModeFailClosed:
    """Patent Claim 3 requires that mlock/VirtualLock failure rejects
    the session outright — no fallback to unlocked memory.  These
    tests exercise the strict=True path by injecting a fake backend
    that reports lock failure."""

    def test_strict_raises_on_lock_failure(self):
        """When the backend reports lock failure and strict=True,
        SecureBuffer construction must raise SecureBufferLockError
        and leave no partially-initialised buffer behind."""
        from shared.secure_memory import SecureBufferLockError

        with pytest.raises(SecureBufferLockError, match="Failed to lock"):
            SecureBuffer(
                64, use_mlock=True, strict=True,
                backend=_AlwaysFailBackend(),
            )

    def test_strict_default_is_true(self):
        """Production default must be strict — callers have to
        opt into the non-strict path explicitly."""
        from shared.secure_memory import SecureBufferLockError

        # No explicit strict= arg → defaults to True → must raise.
        with pytest.raises(SecureBufferLockError):
            SecureBuffer(64, use_mlock=True, backend=_AlwaysFailBackend())

    def test_strict_permits_construction_when_lock_succeeds(self):
        """The strict flag only rejects on FAILURE — a successful
        lock proceeds normally."""
        buf = SecureBuffer(
            64, use_mlock=True, strict=True,
            backend=_AlwaysOkBackend(),
        )
        assert buf.size == 64
        buf.release()

    def test_strict_ignored_when_use_mlock_false(self):
        """When use_mlock=False there is no locking to fail, so the
        strict flag is a no-op."""
        buf = SecureBuffer(
            64, use_mlock=False, strict=True,
            backend=_AlwaysFailBackend(),
        )
        assert buf.size == 64
        buf.release()

    def test_pool_propagates_strict_to_buffers(self):
        """SecureBufferPool must forward strict=True to every buffer
        it allocates, including buffers created after the pool is
        exhausted."""
        from shared.secure_memory import SecureBufferLockError

        # Pool construction itself fails when strict=True because
        # it tries to pre-allocate buffers — the injected backend
        # reports lock failure on every call.
        with pytest.raises(SecureBufferLockError):
            SecureBufferPool(
                64, pool_count=2, use_mlock=True, strict=True,
                backend=_AlwaysFailBackend(),
            )
