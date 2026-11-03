"""
shared/secure_memory.py
Volatile memory management: mlock/VirtualLock wrappers,
secure overwrite, and buffer lifecycle.
"""

from __future__ import annotations
import ctypes
import ctypes.util
import os
import platform
import secrets
import sys
from typing import Optional
import logging

logger = logging.getLogger("ehls.secure_memory")


__all__ = [
    "SecureBuffer",
    "SecureBufferPool",
    "SecureBufferLockError",
]

_SYSTEM = platform.system()


class SecureBufferLockError(RuntimeError):
    """Raised when a SecureBuffer's memory-locking syscall (mlock on
    Linux, VirtualLock on Windows) fails and the caller requested
    strict mode.  Patent Claim 3: the gateway agent refuses to
    receive, decrypt, or process any encrypted instruction data and
    terminates the session with a security error, without falling
    back to any alternative execution mode that does not provide
    memory-locking guarantees."""


# ─── Low-Level Locking ───────────────────────────────────────────────────────

if _SYSTEM == "Linux":
    _libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

    def _mlock(buf: ctypes.Array, size: int) -> bool:
        addr = ctypes.addressof(buf)
        ret = _libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
        if ret != 0:
            errno = ctypes.get_errno()
            logger.warning("mlock failed (errno=%d). Data may be swapped.", errno)
            return False
        return True

    def _munlock(buf: ctypes.Array, size: int) -> None:
        addr = ctypes.addressof(buf)
        _libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))

elif _SYSTEM == "Windows":
    _kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

    def _mlock(buf: ctypes.Array, size: int) -> bool:
        addr = ctypes.addressof(buf)
        ret = _kernel32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
        if ret == 0:
            logger.warning("VirtualLock failed. Data may be paged out.")
            return False
        return True

    def _munlock(buf: ctypes.Array, size: int) -> None:
        addr = ctypes.addressof(buf)
        _kernel32.VirtualUnlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))

else:
    def _mlock(buf: ctypes.Array, size: int) -> bool:
        logger.warning("Unsupported platform for memory locking: %s", _SYSTEM)
        return False

    def _munlock(buf: ctypes.Array, size: int) -> None:
        pass


# ─── Secure Buffer Class ─────────────────────────────────────────────────────

class SecureBuffer:
    """
    A fixed-size, memory-locked buffer that supports secure overwrite
    before deallocation.
    """

    def __init__(
        self,
        size: int,
        use_mlock: bool = True,
        overwrite_passes: int = 3,
        strict: bool = True,
        backend: object = None,
    ):
        """
        Parameters
        ----------
        strict:
            When ``True`` (the production default), an mlock /
            VirtualLock failure raises :class:`SecureBufferLockError`
            and the buffer is NOT created — implementing patent
            Claim 3's fail-closed requirement.  When ``False`` (test /
            unprivileged-CI mode), a lock failure logs a warning and
            proceeds with an unlocked buffer.  Ignored when
            ``use_mlock=False``.
        backend:
            Optional :class:`gateway.memory_lock_backends.MemoryLockBackend`
            instance.  When ``None`` (default), the platform default is
            chosen via ``select_backend()``.  High-assurance deployments
            inject a TEE backend (SGX / TrustZone / SEV-SNP — currently
            stubs, see :mod:`gateway.memory_lock_backends`) here.

            Lazy import to avoid an import cycle:
            ``gateway/`` depends on ``shared/`` for the buffer
            abstraction, so we resolve the default backend at
            construction time rather than at module load.
        """
        # Keep finalization safe if validation or allocation rejects construction.
        self._released = True
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError("size must be a non-negative integer")
        if (not isinstance(overwrite_passes, int) or isinstance(overwrite_passes, bool)
                or overwrite_passes < 0):
            raise ValueError("overwrite_passes must be a non-negative integer")
        self.size = size
        self._overwrite_passes = overwrite_passes
        self._buf: ctypes.Array = (ctypes.c_char * size)()
        self._locked = False
        self._released = False
        self._data_length = 0  # how many bytes are actually used
        self._backend = backend

        if use_mlock:
            if self._backend is None:
                # Lazy import — same pattern as secure_wipe uses for
                # gateway.secure_zero.
                from gateway.memory_lock_backends import select_backend
                self._backend = select_backend()
            addr = ctypes.addressof(self._buf)
            self._locked = self._backend.lock(addr, size)
            if not self._locked and strict:
                raise SecureBufferLockError(
                    f"Failed to lock {size}-byte buffer in memory "
                    f"(backend={self._backend.name!r}, platform={_SYSTEM}).  "
                    f"In strict mode the session is refused rather than "
                    f"falling back to an unlocked buffer.  Increase the OS "
                    f"mlock ulimit (Linux) or run with higher privileges "
                    f"(Windows), or pass ``strict=False`` only in dev / "
                    f"CI without privileges."
                )

    # ── Write / Read ──────────────────────────────────────────────────────

    def write(self, data: bytes, offset: int = 0) -> None:
        if self._released:
            raise RuntimeError("Buffer already released")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValueError("offset must be a non-negative integer")
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        end = offset + len(data)
        if end > self.size:
            raise OverflowError(f"Data ({end}B) exceeds buffer ({self.size}B)")
        ctypes.memmove(ctypes.addressof(self._buf) + offset, data, len(data))
        self._data_length = max(self._data_length, end)

    def read(self, length: Optional[int] = None, offset: int = 0) -> bytes:
        if self._released:
            raise RuntimeError("Buffer already released")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValueError("offset must be a non-negative integer")
        if length is None:
            length = self._data_length - offset
        if not isinstance(length, int) or isinstance(length, bool) or length < 0:
            raise ValueError("length must be a non-negative integer")
        if offset + length > self.size:
            raise OverflowError("Read exceeds buffer bounds")
        return bytes(self._buf[offset: offset + length])

    # ── Secure Overwrite & Release ────────────────────────────────────────

    def secure_wipe(self) -> None:
        """Overwrite buffer with N CSPRNG passes followed by a final
        zero pass.

        Delegates the actual writes to
        :func:`gateway.secure_zero.secure_overwrite_then_zero`, which
        selects the platform's non-optimisable primitive
        (``RtlSecureZeroMemory`` on Windows, ``memset_s`` on POSIX
        where exported, ``ctypes.memset`` otherwise).  The patent's
        Threat T7 ("forced compiler optimisation removing the buffer
        overwrite") is the reason the primitive selection lives in
        its own module — every caller that needs a guaranteed-not-
        elided overwrite goes through that single entry point.
        """
        if self._released:
            return
        # Local import to avoid a cycle: gateway/* depends on shared/*
        # for the buffer abstraction; the primitive itself is platform
        # code that doesn't need anything from shared/.
        from gateway.secure_zero import secure_overwrite_then_zero

        secure_overwrite_then_zero(self._buf, passes=self._overwrite_passes)
        self._data_length = 0

    def release(self) -> None:
        """Securely wipe, unlock, and mark as released."""
        if self._released:
            return
        self.secure_wipe()
        if self._locked:
            # Route through the backend selected at construction time.
            # The legacy ``_munlock`` helper at module scope still
            # exists for backwards compat with any external caller
            # that may have imported it directly, but is no longer
            # used internally.
            addr = ctypes.addressof(self._buf)
            self._backend.unlock(addr, self.size)
            self._locked = False
        self._released = True

    def __del__(self):
        self.release()

    # ── Context manager ───────────────────────────────────────────────────

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.release()
        return False


# ─── Pool of reusable secure buffers ─────────────────────────────────────────

class SecureBufferPool:
    """Pre-allocates a pool of SecureBuffers for reuse without reallocation."""

    def __init__(
        self,
        buffer_size: int,
        pool_count: int = 8,
        use_mlock: bool = True,
        overwrite_passes: int = 3,
        strict: bool = True,
        backend: object = None,
    ):
        """The optional ``backend`` parameter is forwarded to every
        :class:`SecureBuffer` the pool creates — both the
        pre-allocated batch and any later ``acquire()`` overflow.
        High-assurance deployments pass a TEE backend here once."""
        self._available: list[SecureBuffer] = []
        self._in_use: dict[int, SecureBuffer] = {}
        self._buffer_size = buffer_size
        self._use_mlock = use_mlock
        self._overwrite_passes = overwrite_passes
        self._strict = strict
        self._backend = backend
        for _ in range(pool_count):
            self._available.append(
                SecureBuffer(
                    buffer_size, use_mlock, overwrite_passes,
                    strict=strict, backend=backend,
                )
            )

    def acquire(self) -> SecureBuffer:
        if not self._available:
            buf = SecureBuffer(
                self._buffer_size, self._use_mlock,
                self._overwrite_passes, strict=self._strict,
                backend=self._backend,
            )
        else:
            buf = self._available.pop()
        self._in_use[id(buf)] = buf
        return buf

    def return_buffer(self, buf: SecureBuffer) -> None:
        if self._in_use.get(id(buf)) is not buf:
            raise ValueError("Buffer is not checked out from this pool")
        buf.secure_wipe()
        del self._in_use[id(buf)]
        if not buf._released:
            self._available.append(buf)

    def release_all(self) -> None:
        for buf in [*self._available, *self._in_use.values()]:
            buf.release()
        self._available.clear()
        self._in_use.clear()
