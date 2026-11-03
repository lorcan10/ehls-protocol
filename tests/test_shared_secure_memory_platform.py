"""
tests/test_shared_secure_memory_platform.py

Cross-platform smoke test for the platform-detection layer in
``shared/secure_memory.py``.

The high-level :class:`SecureBuffer` / :class:`SecureBufferPool`
abstractions are already exhaustively covered by
``tests/test_shared_secure_memory.py`` and
``tests/security/test_memory_lock_backends.py`` (those tests inject
fake backends to exercise the fail-closed path independent of the
underlying OS).

This file targets the lower layer: the ``_mlock`` / ``_munlock``
functions bound at module-import time based on
``platform.system()``.  Pinning that contract per-platform makes
sure a future Python or platform change can't silently turn the
buffer into a no-op without surfacing here first.

Properties pinned:

  * ``_SYSTEM`` is one of the recognised values.
  * ``_mlock`` and ``_munlock`` are callable on every platform
    (no ImportError fallthrough).
  * On Linux / Windows the platform-specific path was loaded
    (the libc / kernel32 reference exists at module scope).
  * A round-trip ``_mlock`` → ``_munlock`` call against a real
    ctypes buffer doesn't crash, regardless of whether the OS
    granted the lock (CI typically lacks ``CAP_IPC_LOCK``).
"""

from __future__ import annotations

import ctypes
import platform

import pytest

from shared import secure_memory


SYSTEM = platform.system()


def test_system_constant_recognised():
    """``_SYSTEM`` reflects the runtime platform.  If a future
    Python release renames the value (e.g. ``Darwin`` → ``macOS``),
    secure_memory's branching logic loads the wrong implementation
    silently — pin the constant once."""
    assert secure_memory._SYSTEM == SYSTEM
    # We don't require macOS support today (falls through to the
    # no-op branch), but the value must be one of the cases the
    # module knows about.
    assert SYSTEM in {"Linux", "Windows", "Darwin", "FreeBSD"} or \
           SYSTEM.startswith(("Linux", "Windows", "Darwin"))


def test_mlock_munlock_callable():
    """Whatever platform we're on, the bound functions exist and
    are callable.  An ``AttributeError`` here would mean the
    platform-detection cascade fell through without binding any
    implementation — which would silently turn every secure
    buffer into a no-op at runtime."""
    assert callable(secure_memory._mlock)
    assert callable(secure_memory._munlock)


@pytest.mark.skipif(SYSTEM != "Linux", reason="Linux-specific path")
def test_linux_libc_loaded():
    """The Linux branch loads the libc handle at import time;
    if it didn't, the mlock syscall would never reach the kernel."""
    assert hasattr(secure_memory, "_libc")
    assert secure_memory._libc is not None


@pytest.mark.skipif(SYSTEM != "Windows", reason="Windows-specific path")
def test_windows_kernel32_loaded():
    """The Windows branch loads the kernel32 handle at import
    time — VirtualLock / VirtualUnlock are routed through it."""
    assert hasattr(secure_memory, "_kernel32")
    assert secure_memory._kernel32 is not None


def test_mlock_munlock_does_not_crash_on_real_buffer():
    """Round-trip a real ctypes buffer through ``_mlock`` and
    ``_munlock``.  CI typically lacks the privilege to lock pages
    (CAP_IPC_LOCK on Linux, SeLockMemoryPrivilege on Windows), so
    the lock may return False — that's the contract.  What we
    pin here: neither call raises, the return type is bool, and
    the buffer is still readable afterward."""
    size = 256
    buf = (ctypes.c_char * size)()
    ctypes.memmove(buf, b"X" * size, size)

    locked = secure_memory._mlock(buf, size)
    assert isinstance(locked, bool)
    # _munlock has return type None; we just check it doesn't raise.
    secure_memory._munlock(buf, size)

    # Buffer still readable — the syscall round-trip must not have
    # mangled it.
    assert bytes(buf[:8]) == b"X" * 8


def test_unsupported_platform_branch_is_a_safe_noop():
    """On any platform other than Linux / Windows, ``_mlock``
    must return ``False`` (so strict-mode SecureBuffer rejects
    the session, fail-closed) and ``_munlock`` must be a no-op.

    We can't directly exercise the else-branch without
    monkey-patching the module, but we CAN verify its
    behavioural contract by inspecting the module-level
    fallback shape."""
    # The module installs platform-specific implementations at
    # import time.  On supported platforms (Linux/Windows) the
    # contract under test is that neither helper raises;
    # already covered above.  On unsupported platforms the
    # else-branch installs no-ops that we can describe via
    # public contract: _mlock returns False, _munlock returns None.
    if SYSTEM not in ("Linux", "Windows"):
        size = 16
        buf = (ctypes.c_char * size)()
        # Fallback _mlock returns False (per the source's else branch).
        assert secure_memory._mlock(buf, size) is False
        # Fallback _munlock has no observable effect; just must not raise.
        assert secure_memory._munlock(buf, size) is None
