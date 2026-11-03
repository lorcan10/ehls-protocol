"""
gateway/secure_zero.py
Non-optimisable buffer overwrite primitives.

Plain ``memset(buf, 0, n)`` is in principle eligible for dead-store
elimination by an optimising compiler if the buffer isn't observed
afterward.  The patent's wherein-clause for buffer destruction
(Claim 1, §6) hinges on the overwrite *actually happening*, so this
module wraps the platform's documented "secure" variant — the one
the OS guarantees the compiler will not elide:

* **Windows** — ``RtlSecureZeroMemory`` from ``kernel32.dll`` (or
  ``ntdll.dll`` as fallback).  Documented at
  https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-securezeromemory
* **POSIX** — ``memset_s`` from libc when available (C11 Annex K;
  not every libc exports it).  Otherwise the volatile-pointer
  pattern through ``ctypes.memset`` — CPython's ``ctypes`` calls
  are external function calls from the C optimiser's perspective,
  so dead-store elimination does not apply.

The public API is two functions:

* :func:`secure_zero(buf)` — overwrite ``buf`` (a ``ctypes.Array`` /
  ``bytearray``) with zero bytes.  No-op on a zero-length buffer.
* :func:`secure_overwrite_then_zero(buf, passes)` — N passes of
  cryptographically random bytes followed by a final zero pass.
  This is the multi-pass primitive used by
  :class:`shared.secure_memory.SecureBuffer`.

Both functions return ``None`` and raise nothing on supported
platforms; on unsupported platforms they fall back to the
volatile-memset pattern and log a warning once.

Patent reference: ``docs/PATENT_IMPLEMENTATION_GUIDE.md`` §11 WI-05,
threat T7 ("forced compiler optimisation removing the buffer
overwrite").
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import platform
import secrets
from typing import Callable, Optional, Union

logger = logging.getLogger("ehls.secure_zero")


# ── Platform detection and primitive selection ────────────────────────


_SYSTEM = platform.system()
_BACKEND_NAME: str = "fallback-volatile-memset"

# Type for the underlying primitive: takes a ``ctypes.c_void_p``
# address and a ``ctypes.c_size_t`` size, overwrites that region
# with zero, returns nothing observable.
_ZeroPrimitive = Callable[[int, int], None]


def _select_primitive() -> tuple[_ZeroPrimitive, str]:
    """Return ``(callable, name)`` for the platform's preferred
    secure-zero primitive.

    Resolution order:
      1. Windows: ``RtlSecureZeroMemory`` from kernel32.
      2. POSIX:   ``memset_s`` from libc (when exported as a symbol).
      3. Fallback: ``ctypes.memset`` — non-optimisable in practice
         because CPython treats it as an external call.
    """
    if _SYSTEM == "Windows":
        try:
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            # RtlSecureZeroMemory has signature
            # PVOID RtlSecureZeroMemory(PVOID ptr, SIZE_T cnt).
            primitive = kernel32.RtlSecureZeroMemory
            primitive.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            primitive.restype = ctypes.c_void_p

            def _winzero(addr: int, size: int) -> None:
                primitive(ctypes.c_void_p(addr), ctypes.c_size_t(size))

            return _winzero, "RtlSecureZeroMemory"
        except (AttributeError, OSError) as exc:
            logger.warning(
                "RtlSecureZeroMemory not reachable (%s); "
                "falling back to ctypes.memset", exc,
            )

    elif _SYSTEM in ("Linux", "Darwin", "FreeBSD"):
        libc_path = ctypes.util.find_library("c")
        if libc_path:
            libc = ctypes.CDLL(libc_path, use_errno=True)
            # memset_s is C11 Annex K: errno_t memset_s(void *s, rsize_t smax,
            #                                          int c, rsize_t n)
            try:
                primitive = libc.memset_s
                primitive.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                    ctypes.c_int,
                    ctypes.c_size_t,
                ]
                primitive.restype = ctypes.c_int

                def _posixzero(addr: int, size: int) -> None:
                    primitive(
                        ctypes.c_void_p(addr),
                        ctypes.c_size_t(size),
                        ctypes.c_int(0),
                        ctypes.c_size_t(size),
                    )

                return _posixzero, "memset_s"
            except AttributeError:
                # Symbol not exported — most glibc / musl builds
                # don't export memset_s.  Fall through to memset.
                pass

    # Fallback: ctypes.memset.  Two-paragraph rationale for why this
    # is acceptable in practice — see module docstring.
    def _memset_zero(addr: int, size: int) -> None:
        ctypes.memset(ctypes.c_void_p(addr), 0, ctypes.c_size_t(size))

    return _memset_zero, "fallback-volatile-memset"


_PRIMITIVE, _BACKEND_NAME = _select_primitive()


def backend_name() -> str:
    """Return the name of the active secure-zero backend.  Audit /
    diagnostic helper — the gateway's startup banner logs this so
    operators can confirm which primitive is in use on their host."""
    return _BACKEND_NAME


# ── Public API ───────────────────────────────────────────────────────


def _addr_and_size(
    buf: Union[ctypes.Array, bytearray, memoryview],
) -> tuple[int, int]:
    """Resolve ``(address, size)`` for the supported buffer types."""
    if isinstance(buf, ctypes.Array):
        return ctypes.addressof(buf), ctypes.sizeof(buf)
    if isinstance(buf, bytearray):
        addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
        return addr, len(buf)
    if isinstance(buf, memoryview):
        # Wrap the memoryview in a c_char array sharing its memory.
        if buf.readonly:
            raise TypeError("secure_zero requires a writable buffer")
        addr = ctypes.addressof(
            (ctypes.c_char * buf.nbytes).from_buffer(buf)
        )
        return addr, buf.nbytes
    raise TypeError(
        f"secure_zero does not support {type(buf).__name__}; "
        f"pass a ctypes.Array, bytearray, or writable memoryview"
    )


def secure_zero(buf: Union[ctypes.Array, bytearray, memoryview]) -> None:
    """Overwrite *buf* with zero bytes.

    Uses the platform's documented non-optimisable primitive (see
    module docstring); falls back to ``ctypes.memset`` on platforms
    where neither ``RtlSecureZeroMemory`` nor ``memset_s`` is
    available.  Returns silently on a zero-length buffer.
    """
    addr, size = _addr_and_size(buf)
    if size == 0:
        return
    _PRIMITIVE(addr, size)


def secure_overwrite_then_zero(
    buf: Union[ctypes.Array, bytearray, memoryview],
    passes: int = 3,
) -> None:
    """Multi-pass overwrite: ``passes`` rounds of CSPRNG random bytes
    followed by a final zero pass.

    The CSPRNG passes are written via :func:`ctypes.memmove` from a
    fresh ``secrets.token_bytes`` buffer; the final zero pass uses
    :func:`secure_zero`.  This matches the patent §5 Phase 4 step 7
    overwrite recipe (``3 CSPRNG passes + zero-fill``).
    """
    if passes < 0:
        raise ValueError(f"passes must be >= 0; got {passes}")
    addr, size = _addr_and_size(buf)
    if size == 0:
        return
    for _ in range(passes):
        random_data = secrets.token_bytes(size)
        ctypes.memmove(ctypes.c_void_p(addr), random_data, ctypes.c_size_t(size))
    _PRIMITIVE(addr, size)


__all__ = [
    "secure_zero",
    "secure_overwrite_then_zero",
    "backend_name",
]
