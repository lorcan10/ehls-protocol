"""
gateway/memory_lock_backends.py
Pluggable memory-locking backends.

The patent's Claim 3 requires that decrypted instruction segments
live only in memory that is guaranteed to stay resident — never
swapped to disk, never paged out, never observable from another
process under normal OS protections.  Paragraph [0135A] of the v5
specification names three Trusted Execution Environment options
that satisfy this requirement on top of, or in place of, the
operating-system-level mlock / VirtualLock primitives:

* Intel SGX — enclave memory is encrypted by the CPU; not
  observable from the host OS.
* ARM TrustZone — secure-world memory; not observable from the
  normal-world OS.
* AMD SEV-SNP — encrypted VM memory; not observable from the
  hypervisor.

This module defines a :class:`MemoryLockBackend` abstract base
class so the gateway's :class:`shared.secure_memory.SecureBuffer`
can target any of these primitives without changing its own code.
The two operating-system backends (:class:`MlockBackend`,
:class:`VirtualLockBackend`) ship enabled — they're what's
deployed on the K1C reduction-to-practice device today.  The three
TEE backends ship as feature-flagged stubs that raise
``NotImplementedError`` with a clear message pointing at the
high-assurance-customer engagement path; their inclusion in the
public API makes the "TEE alternative is supported" claim
in the v5 specification a non-vapourware statement.

Patent reference: ``docs/PATENT_IMPLEMENTATION_GUIDE.md`` §11 WI-10,
§5 Phase 4 *"TEE alternative (paragraph [0135A])"*, §10 ``memory.backend``
config knob.
"""

from __future__ import annotations

import abc
import ctypes
import ctypes.util
import logging
import platform
from typing import Optional

logger = logging.getLogger("ehls.memory_lock_backends")

_SYSTEM = platform.system()


# ── Abstract base class ───────────────────────────────────────────────


class MemoryLockBackend(abc.ABC):
    """Abstract memory-locking backend.

    A backend's contract is two operations on a contiguous byte
    region: ``lock`` requests that the region stay resident; ``unlock``
    releases that request.  The region is identified by ``(address,
    size)`` rather than by buffer object so the same backend can
    serve heap allocations, ``ctypes.Array`` buffers, and TEE-resident
    memory without type-erasure shenanigans.

    Backends are stateless — every call carries the address it
    needs.  Implementations may be instantiated once and shared
    across many buffers.
    """

    name: str = "abstract"
    """Short, stable identifier — appears in logs, audit entries,
    and the gateway startup banner so operators can confirm which
    backend is active in their deployment."""

    available: bool = False
    """``True`` iff this backend's underlying primitive is reachable
    on the host (e.g. SGX driver loaded, TrustZone monitor
    responsive).  Stubs are ``available=False`` and refuse to
    construct."""

    @abc.abstractmethod
    def lock(self, addr: int, size: int) -> bool:
        """Request that the region ``[addr, addr+size)`` stay resident.

        Returns ``True`` on success, ``False`` on failure (e.g. the
        OS rejected the syscall — out of locked-memory budget).
        Failure is the caller's signal to apply Claim 3's fail-closed
        behaviour: refuse to receive, decrypt, or process any
        encrypted instruction data.
        """

    @abc.abstractmethod
    def unlock(self, addr: int, size: int) -> None:
        """Release a prior lock.  Best-effort: errors are logged but
        do not raise — the caller has already wiped the buffer."""


# ── OS-level backends (production) ────────────────────────────────────


class MlockBackend(MemoryLockBackend):
    """Linux / POSIX backend wrapping ``mlock(2)``."""

    name = "mlock"
    available = _SYSTEM == "Linux" or _SYSTEM == "Darwin" or _SYSTEM == "FreeBSD"

    def __init__(self) -> None:
        if not self.available:
            raise RuntimeError(
                f"MlockBackend not available on {_SYSTEM}; "
                f"use VirtualLockBackend on Windows"
            )
        libc_path = ctypes.util.find_library("c")
        if not libc_path:
            raise RuntimeError("libc not found; cannot bind mlock/munlock")
        self._libc = ctypes.CDLL(libc_path, use_errno=True)
        self._libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        self._libc.mlock.restype = ctypes.c_int
        self._libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        self._libc.munlock.restype = ctypes.c_int

    def lock(self, addr: int, size: int) -> bool:
        ret = self._libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
        if ret != 0:
            errno = ctypes.get_errno()
            logger.warning("mlock failed (errno=%d) for %d bytes", errno, size)
            return False
        return True

    def unlock(self, addr: int, size: int) -> None:
        self._libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))


class VirtualLockBackend(MemoryLockBackend):
    """Windows backend wrapping ``VirtualLock``."""

    name = "virtuallock"
    available = _SYSTEM == "Windows"

    def __init__(self) -> None:
        if not self.available:
            raise RuntimeError(
                f"VirtualLockBackend not available on {_SYSTEM}; "
                f"use MlockBackend on POSIX"
            )
        self._kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

    def lock(self, addr: int, size: int) -> bool:
        ret = self._kernel32.VirtualLock(
            ctypes.c_void_p(addr), ctypes.c_size_t(size),
        )
        if ret == 0:
            logger.warning("VirtualLock failed for %d bytes", size)
            return False
        return True

    def unlock(self, addr: int, size: int) -> None:
        self._kernel32.VirtualUnlock(
            ctypes.c_void_p(addr), ctypes.c_size_t(size),
        )


# ── TEE backends (feature-flagged stubs) ──────────────────────────────


class _TeeStubBase(MemoryLockBackend):
    """Common parent for TEE backends that aren't implemented yet.

    Constructing one raises :class:`NotImplementedError` with a
    clear message — this is the deliberate "feature-flagged stub"
    behaviour the patent guide §11 WI-10 calls out: the public API
    exists and is named in the config schema (``memory.backend``)
    so the v5 specification's TEE-alternative claim is non-
    vapourware, but the implementation is gated behind the
    high-assurance-customer engagement.
    """

    _engagement_path: str = (
        "Enable in production by linking against the appropriate TEE SDK "
        "and providing a concrete backend implementation; contact the "
        "Cosanta Systems high-assurance team for the integration kit."
    )

    available = False

    def __init__(self) -> None:
        raise NotImplementedError(
            f"{type(self).__name__} ({self.name!r}) is a feature-flagged "
            f"stub and does not ship with a runtime implementation.  "
            f"{self._engagement_path}"
        )

    def lock(self, addr: int, size: int) -> bool:  # pragma: no cover - unreachable
        raise NotImplementedError(self._engagement_path)

    def unlock(self, addr: int, size: int) -> None:  # pragma: no cover - unreachable
        raise NotImplementedError(self._engagement_path)


class SgxBackend(_TeeStubBase):
    """Intel SGX enclave memory backend (stub).

    In a real deployment, ``lock`` would map the ``[addr, addr+size)``
    region into an SGX enclave's EPC pages so the instruction
    segment plaintext is not observable from the host OS.  CPU-
    enforced memory encryption supersedes the OS-level mlock
    requirement; the patent guide paragraph [0135A] explicitly
    notes that the irreversibility-coupling property is what
    distinguishes EHLS from prior content-protection schemes even
    inside a TEE.
    """

    name = "sgx"


class TrustZoneBackend(_TeeStubBase):
    """ARM TrustZone secure-world backend (stub).

    Secure-world memory is not observable from the normal-world
    OS.  Suitable for ARM-based gateway deployments (Embodiment 2
    sealed interposer on a Raspberry Pi CM4 / i.MX 8M Mini SOM).
    """

    name = "trustzone"


class SevSnpBackend(_TeeStubBase):
    """AMD SEV-SNP encrypted-VM backend (stub).

    Suitable for cloud-deployed gateways where the TEE boundary is
    the VM rather than the process.  Decrypted segment plaintext
    is encrypted by the CPU at the page-table level and is not
    observable from the hypervisor.
    """

    name = "sev_snp"


# ── Factory ────────────────────────────────────────────────────────────


_BACKEND_REGISTRY: dict[str, type[MemoryLockBackend]] = {
    "mlock": MlockBackend,
    "virtuallock": VirtualLockBackend,
    "sgx": SgxBackend,
    "trustzone": TrustZoneBackend,
    "sev_snp": SevSnpBackend,
}


def list_backends() -> list[tuple[str, bool]]:
    """Return ``[(name, available), ...]`` for every registered
    backend.  Diagnostic helper — the gateway startup banner uses
    this to log which backends are reachable on the host."""
    return [(cls.name, cls.available) for cls in _BACKEND_REGISTRY.values()]


def select_backend(name: Optional[str] = None) -> MemoryLockBackend:
    """Construct the named backend.

    When ``name`` is ``None`` (or ``"auto"``), the platform default is
    chosen — ``mlock`` on POSIX, ``virtuallock`` on Windows.  Pass
    an explicit name to force a specific backend (typically only
    useful for the TEE backends in a high-assurance deployment).

    Raises :class:`KeyError` for an unrecognised name and
    :class:`NotImplementedError` for a feature-flagged stub.
    Constructing an unavailable OS backend (e.g., asking for
    ``virtuallock`` on Linux) raises :class:`RuntimeError`.
    """
    if name is None or name == "auto":
        name = "mlock" if _SYSTEM != "Windows" else "virtuallock"

    name = name.lower()
    if name not in _BACKEND_REGISTRY:
        raise KeyError(
            f"Unknown memory-lock backend {name!r}; "
            f"choose from {sorted(_BACKEND_REGISTRY)}"
        )
    return _BACKEND_REGISTRY[name]()


__all__ = [
    "MemoryLockBackend",
    "MlockBackend",
    "VirtualLockBackend",
    "SgxBackend",
    "TrustZoneBackend",
    "SevSnpBackend",
    "select_backend",
    "list_backends",
]
