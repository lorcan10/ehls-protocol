"""
tests/security/test_memory_lock_backends.py
WI-10 coverage: pluggable memory-locking backend ABC + the three
TEE feature-flagged stubs.

Patent reference: ``docs/PATENT_IMPLEMENTATION_GUIDE.md`` §11 WI-10,
§5 Phase 4 paragraph [0135A].

These tests pin:
  * ABC contract — every backend exposes ``name``, ``available``,
    ``lock(addr, size)``, ``unlock(addr, size)``.
  * The platform-appropriate OS backend (mlock or virtuallock)
    constructs without error and round-trips a real lock /
    unlock on a small ctypes buffer.
  * The three TEE backends raise NotImplementedError on
    construction with a message that points at the high-assurance
    engagement path — protecting the v5 specification's TEE-
    alternative claim from regressing into vapourware.
  * The factory selects the platform default on ``select_backend()``
    /``"auto"`` and rejects unknown names.
"""

from __future__ import annotations

import ctypes
import platform

import pytest

from gateway.memory_lock_backends import (
    MemoryLockBackend,
    MlockBackend,
    SevSnpBackend,
    SgxBackend,
    TrustZoneBackend,
    VirtualLockBackend,
    list_backends,
    select_backend,
)


# ── ABC contract ─────────────────────────────────────────────────────


class TestAbcContract:
    def test_abc_cannot_be_instantiated(self):
        with pytest.raises(TypeError):
            MemoryLockBackend()  # type: ignore[abstract]

    def test_every_backend_exposes_required_attributes(self):
        for cls in (
            MlockBackend, VirtualLockBackend,
            SgxBackend, TrustZoneBackend, SevSnpBackend,
        ):
            assert isinstance(cls.name, str) and cls.name
            assert isinstance(cls.available, bool)
            assert hasattr(cls, "lock")
            assert hasattr(cls, "unlock")

    def test_backend_names_are_unique(self):
        names = [
            MlockBackend.name, VirtualLockBackend.name,
            SgxBackend.name, TrustZoneBackend.name, SevSnpBackend.name,
        ]
        assert len(names) == len(set(names))


# ── Platform OS backend round-trip ────────────────────────────────────


class TestPlatformOsBackend:
    def _platform_backend(self) -> MemoryLockBackend:
        if platform.system() == "Windows":
            return VirtualLockBackend()
        return MlockBackend()

    def test_construction_succeeds_on_native_platform(self):
        backend = self._platform_backend()
        assert backend.available is True
        assert backend.name in ("mlock", "virtuallock")

    def test_round_trip_lock_unlock_real_buffer(self):
        """Lock and unlock a small ctypes buffer.  The lock may
        fail at the OS level if the test runs without sufficient
        RLIMIT_MEMLOCK on Linux or without SeLockMemoryPrivilege on
        Windows — in that case the backend reports False rather than
        raising, so we assert the boolean contract rather than
        the syscall outcome."""
        backend = self._platform_backend()
        size = 4096
        buf = (ctypes.c_char * size)()
        addr = ctypes.addressof(buf)
        result = backend.lock(addr, size)
        # Whether the syscall succeeds depends on the test runner's
        # privileges; what matters is that lock returns a bool.
        assert isinstance(result, bool)
        # unlock must not raise even if lock returned False.
        backend.unlock(addr, size)

    def test_wrong_platform_backend_rejects_construction(self):
        if platform.system() == "Windows":
            with pytest.raises(RuntimeError, match="MlockBackend"):
                MlockBackend()
        else:
            with pytest.raises(RuntimeError, match="VirtualLockBackend"):
                VirtualLockBackend()


# ── TEE feature-flagged stubs ────────────────────────────────────────


class TestTeeStubs:
    @pytest.mark.parametrize("cls", [SgxBackend, TrustZoneBackend, SevSnpBackend])
    def test_construction_raises_not_implemented(self, cls):
        with pytest.raises(NotImplementedError) as exc_info:
            cls()
        msg = str(exc_info.value)
        # Message must point at the high-assurance engagement path —
        # this is what makes the stub a documented contract rather
        # than a confusing dead end.
        assert "stub" in msg
        assert "high-assurance" in msg

    def test_stub_names_match_config_schema(self):
        """The three TEE names appear in PATENT_IMPLEMENTATION_GUIDE
        §10 ``memory.backend`` config knob.  Pin them here so the
        config schema and the registry stay in lockstep."""
        assert SgxBackend.name == "sgx"
        assert TrustZoneBackend.name == "trustzone"
        assert SevSnpBackend.name == "sev_snp"

    def test_stubs_report_unavailable(self):
        """available=False distinguishes a stub from a real backend
        in the list_backends() diagnostic output."""
        for cls in (SgxBackend, TrustZoneBackend, SevSnpBackend):
            assert cls.available is False


# ── Factory ──────────────────────────────────────────────────────────


class TestSelectBackend:
    def test_default_returns_platform_appropriate_backend(self):
        backend = select_backend()
        if platform.system() == "Windows":
            assert isinstance(backend, VirtualLockBackend)
        else:
            assert isinstance(backend, MlockBackend)

    def test_auto_keyword_same_as_none(self):
        a = select_backend(None)
        b = select_backend("auto")
        assert type(a) is type(b)

    def test_explicit_native_name(self):
        if platform.system() == "Windows":
            backend = select_backend("virtuallock")
            assert isinstance(backend, VirtualLockBackend)
        else:
            backend = select_backend("mlock")
            assert isinstance(backend, MlockBackend)

    def test_case_insensitive(self):
        if platform.system() == "Windows":
            backend = select_backend("VirtualLock")
        else:
            backend = select_backend("Mlock")
        assert backend.available is True

    def test_tee_name_raises_not_implemented(self):
        with pytest.raises(NotImplementedError):
            select_backend("sgx")
        with pytest.raises(NotImplementedError):
            select_backend("trustzone")
        with pytest.raises(NotImplementedError):
            select_backend("sev_snp")

    def test_unknown_name_raises_key_error(self):
        with pytest.raises(KeyError, match="Unknown memory-lock backend"):
            select_backend("not_a_backend")

    def test_wrong_platform_os_backend_raises(self):
        """Asking for the other-platform OS backend explicitly must
        raise — never silently fall back."""
        if platform.system() == "Windows":
            with pytest.raises(RuntimeError):
                select_backend("mlock")
        else:
            with pytest.raises(RuntimeError):
                select_backend("virtuallock")


# ── Diagnostic helpers ───────────────────────────────────────────────


class TestListBackends:
    def test_returns_one_entry_per_backend(self):
        entries = list_backends()
        names = [name for (name, _) in entries]
        for expected in ("mlock", "virtuallock", "sgx", "trustzone", "sev_snp"):
            assert expected in names

    def test_only_one_os_backend_available_per_platform(self):
        """On any given host either mlock OR virtuallock is
        available, never both."""
        entries = dict(list_backends())
        if platform.system() == "Windows":
            assert entries["virtuallock"] is True
            assert entries["mlock"] is False
        else:
            assert entries["mlock"] is True
            assert entries["virtuallock"] is False

    def test_tee_backends_unavailable_in_default_build(self):
        """All three TEE backends ship as stubs; available=False is
        the documented contract.  This test catches a regression
        where a stub is accidentally enabled without an
        implementation behind it."""
        entries = dict(list_backends())
        assert entries["sgx"] is False
        assert entries["trustzone"] is False
        assert entries["sev_snp"] is False
