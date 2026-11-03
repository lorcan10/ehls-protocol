"""Integration boundaries for real crypto with simulated execution."""
import asyncio
import pytest
from ehls.simulator import SimulationManager, SimulationRequest, SessionCapacityError
from shared.secure_memory import SecureBuffer


def test_completion_reports_only_acknowledged_wiped_segments(monkeypatch):
    wiped = []
    original = SecureBuffer.release

    def release(self):
        original(self)
        assert bytes(self._buf) == bytes(self.size)
        wiped.append(True)

    monkeypatch.setattr(SecureBuffer, 'release', release)

    async def run():
        manager = SimulationManager(memory_lock=False)
        view = manager.create(SimulationRequest(segment_count=3, interval_ms=10))
        await manager._sessions[view.session_id].task
        completed = manager.get(view.session_id)
        assert completed.status == 'completed'
        assert completed.completed_segments == 3
        assert completed.progress == 100
        assert len(wiped) >= 3
        snapshot = completed.model_dump_json()
        for name in ['ciphertext', 'sender_key', 'receiver_key', 'plaintext', 'nonce']:
            assert name not in snapshot
        completed.status = 'failed'
        assert manager.get(view.session_id).status == 'completed'
        await manager.close()

    asyncio.run(run())


def test_cancel_during_segment_wipes_before_terminal_status(monkeypatch):
    wiped = []
    original = SecureBuffer.release

    def release(self):
        original(self)
        wiped.append(bytes(self._buf) == bytes(self.size))

    monkeypatch.setattr(SecureBuffer, 'release', release)

    async def run():
        manager = SimulationManager(memory_lock=False)
        view = manager.create(SimulationRequest(segment_count=5, interval_ms=5000))
        await asyncio.sleep(0.02)
        assert manager.get(view.session_id).status == 'streaming'
        manager.cancel(view.session_id)
        await asyncio.wait_for(manager._sessions[view.session_id].task, 1)
        view = manager.get(view.session_id)
        assert view.status == 'cancelled'
        assert view.completed_segments == 0
        assert wiped and all(wiped)
        await manager.close()

    asyncio.run(run())


def test_lock_failure_fails_closed(monkeypatch):
    class RefuseLock:
        name = 'test-refusal'
        def lock(self, addr, size): return False
        def unlock(self, addr, size): pass
    monkeypatch.setattr('gateway.memory_lock_backends.select_backend', lambda: RefuseLock())

    async def run():
        manager = SimulationManager(memory_lock=True)
        view = manager.create(SimulationRequest(segment_count=1, interval_ms=10))
        await manager._sessions[view.session_id].task
        failed = manager.get(view.session_id)
        assert failed.status == 'failed'
        assert failed.error == 'memory_lock_failed'
        assert failed.completed_segments == 0
        await manager.close()

    asyncio.run(run())


def test_invalid_delivery_signature_never_acknowledged(monkeypatch):
    import ehls.simulator as sim
    original = sim.serialize_packet

    def tamper(packet):
        if packet.packet_type.value == 'segment_delivery':
            packet.session_id = 'attacker-session'
        return original(packet)

    monkeypatch.setattr(sim, 'serialize_packet', tamper)

    async def run():
        manager = SimulationManager(memory_lock=False)
        view = manager.create(SimulationRequest(segment_count=1, interval_ms=10))
        await manager._sessions[view.session_id].task
        assert manager.get(view.session_id).status == 'failed'
        assert manager.get(view.session_id).completed_segments == 0
        await manager.close()

    asyncio.run(run())


def test_capacity_eviction_and_shutdown():
    async def run():
        manager = SimulationManager(memory_lock=False, max_sessions=1, max_active=1)
        first = manager.create(SimulationRequest(segment_count=1, interval_ms=10))
        with pytest.raises(SessionCapacityError):
            manager.create(SimulationRequest())
        await manager._sessions[first.session_id].task
        second = manager.create(SimulationRequest(segment_count=1, interval_ms=5000))
        with pytest.raises(KeyError):
            manager.get(first.session_id)
        await manager.close()
        assert not manager._sessions

    asyncio.run(run())


def test_expired_records_are_removed():
    async def run():
        manager = SimulationManager(memory_lock=False, retention_seconds=0)
        view = manager.create(SimulationRequest(segment_count=1, interval_ms=10))
        await manager._sessions[view.session_id].task
        with pytest.raises(KeyError):
            manager.get(view.session_id)
        await manager.close()

    asyncio.run(run())
