"""Unsafe ranges must never reach a native memory write; pool shutdown wipes all buffers."""
from unittest.mock import patch
import pytest
from shared.secure_memory import SecureBuffer, SecureBufferPool


@pytest.mark.parametrize('offset', [-1, -100, 0.5, True])
def test_invalid_write_offsets_rejected_before_native_call(offset):
    with SecureBuffer(16, use_mlock=False) as buf:
        with patch('shared.secure_memory.ctypes.memmove') as write:
            with pytest.raises(ValueError):
                buf.write(b'x', offset=offset)
            write.assert_not_called()


@pytest.mark.parametrize('length,offset', [(-1, 0), (1, -1), (None, -1), (None, 100), (1.5, 0)])
def test_invalid_reads_rejected(length, offset):
    with SecureBuffer(16, use_mlock=False) as buf:
        with pytest.raises(ValueError):
            buf.read(length=length, offset=offset)


@pytest.mark.parametrize('kwargs', [{'size': -1}, {'size': True}, {'size': 1.5},
                                   {'size': 16, 'overwrite_passes': -1}])
def test_invalid_buffer_construction_is_safe(kwargs):
    with pytest.raises(ValueError):
        SecureBuffer(**kwargs, use_mlock=False)


def test_pool_shutdown_wipes_checked_out_and_available_buffers():
    pool = SecureBufferPool(16, pool_count=2, use_mlock=False)
    active = pool.acquire()
    active.write(b'synthetic')
    available = pool._available[0]
    pool.release_all()
    for buf in [active, available]:
        assert bytes(buf._buf) == bytes(buf.size)
        with pytest.raises(RuntimeError):
            buf.read()
    assert not pool._in_use and not pool._available


def test_pool_rejects_double_returns_and_foreign_buffers():
    pool = SecureBufferPool(16, pool_count=1, use_mlock=False)
    buf = pool.acquire()
    pool.return_buffer(buf)
    with pytest.raises(ValueError):
        pool.return_buffer(buf)
    with SecureBuffer(16, use_mlock=False) as foreign:
        with pytest.raises(ValueError):
            pool.return_buffer(foreign)
    pool.release_all()
