"""Synthetic fixtures for the standalone protocol test suite."""
import pytest
from shared.crypto import derive_session_key, generate_nonce

@pytest.fixture
def session_key():
    return derive_session_key("a" * 64, "b" * 64, generate_nonce(32), 1234567890.0)
