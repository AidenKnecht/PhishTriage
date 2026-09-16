from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLES = Path(__file__).parent.parent / "samples"


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def samples() -> Path:
    return SAMPLES


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any test that opens a real socket is a bug."""
    import socket

    def guard(*args: object, **kwargs: object) -> None:
        raise RuntimeError("network access attempted during tests")

    monkeypatch.setattr(socket.socket, "connect", guard)
