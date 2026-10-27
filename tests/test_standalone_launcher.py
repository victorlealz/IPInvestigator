from __future__ import annotations

import importlib.util
import os
from pathlib import Path


LAUNCHER = Path(__file__).resolve().parents[1] / "packaging" / "windows" / "standalone_launcher.py"
spec = importlib.util.spec_from_file_location("standalone_launcher", LAUNCHER)
launcher = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(launcher)


def test_requested_port_is_honored(monkeypatch):
    monkeypatch.setenv("IP_INVESTIGATOR_PORT", "45871")
    monkeypatch.setattr(launcher, "_port_is_available", lambda port: port == 45871)
    assert launcher._available_port() == 45871


def test_requested_port_must_be_numeric(monkeypatch):
    monkeypatch.setenv("IP_INVESTIGATOR_PORT", "abc")
    try:
        launcher._available_port()
    except RuntimeError as exc:
        assert "número inteiro" in str(exc)
    else:
        raise AssertionError("RuntimeError esperado")


def test_auto_port_uses_first_available(monkeypatch):
    monkeypatch.delenv("IP_INVESTIGATOR_PORT", raising=False)
    monkeypatch.setattr(launcher, "PORT_START", 10000)
    monkeypatch.setattr(launcher, "PORT_END", 10002)
    monkeypatch.setattr(launcher, "_port_is_available", lambda port: port == 10001)
    assert launcher._available_port() == 10001
