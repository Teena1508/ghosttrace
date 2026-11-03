"""
Unit tests for the live device collector's resilience to real-world host data.
"""

import time

from investigation_engine import collector as collector_module
from investigation_engine.collector import LiveDeviceCollector


class _FakeProcess:
    def __init__(self, info):
        self.info = info


def test_long_command_line_is_clipped_not_fatal(monkeypatch):
    # Real apps (e.g. Electron helpers) can have command lines far over the 4096-char schema limit.
    long_args = ["/Applications/Example.app/Contents/MacOS/Helper"] + [f"--flag-{i}=value" for i in range(1000)]
    fake = _FakeProcess({
        "pid": 4242,
        "ppid": 1,
        "name": "Helper",
        "username": "tester",
        "cmdline": long_args,
        "create_time": time.time(),
        "exe": long_args[0],
        "status": "running",
    })
    monkeypatch.setattr(collector_module.psutil, "process_iter", lambda attrs=None: iter([fake]))

    events = LiveDeviceCollector()._collect_live_processes()

    assert len(events) == 1
    evt = events[0]
    assert len(evt.command_line) == 4096
    # Unclipped evidence is preserved for provenance
    assert evt.original_event_data["cmdline"] == long_args
