import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# main.py needs the service's runtime dependencies; skip where they are absent.
for _module in ("fastapi", "uvicorn", "schedule", "dotenv", "docker"):
    pytest.importorskip(_module)

import main


def test_http_api_has_no_state_changing_routes():
    # The server binds 0.0.0.0 without authentication, so it must stay read-only.
    methods = {m for route in main.app.routes for m in (getattr(route, "methods", None) or ())}
    assert "GET" in methods
    assert methods <= {"GET", "HEAD"}


def test_poll_loop_reconciles_when_flag_file_appears(tmp_path, monkeypatch):
    flag = tmp_path / "sync_enabled"
    reconcile_calls = []
    sleeps = []

    class _StopLoop(Exception):
        pass

    def fake_sleep(_seconds):
        sleeps.append(1)
        if len(sleeps) == 1:
            flag.touch()          # `cli.py enable-sync` creates the flag file
        elif len(sleeps) == 3:
            raise _StopLoop

    monkeypatch.setattr(main, "_sync_flag", flag)
    monkeypatch.setattr(main, "_run_reconcile", lambda r, d: reconcile_calls.append((r, d)))
    monkeypatch.setattr(main, "time", SimpleNamespace(sleep=fake_sleep))
    monkeypatch.setattr(main.schedule, "run_pending", lambda: None)

    try:
        with pytest.raises(_StopLoop):
            main._poll_loop("reconciler", "docker", 300)
    finally:
        main.schedule.clear()

    # One reconcile when the flag appeared, none while it stayed in place.
    assert reconcile_calls == [("reconciler", "docker")]
