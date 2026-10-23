"""Tests for agentbox.replay — no network, no API key, no Docker."""
import json
import time
from pathlib import Path

import pytest

from agentbox.replay import build_html, parse_log, summarise


# ---------------------------------------------------------------------------
# Helpers to build minimal valid .ndjson log fixtures
# ---------------------------------------------------------------------------

def _make_record(seq: int, prev_hash: str, event_type: str, data: dict) -> dict:
    event = {
        "schema_version": "0.1",
        "event_id": f"fake-{seq:04d}",
        "event_type": event_type,
        "ts": time.time() + seq,
        "seq": seq,
        "data": data,
    }
    return {"event": event, "prev_hash": prev_hash, "hash": f"hash{seq:04d}", "sig": "sig"}


def _write_log(path: Path, records: list[dict]) -> Path:
    """Write a list of record dicts as ndjson."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    return path


def _minimal_log(tmp_path: Path, steps: list[dict] | None = None) -> Path:
    """Build a minimal log with a start, optional steps, and end record."""
    recs = []
    seq = 1

    recs.append(_make_record(seq, "0" * 64, "session.start", {
        "session_id": "test-session-abc",
        "isolation": {"backend": "docker"},
    }))
    seq += 1

    for i, step_data in enumerate(steps or [], start=1):
        recs.append(_make_record(seq, f"hash{seq-1:04d}", "step", {
            "step_index": i,
            "command": step_data.get("command", f"echo step{i}"),
            "thought": step_data.get("thought", ""),
            "exit_code": step_data.get("exit_code", 0),
            "stdout": {"text": step_data.get("stdout", "")},
            "stderr": {"text": step_data.get("stderr", "")},
        }))
        seq += 1

    recs.append(_make_record(seq, f"hash{seq-1:04d}", "session.end", {
        "reason": "done",
        "steps": len(steps or []),
    }))

    return _write_log(tmp_path / "test-session.ndjson", recs)


# ===========================================================================
# parse_log
# ===========================================================================

def test_parse_log_returns_events(tmp_path):
    log = _minimal_log(tmp_path, steps=[{"command": "ls", "exit_code": 0}])
    events = parse_log(log)
    types = [e["event_type"] for e in events]
    assert "session.start" in types
    assert "step" in types
    assert "session.end" in types


def test_parse_log_skips_corrupt_lines(tmp_path):
    log = tmp_path / "corrupt.ndjson"
    log.write_text('{"event": {"schema_version":"0.1","event_id":"x","event_type":"session.start","ts":1,"seq":1,"data":{}},"prev_hash":"0","hash":"h","sig":"s"}\n'
                   'THIS IS NOT JSON\n'
                   '{"event": {"schema_version":"0.1","event_id":"y","event_type":"session.end","ts":2,"seq":2,"data":{"reason":"done"}},"prev_hash":"h","hash":"h2","sig":"s"}\n',
                   encoding="utf-8")
    events = parse_log(log)
    # Corrupt line is silently skipped; we still get start + end.
    assert len(events) == 2


def test_parse_log_empty_file(tmp_path):
    log = tmp_path / "empty.ndjson"
    log.write_text("", encoding="utf-8")
    events = parse_log(log)
    assert events == []


# ===========================================================================
# summarise
# ===========================================================================

def test_summarise_basic(tmp_path):
    log = _minimal_log(tmp_path, steps=[
        {"command": "ls", "exit_code": 0},
        {"command": "cat missing.txt", "exit_code": 1},
    ])
    events = parse_log(log)
    s = summarise(events)
    assert s["session_id"] == "test-session-abc"
    assert s["total_steps"] == 2
    assert s["ok"] == 1
    assert s["fail"] == 1
    assert s["end_reason"] == "done"
    assert s["isolation"] == {"backend": "docker"}


def test_summarise_no_steps(tmp_path):
    log = _minimal_log(tmp_path, steps=[])
    events = parse_log(log)
    s = summarise(events)
    assert s["total_steps"] == 0
    assert s["ok"] == 0
    assert s["fail"] == 0


def test_summarise_counts_signals(tmp_path):
    """Signals appended after a step are counted correctly."""
    log = _minimal_log(tmp_path, steps=[{"command": "echo x", "exit_code": 0}])
    # Manually append a signal record.
    sig_record = _make_record(99, "hash0099", "analysis.signal", {
        "step_index": 1,
        "severity": "warn",
        "kind": "loop.exact",
        "hint": "change approach",
        "count": 3,
    })
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps(sig_record) + "\n")

    events = parse_log(log)
    s = summarise(events)
    assert s["warn_signals"] == 1
    assert s["crit_signals"] == 0


def test_summarise_invalid_reply(tmp_path):
    log = _minimal_log(tmp_path, steps=[])
    ir_record = _make_record(99, "hash0002", "session.invalid_reply", {
        "reason": "invalid_reply",
        "last_bad_reply": "missing 'command' or 'final'",
    })
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps(ir_record) + "\n")

    events = parse_log(log)
    s = summarise(events)
    assert s["invalid_reply"] is not None
    assert s["invalid_reply"]["reason"] == "invalid_reply"


# ===========================================================================
# build_html
# ===========================================================================

def test_build_html_returns_string(tmp_path):
    log = _minimal_log(tmp_path, steps=[{"command": "echo hello", "exit_code": 0}])
    html = build_html(log)
    assert isinstance(html, str)
    assert len(html) > 500


def test_build_html_contains_session_id(tmp_path):
    log = _minimal_log(tmp_path, steps=[])
    html = build_html(log)
    assert "test-session-abc" in html


def test_build_html_contains_all_commands(tmp_path):
    steps = [
        {"command": "ls -la", "exit_code": 0},
        {"command": "python3 fib.py", "exit_code": 0},
        {"command": "cat missing.txt", "exit_code": 1},
    ]
    log = _minimal_log(tmp_path, steps=steps)
    html = build_html(log)
    for step in steps:
        assert step["command"] in html


def test_build_html_escapes_xss(tmp_path):
    """Malicious command content must be HTML-escaped."""
    log = _minimal_log(tmp_path, steps=[{
        "command": '<script>alert("xss")</script>',
        "exit_code": 0,
    }])
    html = build_html(log)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_build_html_invalid_reply_banner(tmp_path):
    log = _minimal_log(tmp_path, steps=[])
    ir_record = _make_record(99, "hash0002", "session.invalid_reply", {
        "reason": "invalid_reply",
        "last_bad_reply": "missing 'command' or 'final'",
    })
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps(ir_record) + "\n")

    html = build_html(log)
    assert "invalid-banner" in html
    assert "invalid_reply" in html


def test_build_html_empty_session(tmp_path):
    """A log with no steps must not crash and must show the empty message."""
    log = _minimal_log(tmp_path, steps=[])
    html = build_html(log)
    assert "No steps recorded" in html


def test_build_html_stdout_stderr_in_output(tmp_path):
    log = _minimal_log(tmp_path, steps=[{
        "command": "echo hello world",
        "exit_code": 0,
        "stdout": "hello world\n",
        "stderr": "",
    }])
    html = build_html(log)
    assert "hello world" in html


# ===========================================================================
# CLI integration
# ===========================================================================

def test_cli_replay_writes_html(tmp_path):
    """agentbox replay <logfile> should produce a .html file."""
    from agentbox.cli import cmd_replay

    log = _minimal_log(tmp_path, steps=[{"command": "ls", "exit_code": 0}])
    out_html = tmp_path / "out.html"

    class FakeArgs:
        logfile = str(log)
        output = str(out_html)
        open = False

    rc = cmd_replay(FakeArgs())
    assert rc == 0
    assert out_html.exists()
    content = out_html.read_text(encoding="utf-8")
    assert "agentbox" in content.lower()


def test_cli_replay_missing_logfile(tmp_path):
    from agentbox.cli import cmd_replay

    class FakeArgs:
        logfile = str(tmp_path / "does-not-exist.ndjson")
        output = None
        open = False

    rc = cmd_replay(FakeArgs())
    assert rc == 1
