"""Session replay: parse an agentbox .ndjson log and emit a self-contained
HTML page that visualises every step, signal and session boundary.

Usage (Python API):
    from agentbox.replay import build_html
    html = build_html(Path("runs/my-session.ndjson"))
    Path("replay.html").write_text(html)

CLI usage:
    agentbox replay runs/my-session.ndjson            # writes replay.html next to the log
    agentbox replay runs/my-session.ndjson -o out.html
    agentbox replay runs/my-session.ndjson --open     # also opens in the browser
"""
from __future__ import annotations

import json
from pathlib import Path


# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------

def parse_log(path: Path) -> list[dict]:
    """Return a list of raw event dicts from *path* (one per line)."""
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                events.append(rec["event"])
            except (json.JSONDecodeError, KeyError):
                pass  # skip corrupt lines; integrity check is agentbox verify's job
    return events


def summarise(events: list[dict]) -> dict:
    """Derive high-level session stats from parsed events."""
    steps = [e for e in events if e["event_type"] == "step"]
    signals = [e for e in events if e["event_type"] == "analysis.signal"]
    start_ev = next((e for e in events if e["event_type"] == "session.start"), None)
    end_ev = next((e for e in events if e["event_type"] == "session.end"), None)
    invalid_ev = next((e for e in events if e["event_type"] == "session.invalid_reply"), None)

    ok = sum(1 for s in steps if s["data"].get("exit_code") == 0)
    fail = len(steps) - ok
    warn = sum(1 for s in signals if s["data"].get("severity") == "warn")
    crit = sum(1 for s in signals if s["data"].get("severity") == "critical")

    session_id = start_ev["data"].get("session_id", "unknown") if start_ev else "unknown"
    isolation = start_ev["data"].get("isolation", {}) if start_ev else {}
    end_reason = end_ev["data"].get("reason", "unknown") if end_ev else "unknown"

    duration_s = None
    if start_ev and end_ev:
        try:
            duration_s = round(end_ev["ts"] - start_ev["ts"], 1)
        except (KeyError, TypeError):
            pass

    return {
        "session_id": session_id,
        "isolation": isolation,
        "end_reason": end_reason,
        "invalid_reply": invalid_ev["data"] if invalid_ev else None,
        "total_steps": len(steps),
        "ok": ok,
        "fail": fail,
        "warn_signals": warn,
        "crit_signals": crit,
        "duration_s": duration_s,
    }


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

def _esc(text: str) -> str:
    """Minimal HTML escaping."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _step_card(ev: dict, signals_by_step: dict) -> str:
    d = ev["data"]
    idx = d.get("step_index", "?")
    cmd = _esc(d.get("command", ""))
    thought = _esc(d.get("thought", ""))
    exit_code = d.get("exit_code", "?")
    stdout = _esc(d.get("stdout", {}).get("text", "")[-2000:])
    stderr = _esc(d.get("stderr", {}).get("text", "")[-2000:])
    ok = exit_code == 0
    status_cls = "ok" if ok else "err"
    status_label = "✓ ok" if ok else f"✗ exit {exit_code}"

    sigs_html = ""
    for s in signals_by_step.get(idx, []):
        sev = s["data"].get("severity", "warn")
        kind = _esc(s["data"].get("kind", ""))
        hint = _esc(s["data"].get("hint", ""))
        count = s["data"].get("count", "")
        sev_cls = "sig-crit" if sev == "critical" else "sig-warn"
        sigs_html += (
            f'<div class="signal {sev_cls}">'
            f'<span class="sig-icon">{"🔴" if sev == "critical" else "⚠️"}</span>'
            f'<strong>{kind}</strong>'
            f'{" × " + str(count) if count else ""}'
            f'<span class="sig-hint"> — {hint}</span>'
            f"</div>"
        )

    thought_html = f'<div class="thought">💭 {thought}</div>' if thought else ""
    stdout_html = (
        f'<details class="output"><summary>stdout</summary><pre>{stdout}</pre></details>'
        if stdout.strip()
        else ""
    )
    stderr_html = (
        f'<details class="output"><summary>stderr</summary><pre>{stderr}</pre></details>'
        if stderr.strip()
        else ""
    )

    return f"""
<div class="step-card {status_cls}">
  <div class="step-header">
    <span class="step-num">Step {idx}</span>
    <span class="step-status {status_cls}">{status_label}</span>
  </div>
  {thought_html}
  <div class="command"><code>$ {cmd}</code></div>
  {sigs_html}
  {stdout_html}
  {stderr_html}
</div>"""


def build_html(path: Path) -> str:
    """Parse *path* and return a self-contained HTML replay page."""
    events = parse_log(path)
    summary = summarise(events)

    # Index signals by step_index for fast lookup.
    signals_by_step: dict[int, list] = {}
    for ev in events:
        if ev["event_type"] == "analysis.signal":
            idx = ev["data"].get("step_index")
            signals_by_step.setdefault(idx, []).append(ev)

    # Build step cards.
    steps_html = ""
    for ev in events:
        if ev["event_type"] == "step":
            steps_html += _step_card(ev, signals_by_step)

    if not steps_html:
        steps_html = '<p class="empty">No steps recorded in this session.</p>'

    # Summary badges.
    dur = f"{summary['duration_s']} s" if summary["duration_s"] is not None else "—"
    sandbox_label = summary["isolation"].get("backend", "local")
    reason_cls = "reason-ok" if summary["end_reason"] in ("done", "final_answer", "agent finished") else "reason-warn"
    invalid_banner = ""
    if summary["invalid_reply"]:
        ir = summary["invalid_reply"]
        invalid_banner = (
            f'<div class="invalid-banner">⛔ Session stopped due to repeated invalid replies. '
            f'Reason: <code>{_esc(ir.get("reason", ""))}</code> — '
            f'{_esc(ir.get("last_bad_reply", ""))}</div>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>agentbox replay — {_esc(summary["session_id"])}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  :root {{
    --bg: #0d1117;
    --surface: #161b22;
    --surface2: #1c2330;
    --border: #30363d;
    --accent: #58a6ff;
    --accent2: #3fb950;
    --danger: #f85149;
    --warn: #e3b341;
    --text: #e6edf3;
    --muted: #8b949e;
    --font: 'Inter', system-ui, sans-serif;
    --mono: 'JetBrains Mono', 'Fira Code', monospace;
  }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--font);
    font-size: 14px;
    line-height: 1.6;
    min-height: 100vh;
  }}

  /* ── Header ── */
  .header {{
    background: linear-gradient(135deg, #161b22 0%, #1a2332 100%);
    border-bottom: 1px solid var(--border);
    padding: 28px 40px 24px;
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 20px;
    flex-wrap: wrap;
  }}
  .header-left h1 {{
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: -0.02em;
  }}
  .header-left h1 span {{ color: var(--muted); font-weight: 400; }}
  .session-id {{
    font-family: var(--mono);
    font-size: 0.78rem;
    color: var(--muted);
    margin-top: 4px;
  }}

  /* ── Summary badges ── */
  .badges {{
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    align-items: center;
  }}
  .badge {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 4px 14px;
    font-size: 0.8rem;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
  }}
  .badge.ok   {{ border-color: #238636; color: var(--accent2); }}
  .badge.err  {{ border-color: #6e1a1a; color: var(--danger); }}
  .badge.warn {{ border-color: #6e5a1a; color: var(--warn); }}
  .badge.info {{ border-color: var(--border); color: var(--muted); }}

  /* ── Reason pill ── */
  .reason-pill {{
    display: inline-block;
    border-radius: 6px;
    padding: 3px 10px;
    font-size: 0.78rem;
    font-family: var(--mono);
    font-weight: 500;
  }}
  .reason-ok   {{ background: #1a3a1a; color: var(--accent2); }}
  .reason-warn {{ background: #3a1a1a; color: var(--danger); }}

  /* ── Timeline ── */
  .timeline-wrap {{
    max-width: 900px;
    margin: 0 auto;
    padding: 36px 24px 60px;
  }}
  .section-title {{
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 20px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
  }}

  /* ── Step card ── */
  .step-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 16px;
    overflow: hidden;
    transition: border-color 0.2s, box-shadow 0.2s;
    animation: fadeIn 0.3s ease both;
  }}
  .step-card:hover {{
    border-color: var(--accent);
    box-shadow: 0 0 0 1px rgba(88,166,255,0.15), 0 4px 20px rgba(0,0,0,0.4);
  }}
  .step-card.err  {{ border-left: 3px solid var(--danger); }}
  .step-card.ok   {{ border-left: 3px solid var(--accent2); }}

  .step-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 18px;
    background: var(--surface2);
    border-bottom: 1px solid var(--border);
  }}
  .step-num {{
    font-weight: 600;
    font-size: 0.85rem;
    color: var(--accent);
  }}
  .step-status {{
    font-family: var(--mono);
    font-size: 0.78rem;
    font-weight: 500;
    padding: 2px 10px;
    border-radius: 12px;
  }}
  .step-status.ok  {{ background: #1a3a1a; color: var(--accent2); }}
  .step-status.err {{ background: #3a1a1a; color: var(--danger); }}

  .thought {{
    padding: 10px 18px;
    font-size: 0.82rem;
    color: var(--muted);
    font-style: italic;
    border-bottom: 1px solid var(--border);
  }}
  .command {{
    padding: 12px 18px;
  }}
  .command code {{
    font-family: var(--mono);
    font-size: 0.85rem;
    color: #d2a8ff;
    background: #1a1020;
    padding: 8px 14px;
    border-radius: 6px;
    display: block;
    word-break: break-all;
    border: 1px solid #30203e;
  }}

  /* ── Signals ── */
  .signal {{
    display: flex;
    align-items: flex-start;
    gap: 8px;
    padding: 8px 18px;
    font-size: 0.8rem;
    border-top: 1px solid var(--border);
    animation: slideIn 0.2s ease both;
  }}
  .sig-warn {{ background: rgba(227,179,65,0.06); }}
  .sig-crit {{ background: rgba(248,81,73,0.08); }}
  .sig-icon {{ font-size: 1rem; flex-shrink: 0; }}
  .sig-hint  {{ color: var(--muted); }}

  /* ── Output details ── */
  details.output {{
    border-top: 1px solid var(--border);
  }}
  details.output summary {{
    padding: 8px 18px;
    cursor: pointer;
    font-size: 0.78rem;
    color: var(--muted);
    user-select: none;
    list-style: none;
    display: flex;
    align-items: center;
    gap: 6px;
  }}
  details.output summary::before {{ content: "▶"; font-size: 0.6rem; }}
  details.output[open] summary::before {{ content: "▼"; }}
  details.output summary:hover {{ color: var(--text); background: var(--surface2); }}
  details.output pre {{
    margin: 0;
    padding: 14px 18px;
    font-family: var(--mono);
    font-size: 0.78rem;
    color: #c9d1d9;
    background: #0d1117;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
    border-top: 1px solid var(--border);
  }}

  /* ── Invalid reply banner ── */
  .invalid-banner {{
    background: rgba(248,81,73,0.1);
    border: 1px solid rgba(248,81,73,0.4);
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 24px;
    font-size: 0.85rem;
    color: #f8a09b;
    line-height: 1.5;
  }}

  .empty {{ color: var(--muted); text-align: center; padding: 40px 0; }}

  /* ── Footer ── */
  .footer {{
    text-align: center;
    color: var(--muted);
    font-size: 0.75rem;
    padding: 24px;
    border-top: 1px solid var(--border);
    margin-top: 20px;
  }}
  .footer a {{ color: var(--accent); text-decoration: none; }}

  @keyframes fadeIn {{
    from {{ opacity: 0; transform: translateY(8px); }}
    to   {{ opacity: 1; transform: translateY(0); }}
  }}
  @keyframes slideIn {{
    from {{ opacity: 0; }}
    to   {{ opacity: 1; }}
  }}
</style>
</head>
<body>

<header class="header">
  <div class="header-left">
    <h1>agentbox <span>replay</span></h1>
    <div class="session-id">session: {_esc(summary["session_id"])}</div>
  </div>
  <div class="badges">
    <div class="badge info">🖥 {_esc(sandbox_label)}</div>
    <div class="badge info">⏱ {_esc(dur)}</div>
    <div class="badge info">📋 {summary["total_steps"]} steps</div>
    <div class="badge ok">✓ {summary["ok"]} ok</div>
    {f'<div class="badge err">✗ {summary["fail"]} failed</div>' if summary["fail"] else ""}
    {f'<div class="badge warn">⚠ {summary["warn_signals"]} warnings</div>' if summary["warn_signals"] else ""}
    {f'<div class="badge err">🔴 {summary["crit_signals"]} critical</div>' if summary["crit_signals"] else ""}
    <div class="badge info">stop: <span class="reason-pill {reason_cls}">{_esc(summary["end_reason"])}</span></div>
  </div>
</header>

<main class="timeline-wrap">
  {invalid_banner}
  <div class="section-title">Timeline</div>
  {steps_html}
</main>

<footer class="footer">
  Generated by <a href="https://github.com/Prathmesh010190/Agentboxx">agentbox</a> replay &middot;
  Use <code>agentbox verify {_esc(str(path.name))}</code> to check log integrity.
</footer>

</body>
</html>"""
