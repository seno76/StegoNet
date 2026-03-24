"""Report generation for session statistics.

Supports JSON, CSV, and HTML output formats.
"""

import csv
import io
import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

from netstego.stats.db import PacketLog, SessionRecord, init_db

console = Console()


def get_session_data(db_path: str | None, session_id: str) -> dict:
    """Fetch session and packet data from database.

    Args:
        db_path: Path to stats database.
        session_id: Session ID to query.

    Returns:
        Dict with 'session' and 'packets' keys.
    """
    factory = init_db(db_path)
    with factory() as db:
        session = db.query(SessionRecord).filter_by(session_id=session_id).first()
        packets = (
            db.query(PacketLog)
            .filter_by(session_id=session_id)
            .order_by(PacketLog.seq)
            .all()
        )
        return {
            "session": session,
            "packets": packets,
        }


def _session_to_dict(s: SessionRecord) -> dict:
    """Convert session ORM object to dict."""
    return {
        "session_id": s.session_id,
        "direction": s.direction,
        "channel": s.channel,
        "dest_ip": s.dest_ip,
        "bind_ip": s.bind_ip,
        "file_size": s.file_size,
        "total_packets": s.total_packets,
        "total_chunks": s.total_chunks,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "finished_at": s.finished_at.isoformat() if s.finished_at else None,
        "status": s.status,
    }


def export_json(db_path: str | None, session_id: str, output: Path) -> None:
    """Export session data as JSON."""
    data = get_session_data(db_path, session_id)
    session = data["session"]
    packets = data["packets"]

    result = {
        "session": _session_to_dict(session) if session else None,
        "packets": [
            {
                "seq": p.seq,
                "timestamp": p.timestamp,
                "field_name": p.field_name,
                "field_value": p.field_value,
                "packet_size": p.packet_size,
            }
            for p in packets
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2))
    console.print(f"[dim]JSON report saved to {output}[/dim]")


def export_csv(db_path: str | None, session_id: str, output: Path) -> None:
    """Export packet log as CSV."""
    data = get_session_data(db_path, session_id)
    packets = data["packets"]

    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["seq", "timestamp", "field_name", "field_value", "packet_size"])
        for p in packets:
            writer.writerow([p.seq, p.timestamp, p.field_name, p.field_value, p.packet_size])
    console.print(f"[dim]CSV report saved to {output}[/dim]")


def export_html(db_path: str | None, session_id: str, output: Path) -> None:
    """Export session data as an HTML report."""
    data = get_session_data(db_path, session_id)
    session = data["session"]
    packets = data["packets"]

    session_info = _session_to_dict(session) if session else {}

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>NetStego Report — {session_id}</title>
<style>
body {{ font-family: monospace; margin: 2em; background: #1e1e1e; color: #d4d4d4; }}
h1 {{ color: #569cd6; }}
table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
th, td {{ border: 1px solid #444; padding: 6px 10px; text-align: left; }}
th {{ background: #2d2d2d; color: #9cdcfe; }}
tr:nth-child(even) {{ background: #252526; }}
.meta {{ background: #2d2d2d; padding: 1em; margin: 1em 0; border-radius: 4px; }}
.ok {{ color: #4ec9b0; }} .fail {{ color: #f44747; }}
</style></head><body>
<h1>NetStego Session Report</h1>
<div class="meta">
<p><b>Session ID:</b> {session_info.get('session_id', 'N/A')}</p>
<p><b>Direction:</b> {session_info.get('direction', 'N/A')}</p>
<p><b>Channel:</b> {session_info.get('channel', 'N/A')}</p>
<p><b>Status:</b> <span class="{'ok' if session_info.get('status') == 'completed' else 'fail'}">{session_info.get('status', 'N/A')}</span></p>
<p><b>File Size:</b> {session_info.get('file_size', 'N/A')} bytes</p>
<p><b>Packets:</b> {session_info.get('total_packets', 'N/A')}</p>
<p><b>Started:</b> {session_info.get('started_at', 'N/A')}</p>
<p><b>Finished:</b> {session_info.get('finished_at', 'N/A')}</p>
</div>
<h2>Packet Log ({len(packets)} entries)</h2>
<table>
<tr><th>#</th><th>Seq</th><th>Timestamp</th><th>Field</th><th>Value</th><th>Size</th></tr>
"""
    for i, p in enumerate(packets[:500]):  # Limit to 500 rows
        html += f"<tr><td>{i}</td><td>{p.seq}</td><td>{p.timestamp:.6f}</td>"
        html += f"<td>{p.field_name or ''}</td><td>{p.field_value or ''}</td>"
        html += f"<td>{p.packet_size or ''}</td></tr>\n"

    if len(packets) > 500:
        html += f'<tr><td colspan="6">... and {len(packets) - 500} more rows</td></tr>\n'

    html += "</table></body></html>"

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")
    console.print(f"[dim]HTML report saved to {output}[/dim]")


def print_table(db_path: str | None, session_id: str | None = None) -> None:
    """Print session(s) as a rich table to console."""
    factory = init_db(db_path)
    with factory() as db:
        if session_id:
            sessions = db.query(SessionRecord).filter_by(session_id=session_id).all()
        else:
            sessions = (
                db.query(SessionRecord)
                .order_by(SessionRecord.started_at.desc())
                .limit(20)
                .all()
            )

    if not sessions:
        console.print("[yellow]No sessions found.[/yellow]")
        return

    table = Table(title="NetStego Sessions")
    table.add_column("Session ID")
    table.add_column("Direction")
    table.add_column("Channel")
    table.add_column("Packets")
    table.add_column("Status")
    table.add_column("Started")

    for s in sessions:
        style = "green" if s.status == "completed" else "yellow"
        table.add_row(
            s.session_id,
            s.direction,
            s.channel,
            str(s.total_packets or "?"),
            f"[{style}]{s.status}[/{style}]",
            s.started_at.strftime("%Y-%m-%d %H:%M") if s.started_at else "?",
        )
    console.print(table)
