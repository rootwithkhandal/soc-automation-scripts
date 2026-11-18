#!/usr/bin/env python3
"""
alert-dedup-engine.py — Alert Noise Reducer & Simple Deduplication Engine
========================================================================
SOC Automation Toolkit · Day 6

Ingests SIEM alert batches or streams (JSON, JSONL, CSV from Splunk/Elastic),
collapses repetitive duplicate alerts within sliding time windows, preserves
complete incident timelines (first/last seen), and re-scores priority based on
asset criticality tags.

Usage:
    python alert-dedup-engine.py siem_alerts.json
    python alert-dedup-engine.py alerts.csv --window 60 --output markdown -o ticket_batch.md
    python alert-dedup-engine.py alerts.json --assets asset_inventory.json --output json
    python alert-dedup-engine.py alerts.json --force-unique user --preserve-critical
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

# ── Optional UI dependency ────────────────────────────────────────

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH = True
except ImportError:
    RICH = False

# ── Constants ──────────────────────────────────────────────────────

VERSION = "1.0.0"
BANNER = f"alert-dedup-engine v{VERSION} — SOC Automation Toolkit · Day 6"

SEVERITY_LEVELS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

REVERSE_SEV = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}

SEVERITY_COLORS = {
    "critical": "red bold",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim white",
}

# Common SIEM field mappings
RULE_FIELDS = ["rule_name", "alert_name", "signal.rule.name", "search_name", "signature", "name", "title", "rule"]
HOST_FIELDS = ["host", "host.name", "dest", "dest_ip", "computer_name", "device_name", "target_host", "destination", "target"]
IOC_FIELDS = ["ioc", "src_ip", "source.ip", "ip", "source_ip", "src", "indicator", "attacker_ip", "remote_ip"]
USER_FIELDS = ["user", "user.name", "username", "account", "actor", "src_user", "target_user"]
SEV_FIELDS = ["severity", "signal.severity", "priority", "level", "alert_severity", "criticality"]
TIME_FIELDS = ["@timestamp", "_time", "timestamp", "time", "EventTime", "TimeCreated", "UtcTime"]


# ── Data Models ────────────────────────────────────────────────────

@dataclass(slots=True)
class RawAlert:
    """Normalized ingested SIEM alert."""
    timestamp: datetime
    rule_name: str
    host: str
    ioc: str
    user: str
    severity: str
    raw: dict


@dataclass(slots=True)
class DedupIncident:
    """Consolidated actionable incident representing N collapsed alerts."""
    incident_id: str
    rule_name: str
    host: str
    ioc: str
    users: list[str]
    severity: str
    original_severity: str
    asset_criticality: str
    count: int
    first_seen: str
    last_seen: str
    duration_seconds: int
    notes: list[str]
    sample_raw: dict

    def to_dict(self) -> dict:
        return asdict(self)


# ── Normalization Helpers ──────────────────────────────────────────

def _find_field(rec: dict, candidates: list[str], default: str = "") -> str:
    """Retrieve first matching field from disparate SIEM dictionary schemas."""
    for cand in candidates:
        if cand in rec and rec[cand] is not None and str(rec[cand]).strip() != "":
            return str(rec[cand]).strip()
    return default


def _parse_timestamp(ts: str) -> datetime:
    ts = ts.strip().rstrip("Z")
    try:
        dt = datetime.fromisoformat(ts)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%b %d %H:%M:%S"):
        try:
            dt = datetime.strptime(ts[:26], fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def normalize_alert(rec: dict) -> RawAlert:
    """Normalize vendor-specific alert into standard RawAlert structure."""
    rule_name = _find_field(rec, RULE_FIELDS, default="Generic SIEM Alert")
    host = _find_field(rec, HOST_FIELDS, default="UNKNOWN_HOST")
    ioc = _find_field(rec, IOC_FIELDS, default="—")
    user = _find_field(rec, USER_FIELDS, default="—")
    sev_raw = _find_field(rec, SEV_FIELDS, default="medium").lower()

    if sev_raw not in SEVERITY_LEVELS:
        if "crit" in sev_raw:
            sev_raw = "critical"
        elif "high" in sev_raw:
            sev_raw = "high"
        elif "med" in sev_raw:
            sev_raw = "medium"
        elif "low" in sev_raw:
            sev_raw = "low"
        else:
            sev_raw = "medium"

    ts_raw = _find_field(rec, TIME_FIELDS, default="")
    ts = _parse_timestamp(ts_raw) if ts_raw else datetime.now(timezone.utc)

    return RawAlert(
        timestamp=ts,
        rule_name=rule_name,
        host=host,
        ioc=ioc,
        user=user,
        severity=sev_raw,
        raw=rec,
    )


# ── Asset Inventory Loader ─────────────────────────────────────────

def load_asset_inventory(path: Path | None) -> dict[str, str]:
    """Load asset criticality tags (JSON or key=value / CSV)."""
    mapping: dict[str, str] = {}
    if not path or not path.exists():
        return mapping

    content = path.read_text(encoding="utf-8", errors="replace").strip()
    if content.startswith("{"):
        try:
            data = json.loads(content)
            for k, v in data.items():
                mapping[str(k).lower().strip()] = str(v).lower().strip()
            return mapping
        except json.JSONDecodeError:
            pass

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        sep = "=" if "=" in line else ("," if "," in line else ("\t" if "\t" in line else None))
        if sep:
            k, v = line.split(sep, 1)
            mapping[k.lower().strip()] = v.lower().strip()

    return mapping


# ── Deduplication Engine ──────────────────────────────────────────

def deduplicate_alerts(
    alerts: list[RawAlert],
    window_minutes: int = 30,
    asset_inventory: dict[str, str] | None = None,
    force_unique: list[str] | None = None,
    preserve_critical: bool = False,
) -> tuple[list[DedupIncident], dict]:
    """Group duplicate alerts within a sliding window and re-score based on asset criticality."""
    if not alerts:
        return [], {"total_alerts": 0, "incidents": 0, "reduction_percent": 0.0}

    asset_map = asset_inventory or {}
    force_fields = set(f.lower().strip() for f in (force_unique or []))
    window = timedelta(minutes=window_minutes)

    # Sort chronologically
    alerts_sorted = sorted(alerts, key=lambda a: a.timestamp)

    # Active incidents list
    active_incidents: list[dict] = []
    inc_counter = 1

    for a in alerts_sorted:
        host_norm = a.host.lower().strip()
        ioc_norm = a.ioc.lower().strip()
        rule_norm = a.rule_name.lower().strip()

        # Build group key
        key_parts = [rule_norm, host_norm, ioc_norm]
        for ff in sorted(force_fields):
            if ff == "user":
                key_parts.append(a.user.lower().strip())
            elif ff == "severity":
                key_parts.append(a.severity)
            elif ff in a.raw and a.raw[ff] is not None:
                key_parts.append(str(a.raw[ff]).lower().strip())
        group_key = tuple(key_parts)

        # Inversion safeguard: if preserve_critical is enabled, critical alerts are never collapsed
        is_isolated = preserve_critical and a.severity == "critical"

        matched_inc = None
        if not is_isolated:
            for inc in reversed(active_incidents):
                if inc["key"] == group_key:
                    if (a.timestamp - inc["last_ts"]) <= window:
                        matched_inc = inc
                        break

        if matched_inc:
            # Collapse into existing incident
            matched_inc["count"] += 1
            matched_inc["last_ts"] = a.timestamp
            if a.user and a.user != "—" and a.user not in matched_inc["users"]:
                matched_inc["users"].append(a.user)
            # Escalate severity if any subsequent alert has higher severity
            if SEVERITY_LEVELS.get(a.severity, 0) > SEVERITY_LEVELS.get(matched_inc["severity"], 0):
                matched_inc["severity"] = a.severity
        else:
            # Create new incident bucket
            inc_id = f"INC-{inc_counter:04d}"
            inc_counter += 1

            # Check asset criticality
            asset_crit = asset_map.get(host_norm) or asset_map.get(host_norm.split(".")[0], "unclassified")

            active_incidents.append({
                "id": inc_id,
                "key": group_key,
                "rule_name": a.rule_name,
                "host": a.host,
                "ioc": a.ioc,
                "users": [a.user] if a.user and a.user != "—" else [],
                "severity": a.severity,
                "original_severity": a.severity,
                "asset_criticality": asset_crit,
                "first_ts": a.timestamp,
                "last_ts": a.timestamp,
                "count": 1,
                "notes": [],
                "sample_raw": a.raw,
            })

    # Finalize incidents & apply asset criticality re-scoring
    results: list[DedupIncident] = []
    for inc in active_incidents:
        orig_sev = inc["original_severity"]
        curr_sev = inc["severity"]
        asset_crit = inc["asset_criticality"]
        notes = list(inc["notes"])

        # Asset criticality promotion
        if asset_crit == "critical" and curr_sev in ("medium", "low", "info"):
            curr_sev = "critical"
            notes.append(f"Severity promoted to CRITICAL: Target asset '{inc['host']}' is classified as CRITICAL infrastructure.")
        elif asset_crit == "high" and curr_sev in ("low", "medium"):
            curr_sev = "high"
            notes.append(f"Severity promoted to HIGH: Target asset '{inc['host']}' is classified as HIGH criticality.")
        elif asset_crit == "low" and curr_sev in ("low", "medium"):
            notes.append(f"Target asset '{inc['host']}' is tagged as LOW priority/test environment.")

        duration = int((inc["last_ts"] - inc["first_ts"]).total_seconds())

        results.append(DedupIncident(
            incident_id=inc["id"],
            rule_name=inc["rule_name"],
            host=inc["host"],
            ioc=inc["ioc"],
            users=inc["users"] or ["—"],
            severity=curr_sev,
            original_severity=orig_sev,
            asset_criticality=asset_crit,
            count=inc["count"],
            first_seen=inc["first_ts"].isoformat(),
            last_seen=inc["last_ts"].isoformat(),
            duration_seconds=duration,
            notes=notes,
            sample_raw=inc["sample_raw"],
        ))

    # Sort incidents: highest severity first, then by count descending
    results.sort(
        key=lambda i: (SEVERITY_LEVELS.get(i.severity, 0), i.count),
        reverse=True
    )

    total_in = len(alerts)
    total_out = len(results)
    reduction = ((total_in - total_out) / total_in * 100) if total_in > 0 else 0.0

    stats = {
        "total_alerts": total_in,
        "incidents": total_out,
        "reduction_percent": round(reduction, 1),
        "window_minutes": window_minutes,
    }

    return results, stats


# ── Ingest Parsers ─────────────────────────────────────────────────

def parse_alerts_json(path: Path) -> Iterator[RawAlert]:
    """Parse alerts from JSON array, JSON object container, or streaming JSONL."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        first_char = ""
        while True:
            ch = fh.read(1)
            if not ch:
                break
            if not ch.isspace():
                first_char = ch
                break
        fh.seek(0)

        if first_char == "[":
            records = json.load(fh)
            for r in records:
                if isinstance(r, dict):
                    yield normalize_alert(r)
        elif first_char == "{":
            # Check if it's a wrapped JSON container object
            content = fh.read(2048)
            fh.seek(0)
            if any(k in content for k in ('"alerts"', '"events"', '"incidents"', '"results"', '"hits"', '"signals"')):
                try:
                    obj = json.load(fh)
                    if isinstance(obj, dict):
                        for k in ("alerts", "incidents", "events", "results", "hits", "signals", "data"):
                            if k in obj and isinstance(obj[k], list):
                                for r in obj[k]:
                                    if isinstance(r, dict):
                                        yield normalize_alert(r)
                                return
                        yield normalize_alert(obj)
                        return
                except json.JSONDecodeError:
                    pass
            # Fallback to line-by-line JSONL streaming
            fh.seek(0)
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        r = json.loads(line)
                        if isinstance(r, dict):
                            yield normalize_alert(r)
                    except json.JSONDecodeError:
                        continue
        else:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        r = json.loads(line)
                        if isinstance(r, dict):
                            yield normalize_alert(r)
                    except json.JSONDecodeError:
                        continue


def parse_alerts_csv(path: Path) -> Iterator[RawAlert]:
    """Parse alerts from CSV file."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            yield normalize_alert(dict(row))


# ── Output Formatters ─────────────────────────────────────────────

def format_markdown_report(incidents: list[DedupIncident], stats: dict) -> str:
    """Format markdown report suitable for SOC ticket queues and documentation."""
    lines = [
        "## Alert Noise Reduction & Deduplication Report",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Original Raw Alerts:** {stats['total_alerts']:,}  ",
        f"**Actionable Incidents:** {stats['incidents']:,}  ",
        f"**Noise Reduction:** **{stats['reduction_percent']}%** (Window: {stats['window_minutes']} min)  ",
        "",
        "### Actionable Incident Queue",
        "| ID | Severity | Rule Name | Target Host | IOC | Count | First Seen | Last Seen |",
        "| :--- | :--- | :--- | :--- | :--- | :---: | :--- | :--- |",
    ]
    for inc in incidents:
        orig_note = f" *(was {inc.original_severity})*" if inc.severity != inc.original_severity else ""
        lines.append(
            f"| `{inc.incident_id}` | **{inc.severity.upper()}**{orig_note} | {inc.rule_name} | `{inc.host}` | `{inc.ioc}` | **{inc.count:,}** | {inc.first_seen} | {inc.last_seen} |"
        )

    lines.append("\n### Incident Detail Cards")
    for inc in incidents:
        lines.append(f"#### Incident `{inc.incident_id}`: {inc.rule_name}")
        lines.append(f"- **Target Asset:** `{inc.host}` (Criticality: `{inc.asset_criticality.upper()}`)")
        lines.append(f"- **Severity:** **{inc.severity.upper()}**" + (f" (Promoted from `{inc.original_severity.upper()}`)" if inc.severity != inc.original_severity else ""))
        lines.append(f"- **Alert Count:** Collapsed **{inc.count:,}** duplicate events (Timeline: {inc.first_seen} → {inc.last_seen})")
        lines.append(f"- **Associated IOC:** `{inc.ioc}` | **Users Involved:** {', '.join(f'`{u}`' for u in inc.users)}")
        if inc.notes:
            for n in inc.notes:
                lines.append(f"- ℹ️ {n}")
        lines.append("")

    return "\n".join(lines)


def format_table_output(incidents: list[DedupIncident], stats: dict) -> None:
    """Format terminal UI summary with Rich table or plain-text fallback."""
    if RICH:
        con = Console(stderr=True)
        con.print(Panel(f"[bold]{BANNER}[/bold]", box=box.ROUNDED))
        con.print(
            f"  Raw Alerts: [cyan]{stats['total_alerts']:,}[/cyan]  →  "
            f"Incidents: [green bold]{stats['incidents']:,}[/green bold]  |  "
            f"Noise Reduction: [bold green]{stats['reduction_percent']}%[/bold green] (Window: {stats['window_minutes']}m)\n"
        )
        if not incidents:
            con.print("[green]✓ No alerts to display.[/green]")
            return

        tbl = Table(box=box.SIMPLE_HEAVY, show_lines=True)
        tbl.add_column("ID", style="bold", width=9)
        tbl.add_column("Severity", justify="center")
        tbl.add_column("Rule & Host", style="cyan")
        tbl.add_column("IOC / Source", style="yellow")
        tbl.add_column("Count", justify="right", style="bold")
        tbl.add_column("Timeline (First → Last)", style="dim")
        tbl.add_column("Notes", max_width=35)

        for inc in incidents:
            sc = SEVERITY_COLORS.get(inc.severity, "white")
            sev_str = f"[{sc}]{inc.severity.upper()}[/{sc}]"
            if inc.severity != inc.original_severity:
                sev_str += f"\n[dim]({inc.original_severity})[/dim]"

            tbl.add_row(
                inc.incident_id,
                sev_str,
                f"{inc.rule_name}\n[bold]{inc.host}[/bold] ({inc.asset_criticality})",
                inc.ioc,
                str(inc.count),
                f"{inc.first_seen}\n→ {inc.last_seen}",
                "\n".join(inc.notes) if inc.notes else "-",
            )
        con.print(tbl)
    else:
        print(f"\n{'=' * 75}\n  {BANNER}")
        print(f"  Raw: {stats['total_alerts']:,} alerts → {stats['incidents']:,} incidents | Reduction: {stats['reduction_percent']}%")
        print(f"{'=' * 75}")
        for inc in incidents:
            print(f"\n  [{inc.incident_id}] {inc.severity.upper()} — {inc.rule_name} on {inc.host}")
            print(f"      Count:    {inc.count:,} alerts collapsed")
            print(f"      IOC:      {inc.ioc} | Users: {', '.join(inc.users)}")
            print(f"      Timeline: {inc.first_seen} → {inc.last_seen} ({inc.duration_seconds}s)")
            if inc.notes:
                for n in inc.notes:
                    print(f"      Note:     {n}")
        print()


# ── CLI ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="alert-dedup-engine",
        description=(
            "Ingest SIEM alert batches or streams, collapse repetitive duplicate alerts\n"
            "within sliding time windows, and re-score priority by asset criticality."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s siem_alerts.json\n"
            "  %(prog)s alerts.csv --window 60 --output markdown -o tickets.md\n"
            "  %(prog)s alerts.json --assets assets.json --output json\n"
            "  %(prog)s alerts.json --force-unique user --preserve-critical\n"
        ),
    )
    p.add_argument("logfile", type=Path, help="path to alerts file (JSON, JSONL, or CSV)")
    p.add_argument("-f", "--format", choices=["auto", "json", "csv"], default="auto",
                   help="input log format (default: auto-detect)")
    p.add_argument("-w", "--window", type=int, default=30, metavar="MINUTES",
                   help="sliding deduplication window in minutes (default: 30)")
    p.add_argument("--assets", type=Path, default=None, metavar="PATH",
                   help="asset criticality inventory file (JSON, CSV, or key=val)")
    p.add_argument("--force-unique", nargs="*", default=[], metavar="FIELD",
                   help="fields that force separate incidents (e.g. user, severity)")
    p.add_argument("--preserve-critical", action="store_true",
                   help="never collapse critical severity alerts with subsequent events")
    p.add_argument("--output", choices=["table", "markdown", "json"], default="table",
                   help="output format (default: table)")
    p.add_argument("-o", "--output-file", type=Path, default=None, metavar="PATH",
                   help="write report to destination file")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress headers and progress")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    logfile: Path = args.logfile

    if not logfile.exists():
        print(f"Error: file not found: {logfile}", file=sys.stderr)
        sys.exit(1)

    fmt = args.format
    if fmt == "auto":
        fmt = "csv" if logfile.suffix.lower() == ".csv" else "json"

    parse_fn = parse_alerts_csv if fmt == "csv" else parse_alerts_json

    if not args.quiet:
        print(f"\n  ⏳ Ingesting {logfile.name} (format: {fmt})...", file=sys.stderr)

    alerts = list(parse_fn(logfile))
    if not alerts:
        print(f"Error: No alerts found in {logfile.name}", file=sys.stderr)
        sys.exit(1)

    asset_map = load_asset_inventory(args.assets)
    if asset_map and not args.quiet:
        print(f"  ✓ Loaded asset inventory with {len(asset_map)} tagged assets", file=sys.stderr)

    incidents, stats = deduplicate_alerts(
        alerts,
        window_minutes=args.window,
        asset_inventory=asset_map,
        force_unique=args.force_unique,
        preserve_critical=args.preserve_critical,
    )

    match args.output:
        case "markdown":
            md = format_markdown_report(incidents, stats)
            if args.output_file:
                args.output_file.write_text(md, encoding="utf-8")
                if not args.quiet:
                    print(f"  ✓ Markdown report saved to {args.output_file}", file=sys.stderr)
            else:
                print(md)
        case "json":
            json_str = json.dumps({
                "tool": "alert-dedup-engine",
                "version": VERSION,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "summary": stats,
                "incidents": [inc.to_dict() for inc in incidents],
            }, indent=2)
            if args.output_file:
                args.output_file.write_text(json_str, encoding="utf-8")
                if not args.quiet:
                    print(f"  ✓ JSON pipeline output saved to {args.output_file}", file=sys.stderr)
            else:
                print(json_str)
        case _:
            if args.output_file:
                args.output_file.write_text(format_markdown_report(incidents, stats), encoding="utf-8")
            format_table_output(incidents, stats)

    if any(inc.severity == "critical" for inc in incidents):
        sys.exit(2)
    elif any(inc.severity == "high" for inc in incidents):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
