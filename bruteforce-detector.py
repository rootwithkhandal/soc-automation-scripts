#!/usr/bin/env python3
"""
brute_force_detector.py — Brute-Force & Credential-Stuffing Detector
=====================================================================
SOC Automation Toolkit · Day 1

Parses authentication logs and detects:
  • Brute-force: rapid failed logins against a single account
  • Credential stuffing: one IP targeting many distinct accounts

Supports: Windows EVTX (Event 4625/4624), Linux auth.log, JSON/JSONL, CSV

Usage:
    python brute_force_detector.py auth.evtx
    python brute_force_detector.py /var/log/auth.log --format authlog
    python brute_force_detector.py alerts.json --window 10 --ip-threshold 20
    python brute_force_detector.py events.csv --output json -o report.json
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator

# ── Optional deps (graceful fallback) ──────────────────────────────

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH = True
except ImportError:
    RICH = False

try:
    import Evtx.Evtx as evtx
    HAS_EVTX = True
except ImportError:
    HAS_EVTX = False

# ── Constants ──────────────────────────────────────────────────────

VERSION = "1.0.0"
BANNER = f"brute_force_detector v{VERSION} — SOC Automation Toolkit · Day 1"

WIN_LOGON_FAILURE = "4625"
WIN_LOGON_SUCCESS = "4624"

SEVERITY_THRESHOLDS = {1.0: "medium", 2.0: "high", 5.0: "critical"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_COLORS = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "green"}

WIN_NS = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

AUTHLOG_FAIL = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed\s+(?:password|publickey)\s+for\s+(?:invalid\s+user\s+)?"
    r"(?P<username>\S+)\s+from\s+(?P<ip>[\d.]+)"
)
AUTHLOG_SUCCESS = re.compile(
    r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted\s+\S+\s+for\s+(?P<username>\S+)\s+from\s+(?P<ip>[\d.]+)"
)

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")


# ── Data Models ────────────────────────────────────────────────────

@dataclass(slots=True)
class AuthEvent:
    """Normalized authentication event."""
    timestamp: datetime
    source_ip: str
    username: str
    success: bool
    log_source: str = ""


@dataclass(slots=True)
class Detection:
    """A detected brute-force or credential-stuffing incident."""
    detection_type: str
    source_ip: str
    target_accounts: list[str]
    failure_count: int
    unique_accounts: int
    window_start: str
    window_end: str
    severity: str
    details: str = ""


# ── Log Parsers ────────────────────────────────────────────────────

def parse_evtx(path: Path) -> Iterator[AuthEvent]:
    """Parse Windows EVTX file for logon events (4625/4624)."""
    if not HAS_EVTX:
        _die("python-evtx not installed. Run: pip install python-evtx")

    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
            except ET.ParseError:
                continue

            event_id = root.findtext(".//ns:EventID", namespaces=WIN_NS)
            if event_id not in (WIN_LOGON_FAILURE, WIN_LOGON_SUCCESS):
                continue

            data = {}
            for el in root.findall(".//ns:EventData/ns:Data", namespaces=WIN_NS):
                data[el.get("Name", "")] = el.text or ""

            tc = root.find(".//ns:System/ns:TimeCreated", namespaces=WIN_NS)
            ts_str = tc.get("SystemTime", "") if tc is not None else ""
            if not ts_str:
                continue

            try:
                timestamp = _parse_timestamp(ts_str)
            except ValueError:
                continue

            source_ip = data.get("IpAddress", "-")
            if source_ip in ("-", "", "::1", "127.0.0.1"):
                continue

            yield AuthEvent(
                timestamp=timestamp,
                source_ip=source_ip,
                username=data.get("TargetUserName", "UNKNOWN").lower(),
                success=(event_id == WIN_LOGON_SUCCESS),
                log_source="windows_evtx",
            )


def parse_authlog(path: Path) -> Iterator[AuthEvent]:
    """Parse Linux auth.log / sshd entries."""
    year = datetime.now().year
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            for pattern, success in [(AUTHLOG_SUCCESS, True), (AUTHLOG_FAIL, False)]:
                m = pattern.search(line)
                if m:
                    try:
                        ts = datetime.strptime(
                            f"{year} {m.group('timestamp')}", "%Y %b %d %H:%M:%S"
                        )
                    except ValueError:
                        continue
                    yield AuthEvent(
                        timestamp=ts,
                        source_ip=m.group("ip"),
                        username=m.group("username").lower(),
                        success=success,
                        log_source="linux_authlog",
                    )
                    break


def parse_json(path: Path) -> Iterator[AuthEvent]:
    """Parse JSON array or JSONL authentication events."""
    # shortcut: loads full JSON array into memory, switch to ijson if files exceed 200MB
    content = path.read_text(encoding="utf-8", errors="replace").strip()
    if content.startswith("["):
        records = json.loads(content)
    else:
        records = []
        for line in content.splitlines():
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    for rec in records:
        event = _normalize_record(rec)
        if event:
            yield event


def parse_csv_log(path: Path) -> Iterator[AuthEvent]:
    """Parse CSV authentication logs."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            event = _normalize_record(dict(row))
            if event:
                yield event


def _normalize_record(rec: dict) -> AuthEvent | None:
    """Normalize a dict record into an AuthEvent."""
    ts_raw = (
        rec.get("timestamp") or rec.get("@timestamp") or
        rec.get("EventTime") or rec.get("_time") or
        rec.get("TimeCreated") or rec.get("UtcTime") or ""
    )
    if not ts_raw:
        return None
    try:
        timestamp = _parse_timestamp(str(ts_raw))
    except ValueError:
        return None

    source_ip = (
        rec.get("source_ip") or rec.get("src_ip") or
        rec.get("IpAddress") or rec.get("SourceAddress") or
        rec.get("src") or rec.get("SourceIP") or ""
    )
    if not source_ip or source_ip in ("-", "::1", "127.0.0.1"):
        return None

    username = str(
        rec.get("username") or rec.get("user") or
        rec.get("TargetUserName") or rec.get("Account") or "UNKNOWN"
    ).lower()

    event_id = str(rec.get("EventID", rec.get("event_id", "")))
    status = str(
        rec.get("status", rec.get("event_type", rec.get("Keywords", "")))
    ).lower()

    if event_id == WIN_LOGON_FAILURE:
        success = False
    elif event_id == WIN_LOGON_SUCCESS:
        success = True
    elif "fail" in status or "denied" in status:
        success = False
    elif "success" in status or "accept" in status:
        success = True
    else:
        success = False

    return AuthEvent(
        timestamp=timestamp, source_ip=str(source_ip),
        username=username, success=success, log_source="json",
    )


# ── Detection Engine ──────────────────────────────────────────────

def detect(
    events: list[AuthEvent],
    window_minutes: int = 5,
    ip_threshold: int = 10,
    user_threshold: int = 5,
    account_threshold: int = 10,
    cooloff_minutes: int = 30,
    allowlist_ips: set[str] | None = None,
    allowlist_users: set[str] | None = None,
) -> list[Detection]:
    """Run sliding-window detection over sorted events."""
    allowlist_ips = allowlist_ips or set()
    allowlist_users = allowlist_users or set()
    events.sort(key=lambda e: e.timestamp)

    ip_failures: dict[str, list[AuthEvent]] = defaultdict(list)
    acct_failures: dict[str, list[AuthEvent]] = defaultdict(list)
    ip_last_success: dict[str, datetime] = {}

    for ev in events:
        if ev.source_ip in allowlist_ips or ev.username in allowlist_users:
            continue
        if ev.success:
            ip_last_success[ev.source_ip] = ev.timestamp
            continue
        last_ok = ip_last_success.get(ev.source_ip)
        if last_ok and (ev.timestamp - last_ok) < timedelta(minutes=cooloff_minutes):
            continue
        ip_failures[ev.source_ip].append(ev)
        acct_failures[ev.username].append(ev)

    detections: list[Detection] = []
    seen_keys: set[tuple[str, str]] = set()  # (type_prefix, key) to deduplicate
    window = timedelta(minutes=window_minutes)

    for ip, fails in ip_failures.items():
        for w in _first_window_above(fails, window, ip_threshold, user_threshold):
            users = {e.username for e in w}
            if len(users) >= user_threshold:
                detections.append(Detection(
                    detection_type="credential_stuffing", source_ip=ip,
                    target_accounts=sorted(users), failure_count=len(w),
                    unique_accounts=len(users),
                    window_start=w[0].timestamp.isoformat(),
                    window_end=w[-1].timestamp.isoformat(),
                    severity=_severity(len(users), user_threshold),
                    details=f"{len(users)} distinct accounts in {window_minutes}min",
                ))
                # Mark accounts as seen so per-account loop skips them
                for u in users:
                    seen_keys.add(("acct", u))
            else:
                detections.append(Detection(
                    detection_type="brute_force", source_ip=ip,
                    target_accounts=sorted(users), failure_count=len(w),
                    unique_accounts=len(users),
                    window_start=w[0].timestamp.isoformat(),
                    window_end=w[-1].timestamp.isoformat(),
                    severity=_severity(len(w), ip_threshold),
                    details=f"{len(w)} failures in {window_minutes}min",
                ))
                for u in users:
                    seen_keys.add(("acct", u))
            break  # one detection per IP

    for acct, fails in acct_failures.items():
        if ("acct", acct) in seen_keys:
            continue  # already reported via the IP-level detection
        for w in _first_window_above(fails, window, account_threshold):
            ips = {e.source_ip for e in w}
            detections.append(Detection(
                detection_type="brute_force_account",
                source_ip=", ".join(sorted(ips)[:5]),
                target_accounts=[acct], failure_count=len(w),
                unique_accounts=1,
                window_start=w[0].timestamp.isoformat(),
                window_end=w[-1].timestamp.isoformat(),
                severity=_severity(len(w), account_threshold),
                details=f"Account '{acct}' hit {len(w)}x from {len(ips)} IPs",
            ))
            break

    detections.sort(key=lambda d: SEVERITY_ORDER.get(d.severity, 99))
    return detections


def _first_window_above(
    events: list[AuthEvent],
    window: timedelta,
    count_threshold: int,
    user_threshold: int = 0,
) -> Iterator[list[AuthEvent]]:
    """Yield the first window that crosses either threshold, then stop."""
    i = 0
    while i < len(events):
        w_end = events[i].timestamp + window
        j = i
        while j < len(events) and events[j].timestamp <= w_end:
            j += 1
        w = events[i:j]
        users = {e.username for e in w} if user_threshold else set()
        if len(w) >= count_threshold or (user_threshold and len(users) >= user_threshold):
            yield w
            return
        i = j if j > i else i + 1


def _severity(value: int, threshold: int) -> str:
    ratio = value / threshold
    result = "low"
    for mult, sev in sorted(SEVERITY_THRESHOLDS.items()):
        if ratio >= mult:
            result = sev
    return result


# ── Allowlist ──────────────────────────────────────────────────────

def load_allowlist(path: Path | None) -> tuple[set[str], set[str]]:
    """Load allowlist: one entry per line, IPs and usernames auto-detected."""
    ips, users = set(), set()
    if not path or not path.exists():
        return ips, users
    for line in path.read_text().splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        if _IP_RE.match(entry):
            ips.add(entry)
        else:
            users.add(entry.lower())
    return ips, users


# ── Output Formatters ─────────────────────────────────────────────

def output_table(detections: list[Detection], total: int, failures: int) -> None:
    if RICH:
        _rich_table(detections, total, failures)
    else:
        _plain_table(detections, total, failures)


def _rich_table(detections: list[Detection], total: int, failures: int) -> None:
    con = Console(stderr=True)
    con.print(Panel(f"[bold]{BANNER}[/bold]", box=box.ROUNDED))
    con.print(
        f"  Events: [cyan]{total:,}[/cyan]  |  "
        f"Failures: [yellow]{failures:,}[/yellow]  |  "
        f"Detections: [red bold]{len(detections)}[/red bold]\n"
    )
    if not detections:
        con.print("[green]✓ No brute-force activity detected.[/green]")
        return

    tbl = Table(box=box.SIMPLE_HEAVY, show_lines=True)
    tbl.add_column("#", style="dim", width=3)
    tbl.add_column("Type", style="bold")
    tbl.add_column("Source IP", style="cyan")
    tbl.add_column("Targets", style="yellow")
    tbl.add_column("Fails", justify="right")
    tbl.add_column("Window", style="dim")
    tbl.add_column("Severity")

    for i, d in enumerate(detections, 1):
        targets = ", ".join(d.target_accounts[:3])
        if len(d.target_accounts) > 3:
            targets += f" (+{len(d.target_accounts) - 3})"
        sc = SEVERITY_COLORS.get(d.severity, "white")
        tbl.add_row(
            str(i), d.detection_type.replace("_", " ").title(),
            d.source_ip, targets, str(d.failure_count),
            f"{d.window_start}\n→ {d.window_end}",
            f"[{sc}]{d.severity.upper()}[/{sc}]",
        )
    con.print(tbl)


def _plain_table(detections: list[Detection], total: int, failures: int) -> None:
    print(f"\n{'=' * 70}\n  {BANNER}")
    print(f"  Events: {total:,}  |  Failures: {failures:,}  |  Detections: {len(detections)}")
    print(f"{'=' * 70}")
    if not detections:
        print("\n  ✓ No brute-force activity detected.\n")
        return
    for i, d in enumerate(detections, 1):
        print(f"\n  [{i}] {d.detection_type.replace('_', ' ').upper()}")
        print(f"      IP:       {d.source_ip}")
        print(f"      Targets:  {', '.join(d.target_accounts[:5])}")
        print(f"      Failures: {d.failure_count}")
        print(f"      Window:   {d.window_start} → {d.window_end}")
        print(f"      Severity: {d.severity.upper()}")
    print()


def output_json(detections: list[Detection], total: int, failures: int) -> str:
    return json.dumps({
        "tool": "brute_force_detector", "version": VERSION,
        "generated_at": datetime.now().isoformat(),
        "summary": {"total_events": total, "total_failures": failures,
                     "detections": len(detections)},
        "detections": [asdict(d) for d in detections],
    }, indent=2)


def output_csv_str(detections: list[Detection]) -> str:
    if not detections:
        return ""
    buf = io.StringIO()
    fields = list(asdict(detections[0]).keys())
    writer = csv.DictWriter(buf, fieldnames=fields)
    writer.writeheader()
    for d in detections:
        row = asdict(d)
        row["target_accounts"] = "; ".join(row["target_accounts"])
        writer.writerow(row)
    return buf.getvalue()


def _write_output(content: str, path: Path | None, quiet: bool) -> None:
    """Write content to file or stdout."""
    if path:
        path.write_text(content)
        if not quiet:
            print(f"  ✓ Written to {path}", file=sys.stderr)
    else:
        print(content)


# ── Utilities ──────────────────────────────────────────────────────

def _parse_timestamp(ts: str) -> datetime:
    ts = ts.strip().rstrip("Z")
    # Fast path: ISO 8601 covers ~95% of real log timestamps
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(ts[:26], fmt)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse timestamp: {ts!r}")


def _detect_format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".evtx":
        return "evtx"
    if suffix in (".json", ".jsonl"):
        return "json"
    if suffix == ".csv":
        return "csv"
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:1024]
    except Exception:
        return "json"
    if head.lstrip().startswith(("{", "[")):
        return "json"
    if AUTHLOG_FAIL.search(head) or AUTHLOG_SUCCESS.search(head):
        return "authlog"
    return "json"


def _die(msg: str) -> None:
    print(f"\n  ✗ Error: {msg}\n", file=sys.stderr)
    sys.exit(1)


# ── CLI ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="brute_force_detector",
        description=(
            "Detect brute-force and credential-stuffing attacks in "
            "authentication logs.\n\n"
            "Supports Windows EVTX (4625/4624), Linux auth.log, JSON/JSONL, CSV."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s security.evtx\n"
            "  %(prog)s auth.log --format authlog --window 10\n"
            "  %(prog)s logins.json --ip-threshold 20 --output json\n"
            "  %(prog)s events.csv --allowlist trusted.txt -o report.json\n"
        ),
    )
    p.add_argument("logfile", type=Path, help="log file to analyze")
    p.add_argument("-f", "--format", choices=["auto", "evtx", "authlog", "json", "csv"],
                   default="auto", help="log format (default: auto-detect)")
    p.add_argument("-w", "--window", type=int, default=5, metavar="MIN",
                   help="sliding window in minutes (default: 5)")
    p.add_argument("--ip-threshold", type=int, default=10, metavar="N",
                   help="failures per IP to flag (default: 10)")
    p.add_argument("--user-threshold", type=int, default=5, metavar="N",
                   help="distinct users per IP for credential stuffing (default: 5)")
    p.add_argument("--account-threshold", type=int, default=10, metavar="N",
                   help="failures per account to flag (default: 10)")
    p.add_argument("--cooloff", type=int, default=30, metavar="MIN",
                   help="ignore IP for N min after success (default: 30)")
    p.add_argument("--allowlist", type=Path, default=None, metavar="FILE",
                   help="allowed IPs/usernames file (one per line)")
    p.add_argument("--output", choices=["table", "json", "csv"], default="table",
                   help="output format (default: table)")
    p.add_argument("-o", "--output-file", type=Path, default=None, metavar="PATH",
                   help="write results to file")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress banner and progress")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    logfile: Path = args.logfile

    if not logfile.exists():
        _die(f"File not found: {logfile}")

    fmt = args.format if args.format != "auto" else _detect_format(logfile)
    parsers = {"evtx": parse_evtx, "authlog": parse_authlog,
               "json": parse_json, "csv": parse_csv_log}
    parse_fn = parsers.get(fmt)
    if not parse_fn:
        _die(f"Unknown format: {fmt}")

    if not args.quiet:
        print(f"\n  ⏳ Parsing {logfile.name} (format: {fmt})...", file=sys.stderr)

    events = list(parse_fn(logfile))
    if not events:
        _die(f"No authentication events found in {logfile.name}")

    total = len(events)
    failures = sum(1 for e in events if not e.success)
    if not args.quiet:
        print(f"  ✓ {total:,} events ({failures:,} failures)", file=sys.stderr)

    al_ips, al_users = load_allowlist(args.allowlist)
    if (al_ips or al_users) and not args.quiet:
        print(f"  ✓ Allowlist: {len(al_ips)} IPs, {len(al_users)} users", file=sys.stderr)

    detections = detect(
        events, window_minutes=args.window, ip_threshold=args.ip_threshold,
        user_threshold=args.user_threshold, account_threshold=args.account_threshold,
        cooloff_minutes=args.cooloff, allowlist_ips=al_ips, allowlist_users=al_users,
    )

    match args.output:
        case "json":
            _write_output(output_json(detections, total, failures),
                          args.output_file, args.quiet)
        case "csv":
            _write_output(output_csv_str(detections),
                          args.output_file, args.quiet)
        case _:
            if args.output_file:
                _write_output(output_json(detections, total, failures),
                              args.output_file, args.quiet)
            output_table(detections, total, failures)

    if any(d.severity in ("critical", "high") for d in detections):
        sys.exit(2)
    elif detections:
        sys.exit(1)


if __name__ == "__main__":
    main()
