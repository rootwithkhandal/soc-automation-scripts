#!/usr/bin/env python3
"""
process-anomaly-detector.py — Sysmon / Endpoint Process Anomaly Spotter
======================================================================
SOC Automation Toolkit · Day 5

Monitors or batch-processes Sysmon Event ID 1 (Process Creation) logs:
  • Frequency-based baselining of (parent_image, image, user) triplets
  • Shannon entropy and obfuscated/encoded command line detection
  • Processes executing from user-writable / temp paths
  • Living-off-the-land (LOLBIN) suspicious parent-child relationships
  • System binary masquerading (e.g. svchost.exe outside System32)
  • Nightly baseline persistence (--save-baseline / --load-baseline)

Usage:
    python process-anomaly-detector.py sysmon.json
    python process-anomaly-detector.py sysmon.evtx --format evtx
    python process-anomaly-detector.py events.json --save-baseline baseline.json
    python process-anomaly-detector.py new_events.json --load-baseline baseline.json --output markdown
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import math
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
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

try:
    import Evtx.Evtx as evtx
    HAS_EVTX = True
except ImportError:
    HAS_EVTX = False

# ── Constants ──────────────────────────────────────────────────────

VERSION = "1.0.0"
BANNER = f"process-anomaly-detector v{VERSION} — SOC Automation Toolkit · Day 5"

WIN_NS = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
SYSMON_PROCESS_CREATE = "1"

# Core Windows system binaries that must reside in System32 / Windows
SYSTEM_BINARIES = {
    "svchost.exe": ["system32", "syswow64"],
    "lsass.exe": ["system32"],
    "csrss.exe": ["system32"],
    "smss.exe": ["system32"],
    "services.exe": ["system32"],
    "wininit.exe": ["system32"],
    "winlogon.exe": ["system32"],
    "taskhostw.exe": ["system32"],
    "explorer.exe": ["windows"],
}

# Suspicious parent processes spawning shells or LOLBINs
SUSPICIOUS_PARENTS = {
    # Office
    "winword.exe": ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "rundll32.exe"],
    "excel.exe": ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "rundll32.exe"],
    "powerpnt.exe": ["cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe"],
    "outlook.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
    # Web & Database services
    "w3wp.exe": ["cmd.exe", "powershell.exe", "whoami.exe", "net.exe"],
    "httpd.exe": ["cmd.exe", "powershell.exe", "sh", "bash"],
    "nginx.exe": ["cmd.exe", "powershell.exe", "sh", "bash"],
    "sqlservr.exe": ["cmd.exe", "powershell.exe", "whoami.exe"],
    # System / Service anomalies
    "spoolsv.exe": ["cmd.exe", "powershell.exe"],
}

WRITABLE_PATH_PATTERNS = [
    re.compile(r"[\\/]appdata[\\/]local[\\/]temp", re.IGNORECASE),
    re.compile(r"[\\/]windows[\\/]temp", re.IGNORECASE),
    re.compile(r"[\\/]programdata[\\/][^\\/]+\.exe$", re.IGNORECASE),
    re.compile(r"[\\/]users[\\/][^\\/]+[\\/]downloads", re.IGNORECASE),
    re.compile(r"^/(?:tmp|dev/shm|var/tmp)/", re.IGNORECASE),
]

SEVERITY_COLORS = {
    "critical": "red bold",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
}


# ── Data Models ────────────────────────────────────────────────────

@dataclass(slots=True)
class ProcessEvent:
    """Normalized process creation event."""
    timestamp: datetime
    host: str
    user: str
    parent_path: str
    image_path: str
    command_line: str
    process_id: str = ""
    parent_process_id: str = ""
    process_guid: str = ""
    parent_process_guid: str = ""
    log_source: str = "json"


@dataclass(slots=True)
class AnomalyHit:
    """An outlier process creation detection."""
    timestamp: str
    host: str
    user: str
    parent_image: str
    image_path: str
    command_line: str
    anomaly_score: int
    severity: str
    reasons: list[str]
    entropy: float
    frequency: int

    def to_dict(self) -> dict:
        return asdict(self)


# ── Heuristic & Metric Functions ───────────────────────────────────

def _basename(path: str) -> str:
    """Extract filename from path in Windows or POSIX format."""
    return path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower() if path else ""


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def is_temp_or_writable_path(path: str) -> bool:
    """Check if the process executable runs from a temporary/user-writable path."""
    p_norm = path.lower()
    return any(bool(pat.search(p_norm)) for pat in WRITABLE_PATH_PATTERNS)


def is_masquerading(image_path: str) -> bool:
    """Detect core Windows system binaries running outside expected system directories."""
    bname = _basename(image_path)
    if bname not in SYSTEM_BINARIES:
        return False
    path_norm = image_path.lower().replace("/", "\\")
    allowed_dirs = SYSTEM_BINARIES[bname]
    return not any(f"\\{allowed}\\" in path_norm for allowed in allowed_dirs)


# ── Frequency Baseline ─────────────────────────────────────────────

class ProcessBaseline:
    """Frequency-based baseline for parent-child execution profiling."""

    def __init__(self, min_frequency: int = 3):
        self.min_frequency = min_frequency
        self.counts: dict[str, int] = defaultdict(int)

    def _key(self, parent: str, image: str, user: str) -> str:
        # Normalize user by stripping domain prefix (e.g. CORP\alice -> alice)
        u_norm = user.lower().strip().split("\\")[-1]
        return f"{_basename(parent)}|{_basename(image)}|{u_norm}"

    def observe(self, parent: str, image: str, user: str) -> None:
        self.counts[self._key(parent, image, user)] += 1

    def is_known(self, parent: str, image: str, user: str) -> bool:
        return self.counts.get(self._key(parent, image, user), 0) >= self.min_frequency

    def get_frequency(self, parent: str, image: str, user: str) -> int:
        return self.counts.get(self._key(parent, image, user), 0)

    def save(self, path: Path) -> None:
        data = {
            "version": VERSION,
            "min_frequency": self.min_frequency,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "total_profiles": len(self.counts),
            "counts": self.counts,
        }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> ProcessBaseline:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        bl = cls(min_frequency=data.get("min_frequency", 3))
        bl.counts = defaultdict(int, data.get("counts", {}))
        return bl


# ── Anomaly Detection Engine ──────────────────────────────────────

def detect_anomalies(
    events: list[ProcessEvent],
    baseline: ProcessBaseline | None = None,
    min_baseline_frequency: int = 3,
    min_score_threshold: int = 30,
) -> list[AnomalyHit]:
    """Score process creations against heuristics and baseline frequency."""
    bl = baseline
    if bl is None:
        # Build baseline from dataset if no pre-existing baseline was supplied
        bl = ProcessBaseline(min_frequency=min_baseline_frequency)
        for ev in events:
            bl.observe(ev.parent_path, ev.image_path, ev.user)

    hits: list[AnomalyHit] = []

    for ev in events:
        reasons: list[str] = []
        score = 0

        parent_bname = _basename(ev.parent_path)
        image_bname = _basename(ev.image_path)
        freq = bl.get_frequency(ev.parent_path, ev.image_path, ev.user)

        # 1. Rare parent-child relationship check
        if freq < bl.min_frequency:
            score += 30
            reasons.append(f"Rare parent-child tuple (seen {freq}x, min={bl.min_frequency}): {parent_bname} → {image_bname}")

        # 2. Known LOLBIN / Suspicious parent check
        if parent_bname in SUSPICIOUS_PARENTS:
            targets = SUSPICIOUS_PARENTS[parent_bname]
            if image_bname in targets:
                score += 45
                reasons.append(f"Suspicious LOLBIN spawn: {parent_bname} spawned {image_bname}")

        # 3. System binary masquerading check
        if is_masquerading(ev.image_path):
            score += 55
            reasons.append(f"System binary masquerade: {image_bname} executing outside legitimate system path")

        # 4. User-writable or temp path execution
        if is_temp_or_writable_path(ev.image_path):
            score += 35
            reasons.append(f"Binary executed from temp/writable directory: {ev.image_path}")

        # 5. Shannon entropy & obfuscation check
        cmd_entropy = shannon_entropy(ev.command_line)
        has_encoded_keyword = "-enc" in ev.command_line.lower() or "frombase64string" in ev.command_line.lower()
        if (len(ev.command_line) >= 70 and cmd_entropy >= 4.4) or has_encoded_keyword:
            score += 30
            reason_msg = "Base64/encoded command argument detected" if has_encoded_keyword else f"High-entropy command line (entropy={cmd_entropy}): possible encoded payload"
            reasons.append(reason_msg)

        if len(ev.command_line) > 500:
            score += 15
            reasons.append(f"Abnormally long command line ({len(ev.command_line)} chars)")

        if score >= min_score_threshold:
            final_score = min(100, score)
            if final_score >= 80:
                sev = "critical"
            elif final_score >= 60:
                sev = "high"
            elif final_score >= 40:
                sev = "medium"
            else:
                sev = "low"

            hits.append(AnomalyHit(
                timestamp=ev.timestamp.isoformat(),
                host=ev.host,
                user=ev.user,
                parent_image=ev.parent_path,
                image_path=ev.image_path,
                command_line=ev.command_line,
                anomaly_score=final_score,
                severity=sev,
                reasons=reasons,
                entropy=cmd_entropy,
                frequency=freq,
            ))

    # Rank outliers by anomaly score descending
    hits.sort(key=lambda h: h.anomaly_score, reverse=True)
    return hits


# ── Log Parsers ────────────────────────────────────────────────────

def _parse_timestamp(ts: str) -> datetime:
    ts = ts.strip().rstrip("Z")
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(ts[:26], fmt)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse timestamp: {ts!r}")


def parse_sysmon_json(path: Path) -> Iterator[ProcessEvent]:
    """Parse Sysmon Event ID 1 process creations from JSON or streaming JSONL."""
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
            # JSON array
            for rec in json.load(fh):
                ev = _parse_dict_record(rec)
                if ev:
                    yield ev
        else:
            # Streaming JSONL
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    ev = _parse_dict_record(rec)
                    if ev:
                        yield ev


def _parse_dict_record(rec: dict) -> ProcessEvent | None:
    event_id = str(rec.get("EventID", rec.get("event_id", rec.get("event.code", ""))))
    if event_id != SYSMON_PROCESS_CREATE and "CommandLine" not in rec and "Image" not in rec:
        return None

    ts_raw = (rec.get("timestamp") or rec.get("@timestamp") or
              rec.get("UtcTime") or rec.get("_time") or "")
    if not ts_raw:
        return None
    try:
        ts = _parse_timestamp(str(ts_raw))
    except ValueError:
        return None

    image = rec.get("Image", rec.get("child_image", rec.get("process", "")))
    parent = rec.get("ParentImage", rec.get("parent_image", ""))
    if not image:
        return None

    return ProcessEvent(
        timestamp=ts,
        host=rec.get("Computer", rec.get("host", rec.get("ComputerName", "UNKNOWN"))),
        user=rec.get("User", rec.get("user", "UNKNOWN")),
        parent_path=parent,
        image_path=image,
        command_line=rec.get("CommandLine", rec.get("command_line", "")),
        process_id=str(rec.get("ProcessId", rec.get("process.pid", ""))),
        parent_process_id=str(rec.get("ParentProcessId", rec.get("process.ppid", ""))),
        process_guid=str(rec.get("ProcessGuid", rec.get("process.entity_id", ""))),
        parent_process_guid=str(rec.get("ParentProcessGuid", rec.get("process.parent.entity_id", ""))),
        log_source="json",
    )


def parse_csv_log(path: Path) -> Iterator[ProcessEvent]:
    """Parse CSV process creation logs."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            ev = _parse_dict_record(dict(row))
            if ev:
                yield ev


def parse_evtx(path: Path) -> Iterator[ProcessEvent]:
    """Parse Sysmon Event ID 1 process creations from EVTX."""
    if not HAS_EVTX:
        print("Error: python-evtx not installed. Run: pip install python-evtx", file=sys.stderr)
        sys.exit(1)

    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
            except ET.ParseError:
                continue

            event_id = root.findtext(".//ns:EventID", namespaces=WIN_NS)
            if event_id != SYSMON_PROCESS_CREATE:
                continue

            data = {}
            for el in root.findall(".//ns:EventData/ns:Data", namespaces=WIN_NS):
                data[el.get("Name", "")] = el.text or ""

            tc = root.find(".//ns:System/ns:TimeCreated", namespaces=WIN_NS)
            ts_str = tc.get("SystemTime", "") if tc is not None else ""
            if not ts_str:
                continue
            try:
                ts = _parse_timestamp(ts_str)
            except ValueError:
                continue

            host = data.get("Computer") or root.findtext(".//ns:System/ns:Computer", default="", namespaces=WIN_NS) or "UNKNOWN"
            yield ProcessEvent(
                timestamp=ts,
                host=host,
                user=data.get("User", "UNKNOWN"),
                parent_path=data.get("ParentImage", ""),
                image_path=data.get("Image", ""),
                command_line=data.get("CommandLine", ""),
                process_id=data.get("ProcessId", ""),
                parent_process_id=data.get("ParentProcessId", ""),
                process_guid=data.get("ProcessGuid", ""),
                parent_process_guid=data.get("ParentProcessGuid", ""),
                log_source="evtx",
            )


# ── Output Formatters ─────────────────────────────────────────────

def format_markdown_report(hits: list[AnomalyHit], total_events: int) -> str:
    """Format markdown report suitable for SOC incident ticketing."""
    lines = [
        "## Process Anomaly Detection Report",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Events Evaluated:** {total_events:,} | **Anomalous Outliers:** {len(hits)}  ",
        "",
        "### Ranked Process Outliers",
        "| Rank | Score | Severity | Host | User | Process | Parent | Entropy | Frequency |",
        "| :---: | :---: | :--- | :--- | :--- | :--- | :--- | :---: | :---: |",
    ]
    for idx, h in enumerate(hits, 1):
        p_name = _basename(h.parent_image) or "—"
        i_name = _basename(h.image_path)
        lines.append(
            f"| {idx} | **{h.anomaly_score}/100** | **{h.severity.upper()}** | `{h.host}` | `{h.user}` | `{i_name}` | `{p_name}` | {h.entropy} | {h.frequency}x |"
        )

    lines.append("\n### Detailed Findings")
    for idx, h in enumerate(hits, 1):
        lines.append(f"#### [{idx}] `{_basename(h.image_path)}` on `{h.host}` ({h.severity.upper()} - {h.anomaly_score}/100)")
        lines.append(f"- **Image Path:** `{h.image_path}`")
        lines.append(f"- **Parent Path:** `{h.parent_image}`")
        lines.append(f"- **User:** `{h.user}` | **Timestamp:** `{h.timestamp}`")
        lines.append(f"- **Command Line:** `{h.command_line}`")
        lines.append("- **Detection Indicators:**")
        for r in h.reasons:
            lines.append(f"  - ⚠️ {r}")
        lines.append("")

    return "\n".join(lines)


def format_table_output(hits: list[AnomalyHit], total_events: int) -> None:
    """Format terminal UI summary with Rich table or plain-text fallback."""
    if RICH:
        con = Console(stderr=True)
        con.print(Panel(f"[bold]{BANNER}[/bold]", box=box.ROUNDED))
        con.print(
            f"  Events Evaluated: [cyan]{total_events:,}[/cyan]  |  "
            f"Outliers Flagged: [red bold]{len(hits)}[/red bold]\n"
        )
        if not hits:
            con.print("[green]✓ No process anomalies or outliers detected.[/green]")
            return

        tbl = Table(box=box.SIMPLE_HEAVY, show_lines=True)
        tbl.add_column("Rank", style="dim", width=4)
        tbl.add_column("Score", justify="right", width=7)
        tbl.add_column("Severity")
        tbl.add_column("Host & User", style="cyan")
        tbl.add_column("Parent → Process", style="yellow")
        tbl.add_column("Entropy", justify="right", width=7)
        tbl.add_column("Detection Reasons", max_width=45)

        for idx, h in enumerate(hits, 1):
            sc = SEVERITY_COLORS.get(h.severity, "white")
            p_name = _basename(h.parent_image) or "—"
            i_name = _basename(h.image_path)
            tbl.add_row(
                str(idx),
                f"{h.anomaly_score}",
                f"[{sc}]{h.severity.upper()}[/{sc}]",
                f"{h.host}\n{h.user}",
                f"{p_name}\n→ {i_name}",
                str(h.entropy),
                "\n".join(f"• {r}" for r in h.reasons[:3]),
            )
        con.print(tbl)
    else:
        print(f"\n{'=' * 75}\n  {BANNER}")
        print(f"  Events: {total_events:,}  |  Outliers: {len(hits)}")
        print(f"{'=' * 75}")
        if not hits:
            print("\n  ✓ No process anomalies or outliers detected.\n")
            return
        for idx, h in enumerate(hits, 1):
            p_name = _basename(h.parent_image) or "—"
            i_name = _basename(h.image_path)
            print(f"\n  [{idx}] {h.severity.upper()} (Score: {h.anomaly_score}/100)")
            print(f"      Host / User: {h.host} ({h.user})")
            print(f"      Process:     {p_name} → {i_name}")
            print(f"      Command:     {h.command_line[:120]}")
            for r in h.reasons:
                print(f"      Reason:      {r}")
        print()


# ── CLI ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="process-anomaly-detector",
        description=(
            "Detect anomalous process creation (Sysmon Event ID 1) via\n"
            "frequency baselining, Shannon entropy, LOLBIN detection, and writable path analysis."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s sysmon.json\n"
            "  %(prog)s sysmon.json --save-baseline baseline.json\n"
            "  %(prog)s sysmon.json --load-baseline baseline.json --output markdown -o report.md\n"
            "  %(prog)s sysmon.evtx --format evtx --min-score 50\n"
        ),
    )
    p.add_argument("logfile", type=Path, help="path to process log file (JSON, EVTX, CSV)")
    p.add_argument("-f", "--format", choices=["auto", "json", "evtx", "csv"], default="auto",
                   help="input log format (default: auto-detect)")
    p.add_argument("--min-freq", type=int, default=3, metavar="N",
                   help="minimum frequency in baseline to consider normal (default: 3)")
    p.add_argument("--min-score", type=int, default=30, metavar="SCORE",
                   help="minimum anomaly score threshold to report (default: 30)")
    p.add_argument("--save-baseline", type=Path, default=None, metavar="PATH",
                   help="export learned baseline profile to a JSON file")
    p.add_argument("--load-baseline", type=Path, default=None, metavar="PATH",
                   help="load pre-computed baseline profile from a JSON file")
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
        suffix = logfile.suffix.lower()
        if suffix == ".evtx":
            fmt = "evtx"
        elif suffix == ".csv":
            fmt = "csv"
        else:
            fmt = "json"

    parsers = {
        "json": parse_sysmon_json,
        "csv": parse_csv_log,
        "evtx": parse_evtx,
    }
    parse_fn = parsers.get(fmt)
    if not parse_fn:
        print(f"Error: unsupported format: {fmt}", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print(f"\n  ⏳ Ingesting {logfile.name} (format: {fmt})...", file=sys.stderr)

    events = list(parse_fn(logfile))
    if not events:
        print(f"Error: No process creation events found in {logfile.name}", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print(f"  ✓ {len(events):,} process events parsed", file=sys.stderr)

    # Baseline handling
    baseline: ProcessBaseline | None = None
    if args.load_baseline:
        if not args.load_baseline.exists():
            print(f"Error: baseline file not found: {args.load_baseline}", file=sys.stderr)
            sys.exit(1)
        baseline = ProcessBaseline.load(args.load_baseline)
        if not args.quiet:
            print(f"  ✓ Loaded baseline from {args.load_baseline} ({len(baseline.counts)} profiles)", file=sys.stderr)

    hits = detect_anomalies(
        events,
        baseline=baseline,
        min_baseline_frequency=args.min_freq,
        min_score_threshold=args.min_score,
    )

    if args.save_baseline:
        export_bl = baseline or ProcessBaseline(min_frequency=args.min_freq)
        if baseline is None:
            for ev in events:
                export_bl.observe(ev.parent_path, ev.image_path, ev.user)
        export_bl.save(args.save_baseline)
        if not args.quiet:
            print(f"  ✓ Saved baseline to {args.save_baseline} ({len(export_bl.counts)} profiles)", file=sys.stderr)

    match args.output:
        case "markdown":
            md = format_markdown_report(hits, len(events))
            if args.output_file:
                args.output_file.write_text(md, encoding="utf-8")
                if not args.quiet:
                    print(f"  ✓ Markdown report saved to {args.output_file}", file=sys.stderr)
            else:
                print(md)
        case "json":
            json_str = json.dumps({
                "tool": "process-anomaly-detector",
                "version": VERSION,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_events": len(events),
                "total_outliers": len(hits),
                "hits": [h.to_dict() for h in hits],
            }, indent=2)
            if args.output_file:
                args.output_file.write_text(json_str, encoding="utf-8")
                if not args.quiet:
                    print(f"  ✓ JSON report saved to {args.output_file}", file=sys.stderr)
            else:
                print(json_str)
        case _:
            if args.output_file:
                args.output_file.write_text(format_markdown_report(hits, len(events)), encoding="utf-8")
            format_table_output(hits, len(events))

    if any(h.severity in ("critical", "high") for h in hits):
        sys.exit(2)
    elif hits:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
