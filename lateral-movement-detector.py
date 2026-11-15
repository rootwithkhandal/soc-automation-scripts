#!/usr/bin/env python3
"""
lateral_movement.py — Lateral Movement Indicator Script
========================================================
SOC Automation Toolkit · Day 2

Detects post-compromise lateral movement patterns:
  • Unusual RDP/SMB/WinRM connections between hosts
  • Remote process creation with suspicious parent-child pairs
  • Service account usage from unexpected source hosts
  • Two-signal correlation: flags only when network + process evidence align

Supports: Sysmon EVTX/JSON/JSONL, Windows Event logs, Zeek conn/smb logs, CSV

Usage:
    python lateral_movement.py sysmon_events.json
    python lateral_movement.py sysmon.evtx --format evtx
    python lateral_movement.py conn.log --format zeek
    python lateral_movement.py events.json --output dot -o graph.dot
    python lateral_movement.py events.json --single-signal --output json
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
BANNER = f"lateral_movement v{VERSION} — SOC Automation Toolkit · Day 2"

WIN_NS = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Sysmon Event IDs we care about
SYSMON_PROCESS_CREATE = "1"
SYSMON_NETWORK_CONNECT = "3"
SYSMON_PIPE_CONNECT = "18"

# Lateral movement ports
LATERAL_PORTS = {
    "3389": "RDP", "445": "SMB", "135": "RPC/DCOM",
    "5985": "WinRM-HTTP", "5986": "WinRM-HTTPS",
    "22": "SSH", "23": "Telnet", "139": "NetBIOS",
}

# Suspicious parent-child process pairs (parent → child)
SUSPECT_PARENT_CHILD = {
    ("wmiprvse.exe", "powershell.exe"), ("wmiprvse.exe", "cmd.exe"),
    ("wmiprvse.exe", "mshta.exe"), ("services.exe", "cmd.exe"),
    ("services.exe", "powershell.exe"), ("svchost.exe", "cmd.exe"),
    ("winrshost.exe", "cmd.exe"), ("winrshost.exe", "powershell.exe"),
    ("wsmprovhost.exe", "cmd.exe"), ("wsmprovhost.exe", "powershell.exe"),
    ("mmc.exe", "cmd.exe"), ("explorer.exe", "mshta.exe"),
}

# Processes commonly used for remote execution
REMOTE_EXEC_PROCS = {
    "psexec.exe", "psexesvc.exe", "winexesvc.exe", "smbexec.py",
    "wmic.exe", "wmiexec.exe", "atexec.exe", "dcomexec.exe",
}

# Service accounts pattern
SVC_ACCOUNT_RE = re.compile(r"^(svc_|service_|sa_|admin_|adm_)", re.IGNORECASE)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_COLORS = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "green"}

_LOCAL_IPS = {"127.0.0.1", "::1", "-", "", "0.0.0.0"}


# ── Data Models ────────────────────────────────────────────────────

@dataclass(slots=True)
class NetworkEvent:
    """A network connection between two hosts."""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: str
    protocol: str  # RDP, SMB, WinRM, etc.
    user: str
    process: str
    log_source: str = ""


@dataclass(slots=True)
class ProcessEvent:
    """A process creation event."""
    timestamp: datetime
    host: str
    user: str
    parent_image: str
    child_image: str
    command_line: str
    log_source: str = ""


@dataclass(slots=True)
class LateralIndicator:
    """A detected lateral movement indicator."""
    indicator_type: str  # network_lateral | process_lateral | correlated
    src_host: str
    dst_host: str
    evidence: list[str]
    users: list[str]
    severity: str
    first_seen: str
    last_seen: str
    signal_count: int  # 1 = single signal, 2 = correlated
    details: str = ""


# ── Log Parsers ────────────────────────────────────────────────────

def parse_sysmon_json(path: Path) -> tuple[list[NetworkEvent], list[ProcessEvent]]:
    """Parse Sysmon events from JSON/JSONL (streams JSONL line-by-line)."""
    net_events: list[NetworkEvent] = []
    proc_events: list[ProcessEvent] = []

    def _process_record(rec: dict):
        event_id = str(rec.get("EventID", rec.get("event_id", rec.get("event.code", ""))))
        if event_id == SYSMON_NETWORK_CONNECT:
            ev = _parse_net_record(rec)
            if ev:
                net_events.append(ev)
        elif event_id == SYSMON_PROCESS_CREATE:
            ev = _parse_proc_record(rec)
            if ev:
                proc_events.append(ev)

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
            # shortcut: loads full JSON array into memory, stream with ijson if files exceed 200MB
            for rec in json.load(fh):
                _process_record(rec)
        else:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    _process_record(rec)

    return net_events, proc_events


def parse_sysmon_evtx(path: Path) -> tuple[list[NetworkEvent], list[ProcessEvent]]:
    """Parse Sysmon events from EVTX."""
    if not HAS_EVTX:
        _die("python-evtx not installed. Run: pip install python-evtx")

    net_events: list[NetworkEvent] = []
    proc_events: list[ProcessEvent] = []

    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
            except ET.ParseError:
                continue

            event_id = root.findtext(".//ns:EventID", namespaces=WIN_NS)
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

            if event_id == SYSMON_NETWORK_CONNECT:
                src = data.get("SourceIp", "")
                dst = data.get("DestinationIp", "")
                port = data.get("DestinationPort", "")
                if src in _LOCAL_IPS or dst in _LOCAL_IPS or src == dst:
                    continue
                net_events.append(NetworkEvent(
                    timestamp=timestamp, src_ip=src, dst_ip=dst,
                    dst_port=port,
                    protocol=LATERAL_PORTS.get(port, f"port-{port}"),
                    user=data.get("User", "UNKNOWN"),
                    process=_basename(data.get("Image", "")),
                    log_source="sysmon_evtx",
                ))
            elif event_id == SYSMON_PROCESS_CREATE:
                host = data.get("Computer") or root.findtext(
                    ".//ns:System/ns:Computer", default="", namespaces=WIN_NS) or "UNKNOWN"
                proc_events.append(ProcessEvent(
                    timestamp=timestamp, host=host,
                    user=data.get("User", "UNKNOWN"),
                    parent_image=_basename(data.get("ParentImage", "")),
                    child_image=_basename(data.get("Image", "")),
                    command_line=data.get("CommandLine", ""),
                    log_source="sysmon_evtx",
                ))

    return net_events, proc_events


def parse_zeek(path: Path) -> tuple[list[NetworkEvent], list[ProcessEvent]]:
    """Parse Zeek conn.log (TSV or JSON)."""
    content = path.read_text(encoding="utf-8", errors="replace").strip()
    net_events: list[NetworkEvent] = []

    # JSON Zeek logs
    if content.startswith("{") or content.startswith("["):
        lines = content.splitlines() if content.startswith("{") else json.loads(content)
        records = []
        if isinstance(lines, list) and lines and isinstance(lines[0], str):
            for line in lines:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        else:
            records = lines

        for rec in records:
            ts_raw = rec.get("ts", "")
            try:
                ts = datetime.fromtimestamp(float(ts_raw)) if isinstance(ts_raw, (int, float)) or ts_raw.replace(".", "").isdigit() else _parse_timestamp(str(ts_raw))
            except (ValueError, OSError):
                continue
            src = rec.get("id.orig_h", rec.get("src", ""))
            dst = rec.get("id.resp_h", rec.get("dst", ""))
            port = str(rec.get("id.resp_p", rec.get("dst_port", "")))
            if port not in LATERAL_PORTS or src in _LOCAL_IPS or dst in _LOCAL_IPS:
                continue
            net_events.append(NetworkEvent(
                timestamp=ts, src_ip=src, dst_ip=dst, dst_port=port,
                protocol=LATERAL_PORTS[port], user="-",
                process="-", log_source="zeek",
            ))
        return net_events, []

    # TSV Zeek logs
    for line in content.splitlines():
        if line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) < 7:
            continue
        try:
            ts = datetime.fromtimestamp(float(fields[0]))
        except (ValueError, OSError):
            continue
        src, dst, port = fields[2], fields[4], fields[5]
        if port not in LATERAL_PORTS or src in _LOCAL_IPS or dst in _LOCAL_IPS:
            continue
        net_events.append(NetworkEvent(
            timestamp=ts, src_ip=src, dst_ip=dst, dst_port=port,
            protocol=LATERAL_PORTS[port], user="-",
            process="-", log_source="zeek",
        ))

    return net_events, []


def parse_csv_log(path: Path) -> tuple[list[NetworkEvent], list[ProcessEvent]]:
    """Parse CSV with network/process columns."""
    net_events: list[NetworkEvent] = []
    proc_events: list[ProcessEvent] = []

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        headers = set(reader.fieldnames or [])

        for row in reader:
            event_id = row.get("EventID", row.get("event_id", ""))
            ts_raw = (row.get("timestamp") or row.get("@timestamp") or
                      row.get("UtcTime") or row.get("_time") or "")
            if not ts_raw:
                continue
            try:
                ts = _parse_timestamp(ts_raw)
            except ValueError:
                continue

            if event_id == SYSMON_NETWORK_CONNECT or "DestinationIp" in headers:
                rec = _parse_net_record(row)
                if rec:
                    net_events.append(rec)
            if event_id == SYSMON_PROCESS_CREATE or "ParentImage" in headers:
                rec = _parse_proc_record(row)
                if rec:
                    proc_events.append(rec)

    return net_events, proc_events


def _parse_net_record(rec: dict) -> NetworkEvent | None:
    ts_raw = (rec.get("timestamp") or rec.get("@timestamp") or
              rec.get("UtcTime") or rec.get("_time") or "")
    if not ts_raw:
        return None
    try:
        ts = _parse_timestamp(str(ts_raw))
    except ValueError:
        return None

    src = rec.get("SourceIp", rec.get("src_ip", rec.get("src", "")))
    dst = rec.get("DestinationIp", rec.get("dst_ip", rec.get("dst", "")))
    port = str(rec.get("DestinationPort", rec.get("dst_port", "")))

    if not src or not dst or src in _LOCAL_IPS or dst in _LOCAL_IPS or src == dst:
        return None

    return NetworkEvent(
        timestamp=ts, src_ip=src, dst_ip=dst, dst_port=port,
        protocol=LATERAL_PORTS.get(port, f"port-{port}"),
        user=rec.get("User", rec.get("user", "UNKNOWN")),
        process=_basename(rec.get("Image", rec.get("process", ""))),
        log_source="json",
    )


def _parse_proc_record(rec: dict) -> ProcessEvent | None:
    ts_raw = (rec.get("timestamp") or rec.get("@timestamp") or
              rec.get("UtcTime") or rec.get("_time") or "")
    if not ts_raw:
        return None
    try:
        ts = _parse_timestamp(str(ts_raw))
    except ValueError:
        return None

    parent = _basename(rec.get("ParentImage", rec.get("parent_image", "")))
    child = _basename(rec.get("Image", rec.get("child_image", rec.get("process", ""))))
    if not parent or not child:
        return None

    return ProcessEvent(
        timestamp=ts,
        host=rec.get("Computer", rec.get("host", rec.get("ComputerName", "UNKNOWN"))),
        user=rec.get("User", rec.get("user", "UNKNOWN")),
        parent_image=parent, child_image=child,
        command_line=rec.get("CommandLine", rec.get("command_line", "")),
        log_source="json",
    )


# ── Detection Engine ──────────────────────────────────────────────

def load_host_map(path: Path | None) -> dict[str, str]:
    """Load hostname <-> IP mapping file (JSON, CSV, or key=val)."""
    mapping: dict[str, str] = {}
    if not path or not path.exists():
        return mapping
    content = path.read_text(encoding="utf-8", errors="replace").strip()
    if content.startswith("{"):
        try:
            data = json.loads(content)
            for k, v in data.items():
                mapping[str(k).lower()] = str(v).lower()
                mapping[str(v).lower()] = str(k).lower()
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
            k, v = k.strip().lower(), v.strip().lower()
            mapping[k] = v
            mapping[v] = k
    return mapping


def detect(
    net_events: list[NetworkEvent],
    proc_events: list[ProcessEvent],
    require_two_signals: bool = True,
    time_window_minutes: int = 60,
    host_map: dict[str, str] | None = None,
) -> list[LateralIndicator]:
    """Detect lateral movement from network + process signals."""

    # ── Network signals: connections to lateral-movement ports ─────
    net_signals: dict[tuple[str, str], list[NetworkEvent]] = defaultdict(list)
    for ev in net_events:
        if ev.dst_port in LATERAL_PORTS:
            pair = (ev.src_ip, ev.dst_ip)
            net_signals[pair].append(ev)

    # ── Process signals: suspicious parent-child on hosts ─────────
    proc_signals: dict[str, list[ProcessEvent]] = defaultdict(list)
    proc_by_target: dict[str, list[ProcessEvent]] = defaultdict(list)
    for ev in proc_events:
        parent = ev.parent_image.lower()
        child = ev.child_image.lower()
        is_suspect = (
            (parent, child) in SUSPECT_PARENT_CHILD
            or child in REMOTE_EXEC_PROCS
            or SVC_ACCOUNT_RE.match(ev.user)
        )
        if is_suspect:
            proc_signals[ev.host].append(ev)
            h_lower = ev.host.lower()
            proc_by_target[h_lower].append(ev)
            short_host = h_lower.split(".")[0]
            if short_host != h_lower:
                proc_by_target[short_host].append(ev)

    # ── Correlate: host pairs with both network + process evidence ─
    indicators: list[LateralIndicator] = []
    window = timedelta(minutes=time_window_minutes)

    for pair, n_events in net_signals.items():
        src_ip, dst_ip = pair
        evidence: list[str] = []
        users = set()
        all_times = []

        # Network evidence
        protocols = {ev.protocol for ev in n_events}
        processes = {ev.process for ev in n_events if ev.process != "-"}
        for ev in n_events:
            users.add(ev.user)
            all_times.append(ev.timestamp)
        evidence.append(
            f"Network: {len(n_events)} connections via {', '.join(sorted(protocols))}"
            + (f" by {', '.join(sorted(processes))}" if processes else "")
        )

        # Process evidence on destination host (direct, mapped, or domain-stripped)
        candidates = {dst_ip.lower()}
        if host_map and dst_ip.lower() in host_map:
            mapped = host_map[dst_ip.lower()]
            candidates.add(mapped)
            candidates.add(mapped.split(".")[0])

        dst_proc: list[ProcessEvent] = []
        seen_procs = set()
        for c in candidates:
            for p in proc_by_target.get(c, []):
                key = (p.timestamp, p.host, p.parent_image, p.child_image, p.command_line)
                if key not in seen_procs:
                    seen_procs.add(key)
                    dst_proc.append(p)

        correlated_procs = [
            p for p in dst_proc
            if any(abs(p.timestamp - n.timestamp) <= window for n in n_events)
        ] if dst_proc else []

        if correlated_procs:
            seen_proc_evidence = set()
            for p in correlated_procs:
                desc = f"Process: {p.parent_image} → {p.child_image} as {p.user} on {p.host}"
                if desc not in seen_proc_evidence:
                    seen_proc_evidence.add(desc)
                    evidence.append(desc)
                users.add(p.user)
                all_times.append(p.timestamp)

        signal_count = 1 + (1 if correlated_procs else 0)

        if require_two_signals and signal_count < 2:
            continue

        all_times.sort()
        sev = _score_severity(n_events, correlated_procs, signal_count)
        indicators.append(LateralIndicator(
            indicator_type="correlated" if signal_count >= 2 else "network_lateral",
            src_host=src_ip, dst_host=dst_ip,
            evidence=evidence, users=sorted(users),
            severity=sev,
            first_seen=all_times[0].isoformat(),
            last_seen=all_times[-1].isoformat(),
            signal_count=signal_count,
            details=f"{src_ip} → {dst_ip} via {', '.join(sorted(protocols))}",
        ))

    # Process-only signals (hosts with suspicious processes, no network pair)
    if not require_two_signals:
        hosts_covered = {dst for _, dst in net_signals}
        for host, p_events in proc_signals.items():
            if host in hosts_covered:
                continue
            evidence = [
                f"Process: {p.parent_image} → {p.child_image} as {p.user}"
                for p in p_events[:5]
            ]
            users = sorted({p.user for p in p_events})
            times = sorted(p.timestamp for p in p_events)
            indicators.append(LateralIndicator(
                indicator_type="process_lateral",
                src_host="unknown", dst_host=host,
                evidence=evidence, users=users,
                severity="medium",
                first_seen=times[0].isoformat(),
                last_seen=times[-1].isoformat(),
                signal_count=1,
                details=f"Suspicious process activity on {host}",
            ))

    indicators.sort(key=lambda i: SEVERITY_ORDER.get(i.severity, 99))
    return indicators


def _score_severity(
    net: list[NetworkEvent],
    procs: list[ProcessEvent],
    signals: int,
) -> str:
    score = 0
    # Two signals = starts at high
    if signals >= 2:
        score += 3
    # Multiple protocols = more suspicious
    protocols = {e.protocol for e in net}
    if len(protocols) >= 2:
        score += 1
    # Remote exec tools
    if any(e.process.lower() in REMOTE_EXEC_PROCS for e in net):
        score += 2
    # Service account
    if any(SVC_ACCOUNT_RE.match(e.user) for e in net):
        score += 1
    if any(SVC_ACCOUNT_RE.match(p.user) for p in procs):
        score += 1
    # High-entropy command lines (long encoded commands)
    if any(len(p.command_line) > 500 for p in procs):
        score += 1

    if score >= 5:
        return "critical"
    if score >= 3:
        return "high"
    if score >= 1:
        return "medium"
    return "low"


# ── Output Formatters ─────────────────────────────────────────────

def output_table(indicators: list[LateralIndicator], stats: dict) -> None:
    if RICH:
        _rich_table(indicators, stats)
    else:
        _plain_table(indicators, stats)


def _rich_table(indicators: list[LateralIndicator], stats: dict) -> None:
    con = Console(stderr=True)
    con.print(Panel(f"[bold]{BANNER}[/bold]", box=box.ROUNDED))
    con.print(
        f"  Network events: [cyan]{stats['net']:,}[/cyan]  |  "
        f"Process events: [cyan]{stats['proc']:,}[/cyan]  |  "
        f"Indicators: [red bold]{len(indicators)}[/red bold]\n"
    )
    if not indicators:
        con.print("[green]✓ No lateral movement indicators detected.[/green]")
        return

    tbl = Table(box=box.SIMPLE_HEAVY, show_lines=True)
    tbl.add_column("#", style="dim", width=3)
    tbl.add_column("Type", style="bold")
    tbl.add_column("Source → Dest", style="cyan")
    tbl.add_column("Users", style="yellow")
    tbl.add_column("Signals", justify="center")
    tbl.add_column("Evidence", max_width=50)
    tbl.add_column("Severity")

    for i, ind in enumerate(indicators, 1):
        sc = SEVERITY_COLORS.get(ind.severity, "white")
        tbl.add_row(
            str(i),
            ind.indicator_type.replace("_", " ").title(),
            f"{ind.src_host}\n→ {ind.dst_host}",
            "\n".join(ind.users[:3]),
            str(ind.signal_count),
            "\n".join(ind.evidence[:3]),
            f"[{sc}]{ind.severity.upper()}[/{sc}]",
        )
    con.print(tbl)


def _plain_table(indicators: list[LateralIndicator], stats: dict) -> None:
    print(f"\n{'=' * 70}\n  {BANNER}")
    print(f"  Network: {stats['net']:,}  |  Process: {stats['proc']:,}  |  Indicators: {len(indicators)}")
    print(f"{'=' * 70}")
    if not indicators:
        print("\n  ✓ No lateral movement indicators detected.\n")
        return
    for i, ind in enumerate(indicators, 1):
        print(f"\n  [{i}] {ind.indicator_type.replace('_', ' ').upper()}")
        print(f"      Path:     {ind.src_host} → {ind.dst_host}")
        print(f"      Users:    {', '.join(ind.users[:5])}")
        print(f"      Signals:  {ind.signal_count}")
        for ev in ind.evidence[:4]:
            print(f"      Evidence: {ev}")
        print(f"      Window:   {ind.first_seen} → {ind.last_seen}")
        print(f"      Severity: {ind.severity.upper()}")
    print()


def output_json(indicators: list[LateralIndicator], stats: dict) -> str:
    return json.dumps({
        "tool": "lateral_movement", "version": VERSION,
        "generated_at": datetime.now().isoformat(),
        "summary": stats | {"indicators": len(indicators)},
        "indicators": [asdict(ind) for ind in indicators],
    }, indent=2)


def output_csv_str(indicators: list[LateralIndicator]) -> str:
    if not indicators:
        return ""
    buf = io.StringIO()
    fields = ["indicator_type", "src_host", "dst_host", "users",
              "severity", "signal_count", "first_seen", "last_seen", "details"]
    writer = csv.DictWriter(buf, fieldnames=fields)
    writer.writeheader()
    for ind in indicators:
        d = asdict(ind)
        d["users"] = "; ".join(d["users"])
        d["evidence"] = "; ".join(d["evidence"])
        writer.writerow({k: d[k] for k in fields})
    return buf.getvalue()


def output_dot(indicators: list[LateralIndicator]) -> str:
    """Generate Graphviz DOT graph of lateral movement paths."""
    lines = ['digraph lateral_movement {',
             '  rankdir=LR;',
             '  node [shape=box, style=filled, fillcolor=lightyellow];',
             '  edge [fontsize=10];', '']

    sev_edge_colors = {"critical": "red", "high": "orangered",
                       "medium": "orange", "low": "gray"}

    for ind in indicators:
        src_id = ind.src_host.replace(".", "_")
        dst_id = ind.dst_host.replace(".", "_")
        color = sev_edge_colors.get(ind.severity, "gray")
        user_str = ", ".join(ind.users[:2]).replace("\\", "\\\\")
        label = f"{ind.indicator_type}\\n{user_str}\\n{ind.severity.upper()}"
        lines.append(f'  "{src_id}" [label="{ind.src_host}"];')
        lines.append(f'  "{dst_id}" [label="{ind.dst_host}"];')
        lines.append(f'  "{src_id}" -> "{dst_id}" [label="{label}", color={color}, penwidth=2];')

    lines.append("}")
    return "\n".join(lines)


def _write_output(content: str, path: Path | None, quiet: bool) -> None:
    if path:
        path.write_text(content)
        if not quiet:
            print(f"  ✓ Written to {path}", file=sys.stderr)
    else:
        print(content)


# ── Utilities ──────────────────────────────────────────────────────

def _parse_timestamp(ts: str) -> datetime:
    ts = ts.strip().rstrip("Z")
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


def _basename(path: str) -> str:
    """Extract filename from a full path (Windows or Unix)."""
    return path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] if path else ""


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
    if head.lstrip().startswith("#") and "\t" in head:
        return "zeek"
    if head.lstrip().startswith(("{", "[")):
        return "json"
    return "json"


def _die(msg: str) -> None:
    print(f"\n  ✗ Error: {msg}\n", file=sys.stderr)
    sys.exit(1)


# ── CLI ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lateral_movement",
        description=(
            "Detect lateral movement indicators from Sysmon, Windows Event, "
            "or Zeek logs.\n\n"
            "Correlates network connections (RDP/SMB/WinRM) with suspicious "
            "process creation to reduce false positives."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s sysmon_events.json\n"
            "  %(prog)s sysmon.evtx --format evtx\n"
            "  %(prog)s conn.log --format zeek --single-signal\n"
            "  %(prog)s events.json --output dot -o graph.dot\n"
        ),
    )
    p.add_argument("logfile", type=Path, help="log file to analyze")
    p.add_argument("-f", "--format", choices=["auto", "evtx", "json", "csv", "zeek"],
                   default="auto", help="log format (default: auto-detect)")
    p.add_argument("-w", "--window", type=int, default=60, metavar="MIN",
                   help="correlation time window in minutes (default: 60)")
    p.add_argument("--single-signal", action="store_true",
                   help="flag on one signal (default: require network + process)")
    p.add_argument("--host-map", type=Path, default=None, metavar="FILE",
                   help="host to IP mapping file (JSON or key=val / CSV)")
    p.add_argument("--output", choices=["table", "json", "csv", "dot"], default="table",
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
    parsers = {
        "evtx": parse_sysmon_evtx, "json": parse_sysmon_json,
        "csv": parse_csv_log, "zeek": parse_zeek,
    }
    parse_fn = parsers.get(fmt)
    if not parse_fn:
        _die(f"Unknown format: {fmt}")

    if not args.quiet:
        print(f"\n  ⏳ Parsing {logfile.name} (format: {fmt})...", file=sys.stderr)

    net_events, proc_events = parse_fn(logfile)
    if not net_events and not proc_events:
        _die(f"No relevant events found in {logfile.name}")

    stats = {"net": len(net_events), "proc": len(proc_events)}
    if not args.quiet:
        print(f"  ✓ {stats['net']:,} network events, {stats['proc']:,} process events",
              file=sys.stderr)

    host_map = load_host_map(args.host_map)
    if host_map and not args.quiet:
        print(f"  ✓ Host mapping: {len(host_map) // 2} entries loaded", file=sys.stderr)

    indicators = detect(
        net_events, proc_events,
        require_two_signals=not args.single_signal,
        time_window_minutes=args.window,
        host_map=host_map,
    )

    match args.output:
        case "json":
            _write_output(output_json(indicators, stats), args.output_file, args.quiet)
        case "csv":
            _write_output(output_csv_str(indicators), args.output_file, args.quiet)
        case "dot":
            _write_output(output_dot(indicators), args.output_file, args.quiet)
        case _:
            if args.output_file:
                _write_output(output_json(indicators, stats), args.output_file, args.quiet)
            output_table(indicators, stats)

    if any(i.severity in ("critical", "high") for i in indicators):
        sys.exit(2)
    elif indicators:
        sys.exit(1)


if __name__ == "__main__":
    main()
