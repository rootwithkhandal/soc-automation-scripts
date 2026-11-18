#!/usr/bin/env python3
"""
playbook-runner.py — Automated Response Playbook Runner (Read-Only First)
=======================================================================
SOC Automation Toolkit · Day 7

Ingests high-confidence incident alerts (from Days 1, 2, 5, or Day 6 dedup),
performs safe enrichment and timeline documentation, extracts correlated logs
within a sliding context window, generates a SOC ticket template with MITRE
ATT&CK mappings, and stages gated containment actions behind a strict
human-in-the-loop safety interface.

Usage:
    python playbook-runner.py incidents.json
    python playbook-runner.py incidents.json --logs raw_events.json --window 15 -o ticket.md
    python playbook-runner.py incidents.json --webhook https://hooks.slack.com/services/...
    python playbook-runner.py incidents.json --execute --confirm
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

# ── Optional UI dependency ────────────────────────────────────────

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.markdown import Markdown
    from rich import box
    RICH = True
except ImportError:
    RICH = False

# ── Constants ──────────────────────────────────────────────────────

VERSION = "1.0.0"
BANNER = f"playbook-runner v{VERSION} — SOC Automation Toolkit · Day 7"


# ── Data Models ────────────────────────────────────────────────────

@dataclass(slots=True)
class PlaybookAlert:
    """Standardized high-confidence incident alert for playbook execution."""
    incident_id: str
    rule_name: str
    host: str
    ioc: str
    user: str
    severity: str
    count: int = 1
    first_seen: str = ""
    last_seen: str = ""
    notes: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ── Heuristic MITRE ATT&CK Mapping ─────────────────────────────────

def resolve_mitre_mapping(rule_name: str, ioc: str = "") -> list[str]:
    """Map alert rule keywords to MITRE ATT&CK tactics & techniques."""
    r = rule_name.lower()
    tactics: list[str] = []

    if any(k in r for k in ["brute", "stuffing", "credential", "failed login", "auth", "authentication", "password"]):
        tactics.append("Credential Access (TA0006) — T1110: Brute Force")

    if any(k in r for k in ["lateral", "psexec", "smb", "rdp", "wmi", "winrm", "remote execution"]):
        tactics.append("Lateral Movement (TA0008) — T1021: Remote Services")
        tactics.append("Execution (TA0002) — T1569.002: Service Execution")

    if any(k in r for k in ["beacon", "c2", "cobalt", "command and control", "untrusted domain", "dns tunnel", "exfil"]):
        tactics.append("Command and Control (TA0011) — T1071.001: Web Protocols")

    if any(k in r for k in ["anomaly", "lolbin", "powershell", "cmd", "certutil", "mshta", "masquerade", "living off the land"]):
        tactics.append("Defense Evasion (TA0005) — T1218: System Binary Proxy Execution")
        tactics.append("Execution (TA0002) — T1059.001: PowerShell / Scripting")

    if any(k in r for k in ["phish", "email", "attachment", "macro", "vba", "spearphishing"]):
        tactics.append("Initial Access (TA0001) — T1566: Phishing")
        tactics.append("Execution (TA0002) — T1204: User Execution")

    if not tactics:
        tactics.append("Initial Investigation — T1000: Generic Security Detection")

    return tactics


# ── Ingestion Helpers ──────────────────────────────────────────────

def _parse_ts(ts: str) -> datetime:
    """Parse ISO8601 or common SIEM timestamp to timezone-aware UTC datetime."""
    ts = ts.strip().rstrip("Z")
    try:
        dt = datetime.fromisoformat(ts)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(ts[:26], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def parse_input_alerts(data: Any) -> list[PlaybookAlert]:
    """Ingest alerts from Day 6, Day 1, Day 2, Day 5, or generic alert lists."""
    if isinstance(data, (str, Path)):
        p = Path(data)
        if not p.exists():
            return []
        raw_text = p.read_text(encoding="utf-8", errors="replace").strip()
        if not raw_text:
            return []
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError:
            data = [json.loads(line) for line in raw_text.splitlines() if line.strip()]

    results: list[PlaybookAlert] = []

    # Unpack container payloads from toolkit scripts
    if isinstance(data, dict):
        if "incidents" in data and isinstance(data["incidents"], list):
            items = data["incidents"]
        elif "detections" in data and isinstance(data["detections"], list):
            items = data["detections"]
        elif "indicators" in data and isinstance(data["indicators"], list):
            items = data["indicators"]
        elif "hits" in data and isinstance(data["hits"], list):
            items = data["hits"]
        else:
            items = [data]
    elif isinstance(data, list):
        items = data
    else:
        items = []

    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            continue

        # Day 1: Brute Force / Credential Stuffing detection format
        det_type = item.get("detection_type", item.get("type", ""))
        if "brute_force" in det_type or "credential_stuffing" in det_type:
            r_name = f"Authentication Attack ({det_type})"
            ioc_val = item.get("source_ip", item.get("ip", "—"))
            targets = item.get("target_accounts", [])
            u_str = ", ".join(targets) if targets else str(item.get("username", item.get("user", "—")))
            cnt = item.get("failure_count", item.get("failures", item.get("distinct_users", 1)))
            first_s = item.get("window_start", item.get("first_seen", ""))
            last_s = item.get("window_end", item.get("last_seen", ""))
            results.append(PlaybookAlert(
                incident_id=item.get("incident_id", f"INC-BF-{idx+1:03d}"),
                rule_name=r_name,
                host=item.get("target_host", "auth-domain"),
                ioc=ioc_val,
                user=u_str or "—",
                severity=item.get("severity", "high").lower(),
                count=cnt,
                first_seen=first_s,
                last_seen=last_s,
                notes=[item.get("details", f"Failures: {cnt}")],
                mitre_tactics=resolve_mitre_mapping(r_name, ioc_val),
                raw=item
            ))
            continue

        # Day 2: Lateral Movement indicator format
        if "src_host" in item and "dst_host" in item:
            ind_type = item.get("indicator_type", "Lateral Movement")
            r_name = f"Lateral Movement Activity ({ind_type})"
            usrs = item.get("users", [])
            u_str = ", ".join(usrs) if isinstance(usrs, list) else str(item.get("user", "—"))
            results.append(PlaybookAlert(
                incident_id=item.get("incident_id", f"INC-LM-{idx+1:03d}"),
                rule_name=r_name,
                host=f"{item.get('src_host')} -> {item.get('dst_host')}",
                ioc=item.get("dst_ip", item.get("src_ip", "—")),
                user=u_str or "—",
                severity=item.get("severity", "high").lower(),
                count=item.get("signal_count", item.get("count", 1)),
                first_seen=item.get("first_seen", item.get("timestamp", "")),
                last_seen=item.get("last_seen", item.get("timestamp", "")),
                notes=[item.get("details", f"Signals: {item.get('signals', [])}")],
                mitre_tactics=resolve_mitre_mapping(r_name),
                raw=item
            ))
            continue

        # Day 5: Process Anomaly hit format
        if "anomaly_score" in item or ("command_line" in item and "image" in item):
            score = item.get("anomaly_score", 50)
            sev = "critical" if score >= 80 else ("high" if score >= 50 else "medium")
            img = item.get("image", "unknown.exe")
            r_name = f"Process Anomaly: {Path(img).name if img else 'Unknown'}"
            ts = item.get("timestamp", "")
            results.append(PlaybookAlert(
                incident_id=item.get("incident_id", f"INC-PA-{idx+1:03d}"),
                rule_name=r_name,
                host=item.get("host", "UNKNOWN_HOST"),
                ioc=item.get("hashes", {}).get("SHA256", "—") if isinstance(item.get("hashes"), dict) else "—",
                user=item.get("user", "—"),
                severity=sev,
                count=1,
                first_seen=ts,
                last_seen=ts,
                notes=item.get("reasons", [f"Anomaly score: {score}"]),
                mitre_tactics=resolve_mitre_mapping(f"{r_name} {item.get('command_line', '')}"),
                raw=item
            ))
            continue

        # Day 6 / Generic SIEM alert format
        rule_name = item.get("rule_name", item.get("alert_name", item.get("title", f"Security Alert {idx+1}")))
        host = item.get("host", item.get("dest", item.get("computer_name", "UNKNOWN_HOST")))
        ioc = item.get("ioc", item.get("src_ip", item.get("ip", "—")))
        raw_users = item.get("users", item.get("user", item.get("username", item.get("user_name", "—"))))
        user_str = ", ".join(raw_users) if isinstance(raw_users, list) else str(raw_users)
        sev = item.get("severity", item.get("priority", "medium")).lower()

        results.append(PlaybookAlert(
            incident_id=item.get("incident_id", f"INC-{idx+1:04d}"),
            rule_name=rule_name,
            host=host,
            ioc=ioc,
            user=user_str or "—",
            severity=sev,
            count=item.get("count", 1),
            first_seen=item.get("first_seen", item.get("timestamp", "")),
            last_seen=item.get("last_seen", item.get("timestamp", "")),
            notes=item.get("notes", []),
            mitre_tactics=resolve_mitre_mapping(rule_name, ioc),
            raw=item
        ))

    return results


# ── Related Log Extraction ─────────────────────────────────────────

def extract_related_logs(alert: PlaybookAlert, logs: list[dict] | Path, window_minutes: int = 15) -> list[dict]:
    """Pull logs around incident timestamp window matching host, ioc, or user."""
    records: list[dict] = []
    if isinstance(logs, Path):
        if not logs.exists():
            return []
        log_files = [logs] if not logs.is_dir() else (list(logs.glob("*.json")) + list(logs.glob("*.jsonl")) + list(logs.glob("*.csv")))
        for lf in log_files:
            if lf.suffix.lower() == ".csv":
                try:
                    with open(lf, "r", encoding="utf-8", errors="replace") as cf:
                        for row in csv.DictReader(cf):
                            records.append(dict(row))
                except Exception:
                    continue
                continue
            try:
                raw = lf.read_text(encoding="utf-8", errors="replace").strip()
                if not raw:
                    continue
                try:
                    data = json.loads(raw)
                    if isinstance(data, list):
                        records.extend(data)
                    elif isinstance(data, dict):
                        for k in ("events", "logs", "records", "data"):
                            if k in data and isinstance(data[k], list):
                                records.extend(data[k])
                                break
                        else:
                            records.append(data)
                except json.JSONDecodeError:
                    for line in raw.splitlines():
                        line = line.strip()
                        if line:
                            try:
                                records.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
            except Exception:
                continue
    elif isinstance(logs, list):
        records = logs

    if not records:
        return []

    # Establish baseline timeframe
    ref_ts_str = alert.first_seen or alert.last_seen or datetime.now(timezone.utc).isoformat()
    ref_dt = _parse_ts(ref_ts_str)
    start_dt = ref_dt - timedelta(minutes=window_minutes)
    end_dt = _parse_ts(alert.last_seen or ref_ts_str) + timedelta(minutes=window_minutes)

    matched: list[dict] = []
    # Relevant identifiers
    identifiers = {alert.host.lower(), alert.ioc.lower(), alert.user.lower()}
    identifiers.discard("—")
    identifiers.discard("unknown_host")
    identifiers.discard("")

    for rec in records:
        # Check timestamp
        ts_val = rec.get("timestamp", rec.get("@timestamp", rec.get("_time", rec.get("time"))))
        if not ts_val:
            continue
        try:
            dt = _parse_ts(str(ts_val))
            if not (start_dt <= dt <= end_dt):
                continue
        except Exception:
            continue

        # Check entity correlation
        rec_str = json.dumps(rec).lower()
        if any(ident in rec_str for ident in identifiers):
            matched.append(rec)

    return matched


# ── Containment Staging & Safety Gate ──────────────────────────────

def stage_containment_actions(alert: PlaybookAlert) -> list[dict]:
    """Generate categorized containment actions for the incident (default: DRY-RUN)."""
    actions: list[dict] = []

    # 1. Network Containment (IP Blocking)
    if alert.ioc and alert.ioc != "—":
        actions.append({
            "category": "network_block",
            "action": f"Block Attacker IP ({alert.ioc}) at Perimeter",
            "command": (
                f"iptables -A INPUT -s {alert.ioc} -j DROP # Linux\n"
                f'netsh advfirewall firewall add rule name="SOC_Block_{alert.ioc}" dir=in action=block remoteip={alert.ioc} # Win'
            ),
            "status": "DRY-RUN / STAGED",
            "risk": "Low (Blocks external/attacker IP)",
        })

    # 2. Host Containment (Host Isolation)
    if alert.host and alert.host != "UNKNOWN_HOST":
        actions.append({
            "category": "host_isolation",
            "action": f"Isolate Compromised Host ({alert.host})",
            "command": (
                f"# CrowdStrike / SentinelOne API: isolate --device-id {alert.host}\n"
                f'netsh advfirewall set allprofiles state on; '
                f'netsh advfirewall firewall add rule name="SOC_Isolate" dir=in action=block'
            ),
            "status": "DRY-RUN / STAGED",
            "risk": "High (Network connectivity severed for endpoint)",
        })

    # 3. Identity Containment (Account Lockout)
    if alert.user and alert.user != "—":
        for u in [usr.strip() for usr in alert.user.split(",")]:
            if not u or u == "—":
                continue
            actions.append({
                "category": "account_containment",
                "action": f"Revoke Sessions & Disable Account ({u})",
                "command": (
                    f'Disable-LocalUser -Name "{u}"\n'
                    f'Revoke-AzureADUserAllRefreshToken -ObjectId "{u}"'
                ),
                "status": "DRY-RUN / STAGED",
                "risk": "Medium (Disrupts user active sessions)",
            })

    return actions


def execute_containment_actions(actions: list[dict], dry_run: bool = True, confirmed: bool = False) -> list[dict]:
    """Execute containment commands behind strict human-in-the-loop gate."""
    updated = []
    for act in actions:
        item = dict(act)
        if dry_run:
            item["status"] = "DRY-RUN / STAGED"
        elif not confirmed:
            item["status"] = "BLOCKED: Confirmation required"
        else:
            # Gated live execution simulator
            item["status"] = "EXECUTED (Simulated live containment action)"
        updated.append(item)
    return updated


# ── Ticket Generation ──────────────────────────────────────────────

def generate_ticket_template(alert: PlaybookAlert, related_logs: list[dict] | None = None) -> str:
    """Produce standardized Markdown incident ticket for ITSM / ticketing systems."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    staged = stage_containment_actions(alert)

    lines = [
        f"# SOC Incident Ticket: {alert.incident_id}",
        f"**Generated:** {now_str} | **Severity:** `{alert.severity.upper()}` | **Tool:** `playbook-runner v{VERSION}`\n",
        "## 1. Incident Overview",
        f"- **Detection Rule:** {alert.rule_name}",
        f"- **Target Asset:** `{alert.host}`",
        f"- **Observed IOC:** `{alert.ioc}`",
        f"- **Compromised User(s):** `{alert.user}`",
        f"- **Total Alert Volume:** {alert.count} events collapsed",
        f"- **Incident Timeline:** {alert.first_seen or 'N/A'} → {alert.last_seen or 'N/A'}\n",
    ]

    if alert.notes:
        lines.append("### Context & Asset Criticality")
        for note in alert.notes:
            lines.append(f"- ℹ️ {note}")
        lines.append("")

    lines.append("## 2. MITRE ATT&CK Mapping")
    for tactic in alert.mitre_tactics:
        lines.append(f"- **{tactic}**")
    lines.append("")

    if related_logs:
        lines.append(f"## 3. Related Forensic Timeline ({len(related_logs)} matched events)")
        lines.append("| Timestamp | Host / Device | Source IP | Event Summary |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for rec in related_logs[:15]:
            ts = rec.get("timestamp", rec.get("@timestamp", rec.get("_time", "—")))
            h = rec.get("host", rec.get("host.name", rec.get("dest", "—")))
            src = rec.get("src_ip", rec.get("source.ip", rec.get("source_ip", "—")))
            msg = rec.get("msg", rec.get("message", rec.get("EventID", rec.get("search_name", "Log Record"))))
            lines.append(f"| `{ts}` | `{h}` | `{src}` | {msg} |")
        if len(related_logs) > 15:
            lines.append(f"| ... | ... | ... | *(+{len(related_logs) - 15} additional events omitted for brevity)* |")
        lines.append("")

    lines.append("## 4. Containment & Response Checklist (Human-in-the-Loop)")
    lines.append("- [ ] **Triage Validation:** Confirm alert is true positive; rule out authorized pentest or maintenance.")
    lines.append("- [ ] **Host Forensic Collection:** Capture triage memory and volatile process artifacts before isolation.")
    lines.append("- [ ] **Network Containment:** Block perimeter attacker IP on border edge firewalls.")
    lines.append("- [ ] **Host Isolation:** Sever network connection of compromised host via EDR/firewall.")
    lines.append("- [ ] **Credential Remediation:** Revoke Azure AD / Active Directory session tokens & force password reset.")
    lines.append("- [ ] **Lateral Movement Audit:** Review neighboring hosts for SMB/RDP connections in log window.")
    lines.append("- [ ] **Management Escalation:** Notify Incident Commander and compliance if sensitive data exposed.\n")

    lines.append("## 5. Staged Containment Actions")
    for act in staged:
        lines.append(f"### Action: {act['action']}")
        lines.append(f"- **Category:** `{act['category']}` | **Risk:** `{act['risk']}` | **Status:** `{act['status']}`")
        lines.append("```bash")
        lines.append(act["command"])
        lines.append("```\n")

    return "\n".join(lines)


# ── Webhook Notification ───────────────────────────────────────────

def post_chat_webhook(webhook_url: str, alert: PlaybookAlert) -> bool:
    """Send formatted notification payload to chat webhook (Slack/Discord/Teams)."""
    payload = {
        "text": f"🚨 *SOC Incident Alert: {alert.incident_id}*",
        "attachments": [{
            "color": "danger" if alert.severity in ("critical", "high") else "warning",
            "title": f"{alert.severity.upper()}: {alert.rule_name}",
            "fields": [
                {"title": "Target Host", "value": alert.host, "short": True},
                {"title": "Source IOC", "value": alert.ioc, "short": True},
                {"title": "User Account", "value": alert.user, "short": True},
                {"title": "Event Count", "value": str(alert.count), "short": True},
            ],
            "footer": f"playbook-runner v{VERSION} · Human-in-the-loop containment staged",
            "ts": int(datetime.now(timezone.utc).timestamp()),
        }]
    }

    req_data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=req_data,
        headers={"Content-Type": "application/json", "User-Agent": f"playbook-runner/{VERSION}"}
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        print(f"Warning: Webhook dispatch failed: {e}", file=sys.stderr)
        return False


# ── Terminal Display Helpers ───────────────────────────────────────

def display_cli_summary(alerts: list[PlaybookAlert], staged_actions: list[dict], live_status: str) -> None:
    """Output high-clarity SOC summary to the console."""
    if RICH:
        console = Console()
        console.print(Panel(
            f"[bold cyan]{BANNER}[/bold cyan]\n"
            f"[bold white]Incidents Loaded:[/bold white] {len(alerts)} | "
            f"[bold white]Mode:[/bold white] [bold yellow]{live_status}[/bold yellow]",
            box=box.ROUNDED,
            border_style="cyan"
        ))

        t = Table(title="Staged Incident Playbooks", box=box.SIMPLE_HEAVY)
        t.add_column("Incident ID", style="bold cyan")
        t.add_column("Severity", style="bold")
        t.add_column("Rule Name", style="white")
        t.add_column("Target Host", style="green")
        t.add_column("IOC", style="red")
        t.add_column("Count", justify="center")

        for a in alerts:
            sev_style = "red bold" if a.severity in ("critical", "high") else "yellow"
            t.add_row(a.incident_id, f"[{sev_style}]{a.severity.upper()}[/{sev_style}]", a.rule_name, a.host, a.ioc, str(a.count))

        console.print(t)

        console.print("\n[bold yellow]Staged Containment Actions (Human-in-the-Loop Safe):[/bold yellow]")
        for act in staged_actions:
            console.print(f"  • [bold]{act['action']}[/bold] — Status: [green]{act['status']}[/green] (Risk: {act['risk']})")
    else:
        print(f"\n===========================================================================")
        print(f"  {BANNER}")
        print(f"  Incidents Loaded: {len(alerts)} | Execution Mode: {live_status}")
        print(f"===========================================================================\n")
        for a in alerts:
            print(f"  [{a.incident_id}] {a.severity.upper()} — {a.rule_name} on {a.host} (IOC: {a.ioc})")
        print("\n  Staged Containment Actions:")
        for act in staged_actions:
            print(f"    - {act['action']} [{act['status']}]")


# ── CLI Argument Parser ────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="playbook-runner.py",
        description="Automated Response Playbook Runner (Read-Only First) · Day 7",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("incident_file", type=Path, help="JSON file containing alert(s) from Days 1, 2, 5, or Day 6 dedup")
    p.add_argument("--incident-id", type=str, default=None, help="target a specific incident ID from the input batch")
    p.add_argument("--all", action="store_true", help="process all incidents in the batch file")
    p.add_argument("--logs", type=Path, default=None, help="raw log file or directory (JSON/JSONL/CSV) for timeline context correlation")
    p.add_argument("--window", type=int, default=15, help="context time window in minutes for related log search (default: 15)")
    p.add_argument("-o", "--output-ticket", type=Path, default=None, help="destination Markdown file for generated SOC ticket")
    p.add_argument("--output-json", type=Path, default=None, help="export full execution plan and staged commands to JSON")
    p.add_argument("--webhook", type=str, default=None, help="chat incoming webhook URL (Slack/Discord/Teams)")
    p.add_argument("--execute", action="store_true", help="request live containment execution (default: dry-run only)")
    p.add_argument("--confirm", action="store_true", help="explicit human authorization to proceed with live execution")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress interactive console headers")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {VERSION}")
    return p


# ── Main Entrypoint ────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    inc_file: Path = args.incident_file

    if not inc_file.exists():
        print(f"Error: incident file not found: {inc_file}", file=sys.stderr)
        sys.exit(1)

    alerts = parse_input_alerts(inc_file)
    if not alerts:
        print(f"Error: No actionable incidents found in {inc_file.name}", file=sys.stderr)
        sys.exit(1)

    # Resolve target incident(s)
    if args.incident_id:
        matched = [a for a in alerts if a.incident_id.lower() == args.incident_id.lower()]
        if not matched:
            avail = ", ".join(a.incident_id for a in alerts[:8])
            print(f"Error: Incident ID '{args.incident_id}' not found. Available: {avail}", file=sys.stderr)
            sys.exit(1)
        targets = matched
    elif args.all:
        targets = alerts
    else:
        targets = [alerts[0]]

    # Stage containment actions across targets
    all_staged = []
    ticket_sections = []
    total_logs_matched = 0

    for item in targets:
        r_logs = extract_related_logs(item, args.logs, window_minutes=args.window) if args.logs else []
        total_logs_matched += len(r_logs)
        t_md = generate_ticket_template(item, related_logs=r_logs)
        ticket_sections.append(t_md)
        all_staged.extend(stage_containment_actions(item))

    # Determine execution status
    is_dry_run = not args.execute
    if args.execute and not args.confirm:
        print("\n  [SAFETY GATE] Live execution requested without --confirm flag.", file=sys.stderr)
        print("  Containment actions BLOCKED. Re-run with --confirm to authorize live execution.\n", file=sys.stderr)
        executed_actions = execute_containment_actions(all_staged, dry_run=False, confirmed=False)
        mode_label = "BLOCKED (Missing Confirmation)"
    elif args.execute and args.confirm:
        executed_actions = execute_containment_actions(all_staged, dry_run=False, confirmed=True)
        mode_label = "LIVE EXECUTED (Human Authorized)"
    else:
        executed_actions = execute_containment_actions(all_staged, dry_run=True, confirmed=False)
        mode_label = "READ-ONLY / DRY-RUN (Safe)"

    # Generate Markdown ticket
    ticket_md = "\n\n---\n\n".join(ticket_sections)
    if args.output_ticket:
        args.output_ticket.write_text(ticket_md, encoding="utf-8")
        if not args.quiet:
            print(f"  ✓ SOC Incident Ticket saved to {args.output_ticket}", file=sys.stderr)

    # Optional JSON export
    if args.output_json:
        export_payload = {
            "tool": "playbook-runner",
            "version": VERSION,
            "incidents": [t.to_dict() for t in targets],
            "related_logs_count": total_logs_matched,
            "containment_actions": executed_actions,
            "mode": mode_label,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
        args.output_json.write_text(json.dumps(export_payload, indent=2), encoding="utf-8")
        if not args.quiet:
            print(f"  ✓ JSON execution report saved to {args.output_json}", file=sys.stderr)

    # Webhook dispatch if requested
    if args.webhook:
        for t in targets:
            post_chat_webhook(args.webhook, t)
        if not args.quiet:
            print(f"  ✓ Incident notification(s) dispatched to webhook.", file=sys.stderr)

    # Console display
    if not args.quiet:
        display_cli_summary(targets, executed_actions, mode_label)
        if not args.output_ticket and not args.output_json:
            print("\n" + "=" * 75)
            print("  PREVIEW: SOC Incident Ticket Template (Markdown)")
            print("=" * 75 + "\n")
            print(ticket_md)

    # Exit code: 0 for successful safe/live run, 1 if blocked
    if args.execute and not args.confirm:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
