#!/usr/bin/env python3
"""
phishing-triage.py — Phishing & Malicious Email Triage Helper
============================================================
SOC Automation Toolkit · Day 4

Parses .eml or raw email messages, performs security triage:
  • Header spoofing & Reply-To domain mismatch
  • SPF, DKIM, and DMARC authentication result analysis
  • Hyperlink & anchor-text mismatch detection
  • Attachment extraction, hashing (MD5/SHA256), and dangerous extension flagging
  • Urgency & credential-harvesting keyword heuristics
  • Optional Day 3 threat intelligence enrichment (--enrich)
  • False-positive suppression via sender domain allowlisting

Usage:
    python phishing-triage.py sample.eml
    python phishing-triage.py sample.eml --output markdown -o ticket_triage.md
    python phishing-triage.py sample.eml --enrich --output json
    python phishing-triage.py sample.eml --allowlist trusted_domains.txt
"""

from __future__ import annotations

import argparse
import email
import email.policy
import hashlib
import html.parser
import importlib.util
import io
import json
import re
import sys
import zipfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
BANNER = f"phishing-triage v{VERSION} — SOC Automation Toolkit · Day 4"

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".hta", ".iso", ".img", ".bat",
    ".cmd", ".ps1", ".js", ".jse", ".wsf", ".docm", ".xlsm",
    ".pptm", ".jar", ".cpl", ".dll", ".lnk",
}

SUSPICIOUS_KEYWORDS = [
    "wire transfer", "urgent action", "immediate payment",
    "verify your account", "password expire", "suspended account",
    "gift card", "payroll update", "direct deposit", "tax refund",
    "invoice overdue", "unauthorized login", "action required immediately",
]

_URL_RE = re.compile(r"https?://[^\s<>'\"()]+", re.IGNORECASE)
_EMAIL_ADDR_RE = re.compile(r"[\w\.-]+@([\w\.-]+\.[a-zA-Z]{2,})")
_IP_URL_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s]*)?", re.IGNORECASE)
_DOUBLE_EXT_RE = re.compile(r"\.[a-zA-Z0-9]{2,4}\.(exe|scr|vbs|hta|bat|js|iso|img|cmd|ps1)$", re.IGNORECASE)

SEVERITY_COLORS = {
    "malicious": "red bold",
    "suspicious": "yellow bold",
    "low_risk": "cyan",
    "clean": "green",
    "benign": "green",
}


# ── Data Models ────────────────────────────────────────────────────

@dataclass(slots=True)
class TriageResult:
    """Consolidated triage analysis for a submitted email message."""
    sender: str
    sender_domain: str
    recipient: str
    subject: str
    date: str
    reply_to: str
    reply_to_mismatch: bool
    display_name_spoofed: bool
    spf_status: str
    dkim_status: str
    dmarc_status: str
    urls: list[dict]
    attachments: list[dict]
    findings: list[str]
    risk_score: int
    verdict: str  # malicious | suspicious | low_risk | clean
    tags: list[str]
    enrichment: dict | None = None

    def to_dict(self) -> dict:
        return asdict(self)


# ── HTML Anchor Parser ─────────────────────────────────────────────

class HTMLAnchorExtractor(html.parser.HTMLParser):
    """Extracts hyperlinks and corresponding anchor text from HTML email bodies."""

    def __init__(self):
        super().__init__()
        self.links: list[dict] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            for k, v in attrs:
                if k.lower() == "href" and v:
                    self._current_href = v.strip()
                    self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current_href is not None:
            anchor_text = "".join(self._current_text).strip()
            self.links.append({"href": self._current_href, "text": anchor_text})
            self._current_href = None
            self._current_text = []


# ── Extraction & Heuristic Helpers ─────────────────────────────────

import urllib.parse

def inspect_attachment_payload(filename: str, payload: bytes) -> dict[str, Any]:
    """Inspect attachment payload for embedded VBA macros and hidden archive files."""
    flags: dict[str, Any] = {
        "has_embedded_macro": False,
        "archive_files": [],
        "archive_has_dangerous_file": False,
    }
    if not payload:
        return flags

    # 1. Check ZIP container (covers .zip, .docx, .xlsx, .docm, .xlsm, etc.)
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            namelist = zf.namelist()
            flags["archive_files"] = namelist[:10]
            for name in namelist:
                n_lower = name.lower()
                if "vbaproject.bin" in n_lower or "vba/" in n_lower:
                    flags["has_embedded_macro"] = True
                ext = Path(name).suffix.lower()
                if ext in DANGEROUS_EXTENSIONS or bool(_DOUBLE_EXT_RE.search(name)):
                    flags["archive_has_dangerous_file"] = True
    except (zipfile.BadZipFile, Exception):
        pass

    # 2. Check legacy OLE files (.doc, .xls) for VBA markers
    if payload.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        if b"VBA" in payload or b"_VBA_PROJECT" in payload or b"Macros" in payload:
            flags["has_embedded_macro"] = True

    return flags


def _extract_domain(addr_or_url: str) -> str:
    """Extract clean domain from email address or URL."""
    s = addr_or_url.strip()
    if s.startswith("http://") or s.startswith("https://"):
        try:
            return (urllib.parse.urlparse(s).hostname or "").lower()
        except Exception:
            return ""
    m = _EMAIL_ADDR_RE.search(s)
    if m:
        return m.group(1).lower()
    try:
        parsed = urllib.parse.urlparse("//" + s)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def extract_urls_from_body(body: str, is_html: bool = False) -> list[dict]:
    """Extract unique URLs and detect anchor text vs href discrepancies."""
    results: list[dict] = []
    seen_hrefs = set()

    if is_html:
        parser = HTMLAnchorExtractor()
        try:
            parser.feed(body)
            for link in parser.links:
                href = link["href"]
                text = link["text"]
                if href in seen_hrefs:
                    continue
                seen_hrefs.add(href)

                mismatch = False
                # If anchor text looks like a URL pointing somewhere else
                if text.startswith("http://") or text.startswith("https://"):
                    mismatch = _extract_domain(text) != _extract_domain(href)

                is_ip = bool(_IP_URL_RE.match(href))
                results.append({
                    "href": href,
                    "anchor_text": text,
                    "mismatch": mismatch,
                    "is_ip_url": is_ip,
                })
        except Exception:
            pass

    # Regex fallback / additional search in plain text
    for match in _URL_RE.finditer(body):
        url = match.group(0).rstrip(".,;!>)\"'")
        if url not in seen_hrefs:
            seen_hrefs.add(url)
            results.append({
                "href": url,
                "anchor_text": "",
                "mismatch": False,
                "is_ip_url": bool(_IP_URL_RE.match(url)),
            })

    return results


def check_auth_headers(msg: email.message.EmailMessage) -> tuple[str, str, str]:
    """Parse SPF, DKIM, and DMARC results from standard security headers."""
    auth_header = msg.get("Authentication-Results", "")
    spf_header = msg.get("Received-SPF", "")

    combined = f"{auth_header} {spf_header}".lower()

    def _extract_status(tag: str) -> str:
        # Matches e.g. "spf=pass", "dkim=fail (test)", "dmarc=none"
        m = re.search(rf"{tag}\s*=\s*([a-zA-Z]+)", combined)
        if m:
            val = m.group(1).lower()
            if val in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"):
                return val
        if tag == "spf" and "received-spf:" in combined:
            if "pass" in combined:
                return "pass"
            if "fail" in combined:
                return "fail"
        return "none"

    spf = _extract_status("spf")
    dkim = _extract_status("dkim")
    dmarc = _extract_status("dmarc")

    return spf, dkim, dmarc


# ── Day 3 Threat Intel Integration ─────────────────────────────────

def _enrich_iocs_via_day3(urls: list[str], hashes: list[str]) -> dict:
    """Optionally leverage Day 3 ioc-enricher to check URLs and attachment hashes."""
    enrichment_data: dict[str, Any] = {"urls": {}, "hashes": {}}
    root = Path(__file__).resolve().parent

    enricher_path = None
    for cand in ("ioc-enricher.py", "ioc_enricher.py"):
        p = root / cand
        if p.exists():
            enricher_path = p
            break

    if not enricher_path:
        return enrichment_data

    try:
        spec = importlib.util.spec_from_file_location("ioc_enricher", enricher_path)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            sys.modules["ioc_enricher"] = mod
            spec.loader.exec_module(mod)
            enrich_fn = getattr(mod, "enrich_ioc", None)
            if enrich_fn:
                for url in urls[:5]:
                    res = enrich_fn(url)
                    enrichment_data["urls"][url] = res.to_dict()
                for h in hashes[:5]:
                    res = enrich_fn(h)
                    enrichment_data["hashes"][h] = res.to_dict()
    except Exception:
        pass

    return enrichment_data


# ── Core Triage Engine ─────────────────────────────────────────────

def parse_eml(file_or_str: Path | str) -> email.message.EmailMessage:
    """Parse EML file or raw string into EmailMessage."""
    if isinstance(file_or_str, Path):
        raw_bytes = file_or_str.read_bytes()
        return email.message_from_bytes(raw_bytes, policy=email.policy.default)
    return email.message_from_string(str(file_or_str), policy=email.policy.default)


def triage_email(
    eml_input: email.message.EmailMessage | Path | str,
    allowlist_domains: set[str] | None = None,
    enrich: bool = False,
) -> TriageResult:
    """Analyze an email message and return structured triage findings."""
    msg = parse_eml(eml_input) if not isinstance(eml_input, email.message.EmailMessage) else eml_input
    allowlist_domains = {d.lower() for d in (allowlist_domains or set())}

    sender = str(msg.get("From", "UNKNOWN"))
    sender_domain = _extract_domain(sender)
    recipient = str(msg.get("To", "UNKNOWN"))
    subject = str(msg.get("Subject", "(No Subject)"))
    date = str(msg.get("Date", "UNKNOWN"))
    reply_to = str(msg.get("Reply-To", ""))

    reply_to_domain = _extract_domain(reply_to) if reply_to else ""
    reply_to_mismatch = bool(reply_to_domain and sender_domain and reply_to_domain != sender_domain)

    # Display name spoofing: e.g. "Security Team <attacker@external.xyz>"
    display_name_spoofed = False
    display_name_email = _EMAIL_ADDR_RE.search(sender.split("<")[0])
    if display_name_email:
        if display_name_email.group(1).lower() != sender_domain:
            display_name_spoofed = True

    spf_status, dkim_status, dmarc_status = check_auth_headers(msg)

    # Body and attachment parsing
    body_text = ""
    body_html = ""
    attachments: list[dict] = []

    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", "")).lower()
        filename = part.get_filename() or ""

        if part.is_multipart():
            continue

        if "attachment" in content_disposition or filename:
            payload = part.get_payload(decode=True) or b""
            ext = Path(filename).suffix.lower() if filename else ""
            is_danger = ext in DANGEROUS_EXTENSIONS or bool(_DOUBLE_EXT_RE.search(filename))
            inspection = inspect_attachment_payload(filename, payload)
            if inspection["has_embedded_macro"] or inspection["archive_has_dangerous_file"]:
                is_danger = True

            md5_hash = hashlib.md5(payload).hexdigest()
            sha256_hash = hashlib.sha256(payload).hexdigest()

            attachments.append({
                "filename": filename or "unnamed_attachment",
                "size_bytes": len(payload),
                "extension": ext,
                "is_dangerous_extension": is_danger,
                "has_embedded_macro": inspection["has_embedded_macro"],
                "archive_files": inspection["archive_files"],
                "archive_has_dangerous_file": inspection["archive_has_dangerous_file"],
                "md5": md5_hash,
                "sha256": sha256_hash,
            })
        else:
            ctype = part.get_content_type()
            try:
                content = part.get_content()
                if isinstance(content, str):
                    if ctype == "text/html":
                        body_html += content
                    else:
                        body_text += content
            except Exception:
                pass

    # Extract and analyze URLs
    urls = extract_urls_from_body(body_html, is_html=True)
    urls.extend(extract_urls_from_body(body_text, is_html=False))

    # Deduplicate URLs by href
    unique_urls = []
    seen = set()
    for u in urls:
        if u["href"] not in seen:
            seen.add(u["href"])
            unique_urls.append(u)

    # ── Score & Finding Accumulator ───────────────────────────────
    findings: list[str] = []
    tags: set[str] = set()
    score = 0

    if reply_to_mismatch:
        score += 35
        findings.append(f"Reply-To domain mismatch: Sender '{sender_domain}' != Reply-To '{reply_to_domain}'")
        tags.add("reply_to_mismatch")

    if display_name_spoofed:
        score += 30
        findings.append(f"Display name spoofing detected in '{sender}'")
        tags.add("display_name_spoof")

    if spf_status in ("fail", "softfail"):
        score += 25
        findings.append(f"SPF authentication failed: {spf_status}")
        tags.add("spf_fail")

    if dkim_status == "fail":
        score += 25
        findings.append("DKIM authentication failed")
        tags.add("dkim_fail")

    if dmarc_status == "fail":
        score += 30
        findings.append("DMARC verification failed")
        tags.add("dmarc_fail")

    # Attachment checks
    for att in attachments:
        if att.get("has_embedded_macro"):
            score += 50
            findings.append(f"Embedded VBA macro project detected: {att['filename']}")
            tags.add("embedded_macro")
        if att.get("archive_has_dangerous_file"):
            score += 50
            findings.append(f"Dangerous executable found inside archive attachment: {att['filename']}")
            tags.add("archive_dangerous_content")
        if _DOUBLE_EXT_RE.search(att["filename"]):
            score += 50
            findings.append(f"Dangerous double extension detected: {att['filename']}")
            tags.add("double_extension")
        elif att["is_dangerous_extension"] and not att.get("has_embedded_macro") and not att.get("archive_has_dangerous_file"):
            score += 45
            findings.append(f"Dangerous attachment extension: {att['filename']}")
            tags.add("dangerous_attachment")

    # URL checks
    for u in unique_urls:
        if u["mismatch"]:
            score += 40
            findings.append(f"Anchor text and destination href mismatch: text '{u['anchor_text']}' -> link '{u['href']}'")
            tags.add("link_text_mismatch")
        if u["is_ip_url"]:
            score += 25
            findings.append(f"IP-based hyperlink in body: {u['href']}")
            tags.add("ip_url")

    # Keyword check
    combined_body = f"{subject} {body_text} {body_html}".lower()
    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in combined_body]
    if keyword_hits:
        score += min(25, len(keyword_hits) * 10)
        findings.append(f"Urgency / phishing keywords found: {', '.join(keyword_hits[:3])}")
        tags.add("suspicious_keywords")

    # Day 3 threat intelligence enrichment
    enrichment_result = None
    if enrich and (unique_urls or attachments):
        url_targets = [u["href"] for u in unique_urls]
        hash_targets = [a["sha256"] for a in attachments]
        enrichment_result = _enrich_iocs_via_day3(url_targets, hash_targets)

        # Elevate score if intel flagged any artifact
        for _, u_data in enrichment_result.get("urls", {}).items():
            if u_data.get("verdict") == "malicious":
                score = max(score, 90)
                findings.append(f"Threat intelligence confirmed malicious URL: {u_data.get('ioc')}")
                tags.add("intel_malicious_url")
        for _, h_data in enrichment_result.get("hashes", {}).items():
            if h_data.get("verdict") == "malicious":
                score = max(score, 95)
                findings.append(f"Threat intelligence confirmed malware hash: {h_data.get('ioc')}")
                tags.add("intel_malware_hash")

    # Allowlist dampening
    if sender_domain in allowlist_domains:
        tags.add("allowlisted")
        # Unless an explicit dangerous executable attachment was present
        if not any(a["is_dangerous_extension"] for a in attachments):
            score = min(score, 15)

    final_score = min(100, score)

    if final_score >= 70:
        verdict = "malicious"
    elif final_score >= 40:
        verdict = "suspicious"
    elif final_score >= 15:
        verdict = "low_risk"
    else:
        verdict = "clean"

    return TriageResult(
        sender=sender,
        sender_domain=sender_domain,
        recipient=recipient,
        subject=subject,
        date=date,
        reply_to=reply_to,
        reply_to_mismatch=reply_to_mismatch,
        display_name_spoofed=display_name_spoofed,
        spf_status=spf_status,
        dkim_status=dkim_status,
        dmarc_status=dmarc_status,
        urls=unique_urls,
        attachments=attachments,
        findings=findings,
        risk_score=final_score,
        verdict=verdict,
        tags=sorted(tags),
        enrichment=enrichment_result,
    )


# ── Output Formatters ─────────────────────────────────────────────

def format_markdown_report(res: TriageResult) -> str:
    """Format markdown report suitable for SOC incident ticketing."""
    lines = [
        "## Phishing Email Triage Report",
        f"**Analyzed:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Verdict:** **{res.verdict.upper()}** (Risk Score: **{res.risk_score}/100**)  ",
        f"**Tags:** {', '.join(f'`{t}`' for t in res.tags) if res.tags else 'None'}  ",
        "",
        "### Message Metadata",
        f"- **From:** `{res.sender}`",
        f"- **To:** `{res.recipient}`",
        f"- **Subject:** `{res.subject}`",
        f"- **Date:** `{res.date}`",
        f"- **Reply-To:** `{res.reply_to or 'None'}`" + (" ⚠️ **(MISMATCH)**" if res.reply_to_mismatch else ""),
        "",
        "### Authentication Results",
        f"- **SPF:** `{res.spf_status.upper()}`",
        f"- **DKIM:** `{res.dkim_status.upper()}`",
        f"- **DMARC:** `{res.dmarc_status.upper()}`",
        "",
        "### Key Security Findings",
    ]
    if res.findings:
        for f in res.findings:
            lines.append(f"- ⚠️ {f}")
    else:
        lines.append("- ✓ No security anomalies or authentication failures detected.")

    lines.append("\n### Attachments")
    if res.attachments:
        for a in res.attachments:
            danger_warn = " 🚨 **(HIGH RISK EXTENSION)**" if a["is_dangerous_extension"] else ""
            lines.append(f"- **{a['filename']}** ({a['size_bytes']:,} bytes){danger_warn}")
            lines.append(f"  - SHA256: `{a['sha256']}`")
    else:
        lines.append("- No file attachments.")

    lines.append("\n### Extracted Hyperlinks")
    if res.urls:
        for u in res.urls[:10]:
            warn = " ⚠️ *(ANCHOR MISMATCH)*" if u["mismatch"] else ""
            lines.append(f"- `{u['href']}`{warn}")
    else:
        lines.append("- No embedded URLs found.")

    return "\n".join(lines)


def format_table_output(res: TriageResult) -> None:
    """Format terminal UI summary with Rich table or plain-text fallback."""
    if RICH:
        con = Console(stderr=True)
        con.print(Panel(f"[bold]{BANNER}[/bold]", box=box.ROUNDED))

        sc = SEVERITY_COLORS.get(res.verdict, "white")
        con.print(
            f"  Verdict: [{sc}]{res.verdict.upper()}[/{sc}]  |  "
            f"Score: [bold]{res.risk_score}/100[/bold]  |  "
            f"Sender: [cyan]{res.sender}[/cyan]\n"
        )

        tbl = Table(box=box.SIMPLE_HEAVY, show_lines=True)
        tbl.add_column("Category", style="bold", width=18)
        tbl.add_column("Details")

        tbl.add_row("Subject", res.subject)
        tbl.add_row("From / Reply-To", f"{res.sender}\nReply-To: {res.reply_to or '-'}")
        tbl.add_row(
            "Authentication",
            f"SPF: {res.spf_status.upper()} | DKIM: {res.dkim_status.upper()} | DMARC: {res.dmarc_status.upper()}"
        )

        findings_text = "\n".join(f"• {f}" for f in res.findings) if res.findings else "Clean"
        tbl.add_row("Key Findings", findings_text)

        att_text = "\n".join(
            f"• {a['filename']} ({a['size_bytes']:,}B) [{'red' if a['is_dangerous_extension'] else 'green'}]"
            for a in res.attachments
        ) if res.attachments else "None"
        tbl.add_row("Attachments", att_text)

        urls_text = "\n".join(f"• {u['href']}" for u in res.urls[:5]) if res.urls else "None"
        tbl.add_row("Extracted Links", urls_text)

        con.print(tbl)
    else:
        print(f"\n{'=' * 75}\n  {BANNER}")
        print(f"  Verdict: {res.verdict.upper()} (Risk Score: {res.risk_score}/100)")
        print(f"  Sender:  {res.sender}")
        print(f"  Subject: {res.subject}")
        print(f"  Auth:    SPF={res.spf_status.upper()}, DKIM={res.dkim_status.upper()}, DMARC={res.dmarc_status.upper()}")
        print(f"{'=' * 75}")
        if res.findings:
            print("  Findings:")
            for f in res.findings:
                print(f"    • {f}")
        if res.attachments:
            print("  Attachments:")
            for a in res.attachments:
                danger = " [HIGH RISK]" if a["is_dangerous_extension"] else ""
                print(f"    • {a['filename']} ({a['size_bytes']} bytes){danger}")
        if res.urls:
            print("  Links:")
            for u in res.urls[:5]:
                print(f"    • {u['href']}")
        print()


# ── Allowlist Loader ───────────────────────────────────────────────

def load_allowlist(path: Path | None) -> set[str]:
    """Load trusted domains from a file (one domain per line)."""
    domains: set[str] = set()
    if not path or not path.exists():
        return domains
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        item = line.strip().lower()
        if item and not item.startswith("#"):
            domains.add(item)
    return domains


# ── CLI ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishing-triage",
        description=(
            "Triage suspicious email (.eml) messages for phishing indicators,\n"
            "authentication failures (SPF/DKIM/DMARC), spoofing, and malicious attachments."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s email.eml\n"
            "  %(prog)s email.eml --output markdown -o ticket_summary.md\n"
            "  %(prog)s email.eml --enrich --output json\n"
            "  %(prog)s email.eml --allowlist trusted_domains.txt\n"
        ),
    )
    p.add_argument("eml_file", nargs="?", type=Path, default=None,
                   help="path to .eml file (or piped via stdin)")
    p.add_argument("--enrich", action="store_true",
                   help="enrich extracted URLs and attachment hashes via Day 3 ioc-enricher")
    p.add_argument("--allowlist", type=Path, default=None, metavar="FILE",
                   help="file containing trusted sender domains to suppress false positives")
    p.add_argument("--output", choices=["table", "markdown", "json"], default="table",
                   help="output format (default: table)")
    p.add_argument("-o", "--output-file", type=Path, default=None, metavar="PATH",
                   help="write report to destination file")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress headers and progress")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)

    raw_input = ""
    if args.eml_file:
        if not args.eml_file.exists():
            print(f"Error: file not found: {args.eml_file}", file=sys.stderr)
            sys.exit(1)
        eml_msg = parse_eml(args.eml_file)
    elif not sys.stdin.isatty():
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            print("Error: Empty email input provided via stdin.", file=sys.stderr)
            sys.exit(1)
        eml_msg = parse_eml(raw_input)
    else:
        print("Error: Please provide a .eml file path or pipe email content via stdin.", file=sys.stderr)
        sys.exit(1)

    allowlist_domains = load_allowlist(args.allowlist)
    if allowlist_domains and not args.quiet:
        print(f"  ✓ Loaded {len(allowlist_domains)} allowlisted domains", file=sys.stderr)

    result = triage_email(eml_msg, allowlist_domains=allowlist_domains, enrich=args.enrich)

    match args.output:
        case "markdown":
            md = format_markdown_report(result)
            if args.output_file:
                args.output_file.write_text(md, encoding="utf-8")
                if not args.quiet:
                    print(f"  ✓ Markdown report saved to {args.output_file}", file=sys.stderr)
            else:
                print(md)
        case "json":
            json_str = json.dumps(result.to_dict(), indent=2)
            if args.output_file:
                args.output_file.write_text(json_str, encoding="utf-8")
                if not args.quiet:
                    print(f"  ✓ JSON report saved to {args.output_file}", file=sys.stderr)
            else:
                print(json_str)
        case _:
            if args.output_file:
                args.output_file.write_text(format_markdown_report(result), encoding="utf-8")
            format_table_output(result)

    if result.verdict == "malicious":
        sys.exit(2)
    elif result.verdict == "suspicious":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
