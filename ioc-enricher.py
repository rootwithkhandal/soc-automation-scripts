#!/usr/bin/env python3
"""
ioc-enricher.py — Lightweight IOC Enrichment & Reputation Scorer
=================================================================
SOC Automation Toolkit · Day 3

Takes IPs, domains, hashes, or URLs, queries public threat intelligence
sources (VirusTotal, AbuseIPDB, URLhaus, GreyNoise, AlienVault OTX),
aggregates risk into a normalized score + tags, and caches results locally.

Usage:
    python ioc-enricher.py 8.8.8.8 198.51.100.4
    python ioc-enricher.py -f suspicious_iocs.txt --output markdown
    python ioc-enricher.py 44d88612fea8a8f36de82e1278abb02f --output json
    python ioc-enricher.py --offline 10.0.1.5 evil-domain.com
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
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
BANNER = f"ioc-enricher v{VERSION} — SOC Automation Toolkit · Day 3"

DEFAULT_CACHE_PATH = Path(".cache") / "ioc_cache.sqlite"
DEFAULT_TTL_HOURS = 24
HTTP_TIMEOUT_SECONDS = 5.0

SEVERITY_COLORS = {
    "malicious": "red bold",
    "suspicious": "yellow bold",
    "low_risk": "cyan",
    "benign": "green",
    "clean": "green",
    "unverified": "dim white",
}

# ── Regex Matchers ────────────────────────────────────────────────

_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


# ── Data Models ────────────────────────────────────────────────────

@dataclass(slots=True)
class EnrichmentResult:
    """Consolidated enrichment findings for a single IOC."""
    ioc: str
    ioc_type: str
    risk_score: int         # 0 - 100
    verdict: str            # malicious | suspicious | low_risk | benign | unverified
    tags: list[str]
    sources: dict
    cached: bool = False
    checked_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── IOC Detection ──────────────────────────────────────────────────

def detect_ioc_type(ioc: str) -> str:
    """Classify input string into an IOC category."""
    s = ioc.strip()
    if not s:
        return "unknown"
    if s.startswith("http://") or s.startswith("https://"):
        return "url"
    if _MD5_RE.match(s):
        return "md5"
    if _SHA1_RE.match(s):
        return "sha1"
    if _SHA256_RE.match(s):
        return "sha256"
    m = _IPV4_RE.match(s)
    if m:
        if all(0 <= int(octet) <= 255 for octet in m.groups()):
            return "ip"
        return "unknown"
    if _DOMAIN_RE.match(s):
        return "domain"
    return "unknown"


# ── Local SQLite Cache ─────────────────────────────────────────────

class IOCCache:
    """Thread-safe, file-backed SQLite cache with configurable TTL."""

    def __init__(self, db_path: Path, ttl_hours: int = DEFAULT_TTL_HOURS):
        self.db_path = db_path
        self.ttl_hours = ttl_hours
        self._init_db()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ioc_cache (
                    ioc TEXT PRIMARY KEY,
                    ioc_type TEXT,
                    risk_score INTEGER,
                    verdict TEXT,
                    tags TEXT,
                    sources_json TEXT,
                    cached_at TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def get(self, ioc: str) -> EnrichmentResult | None:
        ioc_norm = ioc.strip().lower()
        conn = sqlite3.connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT ioc_type, risk_score, verdict, tags, sources_json, cached_at FROM ioc_cache WHERE ioc = ?",
                (ioc_norm,)
            ).fetchone()
            if not row:
                return None

            ioc_type, score, verdict, tags_raw, sources_json, cached_at_str = row
            try:
                cached_at = datetime.fromisoformat(cached_at_str)
            except ValueError:
                return None

            # TTL check
            if datetime.now(timezone.utc) - cached_at > timedelta(hours=self.ttl_hours):
                return None

            return EnrichmentResult(
                ioc=ioc,
                ioc_type=ioc_type,
                risk_score=score,
                verdict=verdict,
                tags=json.loads(tags_raw) if tags_raw else [],
                sources=json.loads(sources_json) if sources_json else {},
                cached=True,
                checked_at=cached_at_str,
            )
        finally:
            conn.close()

    def set(self, result: EnrichmentResult) -> None:
        ioc_norm = result.ioc.strip().lower()
        now_str = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO ioc_cache
                (ioc, ioc_type, risk_score, verdict, tags, sources_json, cached_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ioc_norm,
                    result.ioc_type,
                    result.risk_score,
                    result.verdict,
                    json.dumps(result.tags),
                    json.dumps(result.sources),
                    now_str,
                )
            )
            conn.commit()
        finally:
            conn.close()


# ── Threat Intel Provider Connectors ──────────────────────────────

def _http_get(url: str, headers: dict | None = None) -> dict | None:
    """Perform HTTP GET with standard urllib, returning decoded JSON dict."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            data = resp.read().decode("utf-8", errors="replace")
            return json.loads(data)
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return None


def _http_post(url: str, data: dict, headers: dict | None = None) -> dict | None:
    """Perform HTTP POST with standard urllib (form encoded)."""
    encoded_data = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=encoded_data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            resp_data = resp.read().decode("utf-8", errors="replace")
            return json.loads(resp_data)
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return None


def query_urlhaus(ioc: str, ioc_type: str) -> dict | None:
    """Query Abuse.ch URLhaus (Public, no auth token required)."""
    endpoint = "https://urlhaus-api.abuse.ch/v1/"
    if ioc_type == "url":
        res = _http_post(endpoint + "url/", {"url": ioc})
    elif ioc_type in ("md5", "sha256"):
        field = "md5_hash" if ioc_type == "md5" else "sha256_hash"
        res = _http_post(endpoint + "payload/", {field: ioc})
    elif ioc_type in ("domain", "ip"):
        res = _http_post(endpoint + "host/", {"host": ioc})
    else:
        return None

    if not res or res.get("query_status") != "ok":
        return None
    return res


def query_virustotal(ioc: str, ioc_type: str, api_key: str) -> dict | None:
    """Query VirusTotal v3 API."""
    if not api_key:
        return None
    cat_map = {
        "ip": f"ip_addresses/{ioc}",
        "domain": f"domains/{ioc}",
        "md5": f"files/{ioc}",
        "sha1": f"files/{ioc}",
        "sha256": f"files/{ioc}",
    }
    path = cat_map.get(ioc_type)
    if not path:
        return None
    url = f"https://www.virustotal.com/api/v3/{path}"
    return _http_get(url, headers={"x-apikey": api_key})


def query_abuseipdb(ioc: str, ioc_type: str, api_key: str) -> dict | None:
    """Query AbuseIPDB v2 API (IPs only)."""
    if ioc_type != "ip" or not api_key:
        return None
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ioc)}&maxAgeInDays=90"
    return _http_get(url, headers={"Key": api_key, "Accept": "application/json"})


def query_greynoise(ioc: str, ioc_type: str, api_key: str) -> dict | None:
    """Query GreyNoise Community API (IPs only)."""
    if ioc_type != "ip":
        return None
    url = f"https://api.greynoise.io/v3/community/{urllib.parse.quote(ioc)}"
    headers = {"key": api_key} if api_key else {}
    return _http_get(url, headers=headers)


def query_otx(ioc: str, ioc_type: str, api_key: str) -> dict | None:
    """Query AlienVault OTX indicator general details."""
    cat_map = {"ip": "IPv4", "domain": "domain", "sha256": "file", "md5": "file"}
    path = cat_map.get(ioc_type)
    if not path:
        return None
    url = f"https://otx.alienvault.com/api/v1/indicators/{path}/{urllib.parse.quote(ioc)}/general"
    headers = {"X-OTX-API-KEY": api_key} if api_key else {}
    return _http_get(url, headers=headers)


# ── Scoring & Aggregation Engine ──────────────────────────────────

def calculate_risk_score(ioc_type: str, sources: dict) -> tuple[int, str, list[str]]:
    """Aggregate threat intel reports into a 0-100 score, verdict, and tags."""
    if not sources:
        return 0, "unverified", ["no_sources"]

    scores: list[int] = []
    tags: set[str] = set()

    # 1. VirusTotal evaluation
    vt = sources.get("VirusTotal")
    if vt:
        stats = vt.get("malicious_votes") or (
            vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        )
        total = vt.get("total_votes") or (
            sum(vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).values()) or 70
        )
        if stats > 0:
            ratio = (stats / total) * 100
            scores.append(min(100, int(ratio * 3)))  # 33% detection = 100 score
            tags.add(f"vt_malicious_{stats}")
        else:
            scores.append(0)

    # 2. AbuseIPDB evaluation
    abuse = sources.get("AbuseIPDB")
    if abuse:
        conf = (
            abuse.get("abuse_confidence_score")
            or abuse.get("abuse_score")
            or abuse.get("data", {}).get("abuseConfidenceScore", 0)
        )
        scores.append(int(conf))
        if conf >= 20:
            tags.add("reported_abuse")

    # 3. URLhaus evaluation
    uh = sources.get("URLhaus")
    if uh:
        status = uh.get("query_status") or uh.get("threat")
        if status in ("ok", "malware_download") or uh.get("threat"):
            scores.append(90)
            tags.add("urlhaus_malware")
        else:
            scores.append(0)

    # 4. GreyNoise evaluation
    gn = sources.get("GreyNoise")
    if gn:
        classification = gn.get("classification") or gn.get("verdict")
        if classification == "malicious":
            scores.append(90)
            tags.add("greynoise_malicious")
        elif classification == "benign":
            scores.append(10)
            tags.add("greynoise_benign")
        elif gn.get("noise") is True:
            tags.add("internet_scanner")
            scores.append(30)

    # 5. AlienVault OTX evaluation
    otx = sources.get("AlienVault_OTX")
    if otx:
        pulse_count = otx.get("pulse_info", {}).get("count", 0)
        if pulse_count > 0:
            scores.append(min(100, pulse_count * 20))
            tags.add(f"otx_{pulse_count}_pulses")

    final_score = max(scores) if scores else 0

    if final_score >= 75:
        verdict = "malicious"
    elif final_score >= 45:
        verdict = "suspicious"
    elif final_score >= 15:
        verdict = "low_risk"
    else:
        verdict = "benign"

    return final_score, verdict, sorted(tags)


# ── Core Enrichment Dispatcher ────────────────────────────────────

def enrich_ioc(
    ioc: str,
    cache: IOCCache | None = None,
    offline: bool = False,
    api_keys: dict | None = None,
) -> EnrichmentResult:
    """Enrich a single IOC using cache, offline heuristics, or remote APIs."""
    ioc = ioc.strip()
    ioc_type = detect_ioc_type(ioc)

    if ioc_type == "unknown":
        return EnrichmentResult(
            ioc=ioc, ioc_type="unknown", risk_score=0,
            verdict="unverified", tags=["invalid_ioc"], sources={}
        )

    # 1. Check local cache
    if cache:
        cached = cache.get(ioc)
        if cached:
            return cached

    # 2. Offline mode: do not query external network
    if offline:
        return EnrichmentResult(
            ioc=ioc,
            ioc_type=ioc_type,
            risk_score=0,
            verdict="unverified",
            tags=["offline"],
            sources={},
            checked_at=datetime.now(timezone.utc).isoformat(),
        )

    # 3. Remote live enrichment
    keys = api_keys or {
        "vt": os.getenv("VT_API_KEY", ""),
        "abuse": os.getenv("ABUSEIPDB_API_KEY", ""),
        "greynoise": os.getenv("GREYNOISE_API_KEY", ""),
        "otx": os.getenv("OTX_API_KEY", ""),
    }

    sources = {}

    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        tasks[executor.submit(query_urlhaus, ioc, ioc_type)] = "URLhaus"
        if keys.get("vt"):
            tasks[executor.submit(query_virustotal, ioc, ioc_type, keys["vt"])] = "VirusTotal"
        if keys.get("abuse") and ioc_type == "ip":
            tasks[executor.submit(query_abuseipdb, ioc, ioc_type, keys["abuse"])] = "AbuseIPDB"
        if keys.get("greynoise") and ioc_type == "ip":
            tasks[executor.submit(query_greynoise, ioc, ioc_type, keys["greynoise"])] = "GreyNoise"
        if keys.get("otx"):
            tasks[executor.submit(query_otx, ioc, ioc_type, keys["otx"])] = "AlienVault_OTX"

        for future in concurrent.futures.as_completed(tasks):
            src_name = tasks[future]
            try:
                data = future.result()
                if data:
                    sources[src_name] = data
            except Exception:
                pass

    score, verdict, tags = calculate_risk_score(ioc_type, sources)

    result = EnrichmentResult(
        ioc=ioc,
        ioc_type=ioc_type,
        risk_score=score,
        verdict=verdict,
        tags=tags,
        sources=sources,
        cached=False,
        checked_at=datetime.now(timezone.utc).isoformat(),
    )

    if cache:
        cache.set(result)

    return result


# ── Output Formatters ─────────────────────────────────────────────

def format_markdown_report(results: list[EnrichmentResult]) -> str:
    """Generate Markdown report suitable for SOC tickets / case notes."""
    lines = [
        "## IOC Enrichment Report",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Total IOCs Evaluated:** {len(results)}  ",
        "",
        "### IOC Summary Table",
        "| Indicator | Type | Risk Score | Verdict | Tags | Cache Status |",
        "| :--- | :--- | :---: | :--- | :--- | :---: |",
    ]
    for r in results:
        tags_str = ", ".join(f"`{t}`" for t in r.tags) if r.tags else "—"
        cached_str = "Cached" if r.cached else "Live Query"
        lines.append(
            f"| `{r.ioc}` | {r.ioc_type.upper()} | **{r.risk_score}/100** | **{r.verdict.upper()}** | {tags_str} | {cached_str} |"
        )

    lines.append("\n### Detailed Findings")
    for r in results:
        lines.append(f"#### `{r.ioc}` ({r.ioc_type.upper()})")
        lines.append(f"- **Verdict:** {r.verdict.upper()} (Risk Score: {r.risk_score}/100)")
        lines.append(f"- **Tags:** {', '.join(r.tags) if r.tags else 'None'}")
        if r.sources:
            lines.append("- **Threat Intelligence Sources:**")
            for src_name, data in r.sources.items():
                lines.append(f"  - **{src_name}:** Reported relevant telemetry")
        else:
            lines.append("- **Threat Intelligence Sources:** No detections or offline")
        lines.append("")

    return "\n".join(lines)


def format_table_output(results: list[EnrichmentResult]) -> None:
    """Display terminal table with rich formatting or plain text fallback."""
    if RICH:
        con = Console(stderr=True)
        con.print(Panel(f"[bold]{BANNER}[/bold]", box=box.ROUNDED))
        tbl = Table(box=box.SIMPLE_HEAVY, show_lines=True)
        tbl.add_column("#", style="dim", width=3)
        tbl.add_column("Indicator", style="bold")
        tbl.add_column("Type", style="cyan")
        tbl.add_column("Score", justify="right")
        tbl.add_column("Verdict")
        tbl.add_column("Tags", style="yellow")
        tbl.add_column("Source", style="dim")

        for idx, r in enumerate(results, 1):
            sc = SEVERITY_COLORS.get(r.verdict, "white")
            cache_info = "[green]Cache[/green]" if r.cached else "[blue]Live[/blue]"
            tbl.add_row(
                str(idx),
                r.ioc,
                r.ioc_type.upper(),
                f"{r.risk_score}/100",
                f"[{sc}]{r.verdict.upper()}[/{sc}]",
                ", ".join(r.tags) if r.tags else "-",
                cache_info,
            )
        con.print(tbl)
    else:
        print(f"\n{'=' * 75}\n  {BANNER}")
        print(f"{'=' * 75}")
        for idx, r in enumerate(results, 1):
            src_str = "CACHED" if r.cached else "LIVE"
            print(f"[{idx}] {r.ioc} ({r.ioc_type.upper()}) | Score: {r.risk_score}/100 | {r.verdict.upper()} [{src_str}]")
            if r.tags:
                print(f"    Tags: {', '.join(r.tags)}")
        print()


# ── CLI ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ioc-enricher",
        description=(
            "Lightweight IOC enrichment and threat reputation scoring engine.\n"
            "Correlates public APIs (VirusTotal, AbuseIPDB, URLhaus, GreyNoise, OTX)\n"
            "and caches results locally in SQLite."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s 8.8.8.8 198.51.100.4\n"
            "  %(prog)s -f iocs.txt --output markdown -o ticket_notes.md\n"
            "  %(prog)s 44d88612fea8a8f36de82e1278abb02f --output json\n"
            "  %(prog)s --offline 10.0.1.5 malicious-domain.com\n"
        ),
    )
    p.add_argument("iocs", nargs="*", help="one or more IOCs (IP, domain, hash, URL)")
    p.add_argument("-f", "--file", type=Path, default=None, metavar="PATH",
                   help="read IOCs from a file (one per line)")
    p.add_argument("--offline", action="store_true",
                   help="offline mode: use local cache and heuristics only, no remote network calls")
    p.add_argument("--no-cache", action="store_true",
                   help="bypass reading and writing to the local SQLite cache")
    p.add_argument("--cache-file", type=Path, default=DEFAULT_CACHE_PATH, metavar="DB",
                   help=f"path to SQLite cache file (default: {DEFAULT_CACHE_PATH})")
    p.add_argument("--ttl", type=int, default=DEFAULT_TTL_HOURS, metavar="HOURS",
                   help=f"cache time-to-live in hours (default: {DEFAULT_TTL_HOURS})")
    p.add_argument("--output", choices=["table", "markdown", "json"], default="table",
                   help="output format (default: table)")
    p.add_argument("-o", "--output-file", type=Path, default=None, metavar="PATH",
                   help="write report to destination file")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress headers and progress")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)

    raw_iocs: list[str] = list(args.iocs)
    if args.file:
        if not args.file.exists():
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        for line in args.file.read_text(encoding="utf-8", errors="replace").splitlines():
            item = line.strip()
            if item and not item.startswith("#"):
                raw_iocs.append(item)

    # If piped stdin
    if not raw_iocs and not sys.stdin.isatty():
        for line in sys.stdin.read().splitlines():
            item = line.strip()
            if item and not item.startswith("#"):
                raw_iocs.append(item)

    if not raw_iocs:
        print("Error: No IOCs provided. Provide via arguments, -f file, or stdin.", file=sys.stderr)
        sys.exit(1)

    cache = None if args.no_cache else IOCCache(args.cache_file, ttl_hours=args.ttl)

    results: list[EnrichmentResult] = []
    for item in raw_iocs:
        res = enrich_ioc(item, cache=cache, offline=args.offline)
        results.append(res)

    # Output formatting
    match args.output:
        case "markdown":
            md_content = format_markdown_report(results)
            if args.output_file:
                args.output_file.write_text(md_content, encoding="utf-8")
                if not args.quiet:
                    print(f"  ✓ Markdown report saved to {args.output_file}", file=sys.stderr)
            else:
                print(md_content)
        case "json":
            json_content = json.dumps({
                "tool": "ioc-enricher",
                "version": VERSION,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_iocs": len(results),
                "results": [r.to_dict() for r in results],
            }, indent=2)
            if args.output_file:
                args.output_file.write_text(json_content, encoding="utf-8")
                if not args.quiet:
                    print(f"  ✓ JSON report saved to {args.output_file}", file=sys.stderr)
            else:
                print(json_content)
        case _:
            if args.output_file:
                args.output_file.write_text(format_markdown_report(results), encoding="utf-8")
            format_table_output(results)

    # Scriptable exit code
    if any(r.verdict == "malicious" for r in results):
        sys.exit(2)
    elif any(r.verdict in ("suspicious", "high_risk") for r in results):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
