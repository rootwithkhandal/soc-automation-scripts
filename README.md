# 🛡️ SOC Automation Toolkit (7-Day Security Operations CLI)

> **A 7-day, 7-script production-ready Python CLI toolkit designed to automate high-frequency Tier-1 and Tier-2 Security Operations Center (SOC) workflows.**  
> Built strictly with standalone single-file portability, zero heavy framework overhead, standard-library-first engineering, and human-in-the-loop safety boundaries.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-51%20Passed%20%7C%20100%25-brightgreen.svg)](tests/)
[![Architecture](https://img.shields.io/badge/Design-CLI--First%20%7C%20Zero--Agent-orange.svg)](#architecture--design-principles)

---

## 📌 Overview

Real-world SOC analysts face two constant friction points: **alert fatigue** and **fragmented manual triage across disparate portals**. Commercial SOAR platforms often introduce fragile DAGs, heavy daemon dependencies, and complex webhook setups that take weeks to configure.

This toolkit solves real operational challenges through **7 standalone, resume-grade Python CLI tools**—each solving one specific operational phase from initial detection to automated containment documentation:

```
[Day 1: Auth Logs]        [Day 2: Sysmon/Zeek]       [Day 5: Process Events]
        │                         │                           │
        └─────────────────┬───────┴───────────────────────────┘
                          ▼
            [Day 6: SIEM Alert Dedup Engine] ──(97% Noise Reduction)
                          │
                          ├─────────────────────────┐
                          ▼                         ▼
            [Day 3: IOC Enricher]         [Day 4: Email Triage]
                          │                         │
                          └───────────┬─────────────┘
                                      ▼
                   [Day 7: Playbook Response Runner]
                    (Markdown Ticket + Staged Containment)
```

---

## 🚀 The 7-Day Curriculum & Tool Reference

| Day | Tool Script | Canonical Name | Target Telemetry | MITRE ATT&CK | Status |
| :---: | :--- | :--- | :--- | :---: | :---: |
| **1** | [Brute-Force Detector](file:///d:/00%20Active/soc-automations/bruteforce-detector.py) | `bruteforce-detector.py` | Win Event 4625, Linux `auth.log`, IdP JSON/CSV | [T1110](https://attack.mitre.org/techniques/T1110/) | ✅ 8 Tests |
| **2** | [Lateral Movement Indicator](file:///d:/00%20Active/soc-automations/lateral-movement-detector.py) | `lateral-movement-detector.py` | Sysmon Event 3 & 1, Zeek SMB/RPC logs | [T1021](https://attack.mitre.org/techniques/T1021/), [T1569](https://attack.mitre.org/techniques/T1569/) | ✅ 11 Tests |
| **3** | [IOC Threat Enricher](file:///d:/00%20Active/soc-automations/ioc-enricher.py) | `ioc-enricher.py` | IPs, Domains, Hashes, URLs | [TA0011](https://attack.mitre.org/tactics/TA0011/) | ✅ 6 Tests |
| **4** | [Phishing Email Triage](file:///d:/00%20Active/soc-automations/phishing-triage.py) | `phishing-triage.py` | Raw `.eml` files, RFC 822 MIME headers | [T1566](https://attack.mitre.org/techniques/T1566/), [T1204](https://attack.mitre.org/techniques/T1204/) | ✅ 7 Tests |
| **5** | [Process Anomaly Spotter](file:///d:/00%20Active/soc-automations/process-anomaly-detector.py) | `process-anomaly-detector.py` | Sysmon Event ID 1 (Process Create) | [T1059](https://attack.mitre.org/techniques/T1059/), [T1218](https://attack.mitre.org/techniques/T1218/) | ✅ 5 Tests |
| **6** | [Alert Deduplication Engine](file:///d:/00%20Active/soc-automations/alert-dedup-engine.py) | `alert-dedup-engine.py` | Splunk, Elastic, Syslog alert batches | SIEM Operations | ✅ 7 Tests |
| **7** | [Playbook Response Runner](file:///d:/00%20Active/soc-automations/playbook-runner.py) | `playbook-runner.py` | Incidents from Days 1–6 + Raw logs | Incident Response | ✅ 7 Tests |

> *Note: For user convenience, interchangeable CLI aliases (`lateral_movement.py`, `playbook_runner.py`, `alert_dedup.py`, etc.) are included and point directly to their canonical counterparts.*

---

## 🛠️ Tool Walkthrough & CLI Usage

### Day 1 · Brute-Force & Credential Stuffing Detector

Detects targeted account brute-forcing and horizontal password spraying across Windows Event 4625, Linux `auth.log`, and cloud IdP exports.

- **Key Features:** Sliding-window counters, post-auth success "cooling-off" period suppression, CIDR/IP allow-listing, streaming JSONL/EVTX ingestion.

```bash
python bruteforce-detector.py auth.log --threshold 10 --window 5
python bruteforce-detector.py Security.evtx --format evtx --output json -o offenders.json
```

### Day 2 · Multi-Signal Lateral Movement Indicator

Identifies post-exploitation pivoting (RDP, SMB, WinRM, PsExec, WMI) across internal hosts.

- **Key Features:** Inverts false positives by requiring **two independent signals** (network connection + anomalous process creation) within a correlation window; supports Graphviz DOT topology export and bidirectional `--host-map` hostname-to-IP resolution.

```bash
python lateral-movement-detector.py sysmon.json --host-map hosts.json --output table
python lateral-movement-detector.py conn.log --format zeek --output dot -o lateral_graph.dot
```

### Day 3 · Threat Intelligence IOC Enricher & Reputation Scorer

Aggregates free-tier OSINT and threat intelligence feeds into unified, actionable risk scores.

- **Key Features:** Multi-provider integration (VirusTotal, AbuseIPDB, URLhaus, GreyNoise Community, AlienVault OTX) with concurrent `ThreadPoolExecutor` lookups, local SQLite TTL caching, and graceful offline degradation.

```bash
python ioc-enricher.py iocs.txt -o ioc_report.md
python ioc-enricher.py 198.51.100.205 --offline --format json
```

### Day 4 · Phishing & Malicious Email Triage Helper

Automates analysis of reported suspicious emails (`.eml`).

- **Key Features:** Header authentication inspection (SPF, DKIM, DMARC), Reply-To mismatch & display-name spoofing detection, visual link text vs. `href` mismatch detection, attachment MD5/SHA256 calculation, and standard-library zip inspection (`vbaProject.bin`, hidden macros).

```bash
python phishing-triage.py suspicious.eml -o triage_summary.md
python phishing-triage.py phish.eml --enrich  # Chains directly into Day 3 threat intel
```

### Day 5 · Endpoint Process Anomaly Spotter

Unsupervised outlier and living-off-the-land (LOLBIN) detection on endpoint execution logs.

- **Key Features:** Frequency baselining (parent/child/user triples), command-line Shannon entropy analysis (detects base64/obfuscated PowerShell), system binary masquerade verification (e.g. `svchost.exe` outside `C:\Windows\System32`), and baseline save/load (`--save-baseline`/`--load-baseline`).

```bash
# Build baseline from 7 days of normal telemetry
python process-anomaly-detector.py baseline_events.json --save-baseline company.baseline

# Score new suspicious telemetry against saved baseline
python process-anomaly-detector.py today_events.evtx --load-baseline company.baseline -o outliers.json
```

### Day 6 · Alert Noise Reducer & Simple Deduplication Engine

Reduces SIEM alarm storms into consolidated actionable incident cards.

- **Key Features:** Ingests Splunk, Elastic, or generic webhook formats (CSV, JSON, JSONL); groups repetitive alerts by similarity within a sliding time window; preserves forensic first-seen/last-seen timestamps; re-scores alert priority based on target `--assets` criticality inventory; supports `--force-unique` and `--preserve-critical`.

```bash
python alert-dedup-engine.py siem_alerts.json --window 30 --assets asset_inventory.json
python alert-dedup-engine.py alerts.csv --output markdown -o ticket_queue.md
```

### Day 7 · Automated Response Playbook Runner (Read-Only First)

Orchestrates safe triage documentation and containment preparation for high-confidence alerts.

- **Key Features:** Ingests outputs from Days 1, 2, 5, or 6; maps detections to MITRE ATT&CK techniques; pulls contextual timeline logs within a correlation window; generates formatted ITSM Markdown ticket templates; and stages containment actions (firewall block syntax, host isolation commands, session revocations) behind a **strict human-in-the-loop safety gate** (`--execute --confirm`).

```bash
# Generate complete SOC incident ticket with log timeline
python playbook-runner.py dedup_alerts.json --logs raw_auth.json --window 15 -o incident_ticket.md

# Safe containment verification (dry-run mode by default)
python playbook-runner.py dedup_alerts.json --incident-id INC-0001

# Gated live containment execution simulation
python playbook-runner.py dedup_alerts.json --execute --confirm
```

---

## 🧩 End-to-End Pipeline Walkthrough

Here is how the toolkit forms an automated investigation and response pipeline:

```bash
# 1. Day 1: Detect credential stuffing offenders from authentication logs
python bruteforce-detector.py tests/samples/synthetic_auth.json --format json -o auth_alerts.json

# 2. Day 6: Deduplicate alerts and promote priority using critical asset tags
python alert-dedup-engine.py tests/samples/synthetic_alerts.json --assets tests/samples/asset_inventory.json --output json -o dedup_incidents.json

# 3. Day 7: Generate ITSM incident ticket and stage containment actions
python playbook-runner.py dedup_incidents.json --logs tests/samples/synthetic_auth.json -o final_ticket.md
```

Sample generated incident ticket section:

```markdown
# SOC Incident Ticket: INC-0001
**Generated:** 2026-11-18 16:34:15 UTC | **Severity:** `CRITICAL` | **Tool:** `playbook-runner v1.0.0`

## 1. Incident Overview
- **Detection Rule:** Suspicious Authentication Failure Spike
- **Target Asset:** `dc01.corp.local` (Criticality: `CRITICAL`)
- **Observed IOC:** `198.51.100.205`
- **Compromised User(s):** `svc_admin, administrator`
- **Total Alert Volume:** 50 events collapsed (Reduction: 97.0%)

## 2. MITRE ATT&CK Mapping
- **Credential Access (TA0006) — T1110: Brute Force**

## 3. Related Forensic Timeline (25 matched events)
| Timestamp | Host / Device | Source IP | Event Summary |
| :--- | :--- | :--- | :--- |
| `2026-11-18T10:00:00` | `dc01.corp.local` | `198.51.100.205` | EventID 4625 |

## 4. Staged Containment Actions (Human-in-the-Loop)
- [ ] Block Attacker IP (`198.51.100.205`) at Perimeter:
      `iptables -A INPUT -s 198.51.100.205 -j DROP`
- [ ] Isolate Compromised Host (`dc01.corp.local`):
      `netsh advfirewall set allprofiles state on`
```

---

## 🏗️ Architecture & Design Principles

1. **Standalone Portability:** 1 script = 1 Python file. No complex microservice clusters or database migrations required to run a tool.
2. **Standard-Library-First:** Days 3, 4, 5, 6, and 7 require **100% Python standard library** (`urllib`, `sqlite3`, `email`, `zipfile`, `hashlib`, `json`, `csv`, `pathlib`). Only visual enhancement ([rich](https://github.com/Textualize/rich)) and binary Windows log reading ([python-evtx](https://github.com/williballenthin/python-evtx)) are in `requirements.txt`.
3. **Safety & Inversion Mindset:**
   - **Never auto-contain blindly:** Day 7 defaults to read-only simulation; live changes require explicit confirmation flags (`--execute --confirm`).
   - **Never miss multi-stage attacks:** Day 6 preserves exact first-seen and last-seen timestamps and offers `--preserve-critical`.
   - **Never drop offline:** Day 3 caches threat intelligence in SQLite with configurable TTLs and features an `--offline` mode.
4. **Tested Against Public Real-World Telemetry:**
   - [OTRF Security Datasets (Mordor)](https://securitydatasets.com/)
   - Atomic Red Team & Atomic-EVTX
   - Splunk Boss of the SOC (BOTS)
   - Nazario Malicious Email Corpus

---

## 🧪 Installation & Testing

### 1. Clone & Setup

```bash
git clone https://github.com/your-username/soc-automations.git
cd soc-automations

# (Optional) Create virtual environment
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

### 2. Run All Automated Test Suites

The project includes **51 self-contained automated tests** across all 7 days with zero external network dependencies:

```bash
# Run all test suites
python tests/test_brute_force.py          # Day 1: 8 passed
python tests/test_lateral_movement.py     # Day 2: 11 passed
python tests/test_ioc_enricher.py         # Day 3: 6 passed
python tests/test_phishing_triage.py      # Day 4: 7 passed
python tests/test_process_anomaly.py      # Day 5: 5 passed
python tests/test_alert_dedup.py          # Day 6: 7 passed
python tests/test_playbook_runner.py      # Day 7: 7 passed
```

---

## 📄 License

This repository is licensed under the [MIT License](LICENSE).
