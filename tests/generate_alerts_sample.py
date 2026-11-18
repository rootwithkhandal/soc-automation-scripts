#!/usr/bin/env python3
"""Generate synthetic SIEM alerts (JSON) with duplicates and critical assets for Day 6."""

import json
import random
from datetime import datetime, timedelta, timezone

random.seed(42)
base_time = datetime(2026, 11, 18, 10, 0, 0, tzinfo=timezone.utc)
alerts = []

# Asset inventory definition
assets = {
    "dc01.corp.local": "critical",
    "payment-gateway.prod": "critical",
    "sql-cluster-01": "high",
    "web-dmz-01": "medium",
    "ws-finance-42": "high",
    "ws-laptop-105": "low"
}

# 1. Storm of Splunk alerts: SSH Brute Force against DC01 (50 duplicate alerts in 15 mins)
for i in range(50):
    ts = base_time + timedelta(seconds=i * 18)
    alerts.append({
        "_time": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "search_name": "Suspicious Authentication Failure Spike",
        "dest": "dc01.corp.local",
        "src_ip": "198.51.100.205",
        "user": f"svc_admin" if i % 5 == 0 else "administrator",
        "alert_severity": "medium"
    })

# 2. Storm of Elastic alerts: Cobalt Strike Beaconing from payment gateway (35 duplicate alerts)
for i in range(35):
    ts = base_time + timedelta(minutes=5, seconds=i * 20)
    alerts.append({
        "@timestamp": ts.isoformat(),
        "signal.rule.name": "Network Beaconing to Untrusted Domain",
        "host.name": "payment-gateway.prod",
        "source.ip": "203.0.113.88",
        "user.name": "SYSTEM",
        "signal.severity": "high"
    })

# 3. Storm of Port Scan alerts on ordinary workstation: low priority noise (40 duplicate alerts)
for i in range(40):
    ts = base_time + timedelta(minutes=2, seconds=i * 15)
    alerts.append({
        "timestamp": ts.isoformat(),
        "rule_name": "Port Scan Detected",
        "host": "ws-laptop-105",
        "ioc": "192.168.1.55",
        "user": "—",
        "severity": "low"
    })

# 4. Critical alerts that should NOT collapse if time window separates them (> 30 mins)
ts_late = base_time + timedelta(hours=2)
for i in range(10):
    ts = ts_late + timedelta(seconds=i * 30)
    alerts.append({
        "timestamp": ts.isoformat(),
        "rule_name": "Suspicious Authentication Failure Spike",
        "host": "dc01.corp.local",
        "ioc": "198.51.100.205",
        "user": "administrator",
        "severity": "medium"
    })

# Shuffle slightly to emulate SIEM arrival order
random.shuffle(alerts)

out_alerts = "d:/00 Active/soc-automations/tests/samples/synthetic_alerts.json"
out_assets = "d:/00 Active/soc-automations/tests/samples/asset_inventory.json"

with open(out_alerts, "w", encoding="utf-8") as f:
    json.dump(alerts, f, indent=2)

with open(out_assets, "w", encoding="utf-8") as f:
    json.dump(assets, f, indent=2)

print(f"Generated {len(alerts)} alerts -> {out_alerts}")
print(f"Generated asset inventory -> {out_assets}")
