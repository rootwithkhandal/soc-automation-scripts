#!/usr/bin/env python3
"""Generate a synthetic auth log (JSON) with planted attack patterns for testing."""

import json
import random
from datetime import datetime, timedelta

random.seed(42)
base = datetime(2026, 11, 14, 8, 0, 0)
events = []

NORMAL_IPS = [f"10.0.1.{i}" for i in range(10, 30)]
NORMAL_USERS = ["alice", "bob", "carol", "dave", "eve", "frank", "grace"]

# ── Normal traffic: scattered failures + successes over 8 hours ────
for minute in range(0, 480, 3):
    ts = base + timedelta(minutes=minute, seconds=random.randint(0, 59))
    ip = random.choice(NORMAL_IPS)
    user = random.choice(NORMAL_USERS)
    # 80% success, 20% failure
    success = random.random() < 0.8
    events.append({
        "timestamp": ts.isoformat(),
        "source_ip": ip,
        "username": user,
        "status": "success" if success else "failure",
        "EventID": "4624" if success else "4625",
    })

# ── Attack 1: Brute-force on single account ──────────────────────
# 25 failed logins from 203.0.113.50 targeting "admin" in 3 minutes
attacker1 = "203.0.113.50"
attack1_start = base + timedelta(hours=2, minutes=15)
for i in range(25):
    ts = attack1_start + timedelta(seconds=i * 7)
    events.append({
        "timestamp": ts.isoformat(),
        "source_ip": attacker1,
        "username": "admin",
        "status": "failure",
        "EventID": "4625",
    })

# ── Attack 2: Credential stuffing (many users from one IP) ───────
# 15 distinct usernames from 198.51.100.77 in 4 minutes
attacker2 = "198.51.100.77"
attack2_start = base + timedelta(hours=4, minutes=30)
stuffed_users = [f"user{i:03d}" for i in range(15)]
for i, user in enumerate(stuffed_users):
    ts = attack2_start + timedelta(seconds=i * 16)
    events.append({
        "timestamp": ts.isoformat(),
        "source_ip": attacker2,
        "username": user,
        "status": "failure",
        "EventID": "4625",
    })

# ── Attack 3: Slow brute-force (below default threshold, above 5) ──
# 7 failures from 192.0.2.99 over 4 minutes — should NOT trigger at default threshold
attacker3 = "192.0.2.99"
attack3_start = base + timedelta(hours=6)
for i in range(7):
    ts = attack3_start + timedelta(seconds=i * 35)
    events.append({
        "timestamp": ts.isoformat(),
        "source_ip": attacker3,
        "username": "svc_backup",
        "status": "failure",
        "EventID": "4625",
    })

# ── Cooloff test: IP that succeeds then fails ────────────────────
# 10.0.1.99 succeeds, then has 15 failures — should be suppressed by cooloff
cooloff_ip = "10.0.1.99"
cooloff_start = base + timedelta(hours=3)
events.append({
    "timestamp": cooloff_start.isoformat(),
    "source_ip": cooloff_ip,
    "username": "ops_user",
    "status": "success",
    "EventID": "4624",
})
for i in range(15):
    ts = cooloff_start + timedelta(minutes=5, seconds=i * 10)
    events.append({
        "timestamp": ts.isoformat(),
        "source_ip": cooloff_ip,
        "username": "ops_user",
        "status": "failure",
        "EventID": "4625",
    })

# Sort and write
events.sort(key=lambda e: e["timestamp"])
out = "d:\\00 Active\\soc-automations\\tests\\samples\\synthetic_auth.json"
with open(out, "w") as f:
    json.dump(events, f, indent=2)

print(f"Generated {len(events)} events → {out}")
print(f"  Normal traffic:     ~160 events")
print(f"  Attack 1 (brute):   25 failures from {attacker1}")
print(f"  Attack 2 (stuffing): 15 users from {attacker2}")
print(f"  Attack 3 (slow):     7 failures from {attacker3} (below threshold)")
print(f"  Cooloff test:       15 failures from {cooloff_ip} (suppressed)")
