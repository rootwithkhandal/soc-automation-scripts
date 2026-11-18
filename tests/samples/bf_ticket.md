# SOC Incident Ticket: INC-BF-001
**Generated:** 2026-11-18 16:34:15 UTC | **Severity:** `HIGH` | **Tool:** `playbook-runner v1.0.0`

## 1. Incident Overview
- **Detection Rule:** Authentication Attack (brute_force)
- **Target Asset:** `auth-domain`
- **Observed IOC:** `203.0.113.50`
- **Compromised User(s):** `admin`
- **Total Alert Volume:** 25 events collapsed
- **Incident Timeline:** 2026-11-14T10:15:00 → 2026-11-14T10:17:48

### Context & Asset Criticality
- ℹ️ 25 failures in 5min

## 2. MITRE ATT&CK Mapping
- **Credential Access (TA0006) — T1110: Brute Force**

## 3. Related Forensic Timeline (25 matched events)
| Timestamp | Host / Device | Source IP | Event Summary |
| :--- | :--- | :--- | :--- |
| `2026-11-14T10:15:00` | `—` | `203.0.113.50` | 4625 |
| `2026-11-14T10:15:07` | `—` | `203.0.113.50` | 4625 |
| `2026-11-14T10:15:14` | `—` | `203.0.113.50` | 4625 |
| `2026-11-14T10:15:21` | `—` | `203.0.113.50` | 4625 |
| `2026-11-14T10:15:28` | `—` | `203.0.113.50` | 4625 |
| `2026-11-14T10:15:35` | `—` | `203.0.113.50` | 4625 |
| `2026-11-14T10:15:42` | `—` | `203.0.113.50` | 4625 |
| `2026-11-14T10:15:49` | `—` | `203.0.113.50` | 4625 |
| `2026-11-14T10:15:56` | `—` | `203.0.113.50` | 4625 |
| `2026-11-14T10:16:03` | `—` | `203.0.113.50` | 4625 |
| `2026-11-14T10:16:10` | `—` | `203.0.113.50` | 4625 |
| `2026-11-14T10:16:17` | `—` | `203.0.113.50` | 4625 |
| `2026-11-14T10:16:24` | `—` | `203.0.113.50` | 4625 |
| `2026-11-14T10:16:31` | `—` | `203.0.113.50` | 4625 |
| `2026-11-14T10:16:38` | `—` | `203.0.113.50` | 4625 |
| ... | ... | ... | *(+10 additional events omitted for brevity)* |

## 4. Containment & Response Checklist (Human-in-the-Loop)
- [ ] **Triage Validation:** Confirm alert is true positive; rule out authorized pentest or maintenance.
- [ ] **Host Forensic Collection:** Capture triage memory and volatile process artifacts before isolation.
- [ ] **Network Containment:** Block perimeter attacker IP on border edge firewalls.
- [ ] **Host Isolation:** Sever network connection of compromised host via EDR/firewall.
- [ ] **Credential Remediation:** Revoke Azure AD / Active Directory session tokens & force password reset.
- [ ] **Lateral Movement Audit:** Review neighboring hosts for SMB/RDP connections in log window.
- [ ] **Management Escalation:** Notify Incident Commander and compliance if sensitive data exposed.

## 5. Staged Containment Actions
### Action: Block Attacker IP (203.0.113.50) at Perimeter
- **Category:** `network_block` | **Risk:** `Low (Blocks external/attacker IP)` | **Status:** `DRY-RUN / STAGED`
```bash
iptables -A INPUT -s 203.0.113.50 -j DROP # Linux
netsh advfirewall firewall add rule name="SOC_Block_203.0.113.50" dir=in action=block remoteip=203.0.113.50 # Win
```

### Action: Isolate Compromised Host (auth-domain)
- **Category:** `host_isolation` | **Risk:** `High (Network connectivity severed for endpoint)` | **Status:** `DRY-RUN / STAGED`
```bash
# CrowdStrike / SentinelOne API: isolate --device-id auth-domain
netsh advfirewall set allprofiles state on; netsh advfirewall firewall add rule name="SOC_Isolate" dir=in action=block
```

### Action: Revoke Sessions & Disable Account (admin)
- **Category:** `account_containment` | **Risk:** `Medium (Disrupts user active sessions)` | **Status:** `DRY-RUN / STAGED`
```bash
Disable-LocalUser -Name "admin"
Revoke-AzureADUserAllRefreshToken -ObjectId "admin"
```
