# SOC Incident Ticket: INC-0001
**Generated:** 2026-11-18 16:31:47 UTC | **Severity:** `CRITICAL` | **Tool:** `playbook-runner v1.0.0`

## 1. Incident Overview
- **Detection Rule:** Suspicious Authentication Failure Spike
- **Target Asset:** `dc01.corp.local`
- **Observed IOC:** `198.51.100.205`
- **Compromised User(s):** `svc_admin, administrator`
- **Total Alert Volume:** 50 events collapsed
- **Incident Timeline:** 2026-11-18T10:00:00+00:00 → 2026-11-18T10:14:42+00:00

### Context & Asset Criticality
- ℹ️ Severity promoted to CRITICAL: Target asset 'dc01.corp.local' is classified as CRITICAL infrastructure.

## 2. MITRE ATT&CK Mapping
- **Credential Access (TA0006) — T1110: Brute Force**

## 4. Containment & Response Checklist (Human-in-the-Loop)
- [ ] **Triage Validation:** Confirm alert is true positive; rule out authorized pentest or maintenance.
- [ ] **Host Forensic Collection:** Capture triage memory and volatile process artifacts before isolation.
- [ ] **Network Containment:** Block perimeter attacker IP on border edge firewalls.
- [ ] **Host Isolation:** Sever network connection of compromised host via EDR/firewall.
- [ ] **Credential Remediation:** Revoke Azure AD / Active Directory session tokens & force password reset.
- [ ] **Lateral Movement Audit:** Review neighboring hosts for SMB/RDP connections in log window.
- [ ] **Management Escalation:** Notify Incident Commander and compliance if sensitive data exposed.

## 5. Staged Containment Actions
### Action: Block Attacker IP (198.51.100.205) at Perimeter
- **Category:** `network_block` | **Risk:** `Low (Blocks external/attacker IP)` | **Status:** `DRY-RUN / STAGED`
```bash
iptables -A INPUT -s 198.51.100.205 -j DROP # Linux
netsh advfirewall firewall add rule name="SOC_Block_198.51.100.205" dir=in action=block remoteip=198.51.100.205 # Win
```

### Action: Isolate Compromised Host (dc01.corp.local)
- **Category:** `host_isolation` | **Risk:** `High (Network connectivity severed for endpoint)` | **Status:** `DRY-RUN / STAGED`
```bash
# CrowdStrike / SentinelOne API: isolate --device-id dc01.corp.local
netsh advfirewall set allprofiles state on; netsh advfirewall firewall add rule name="SOC_Isolate" dir=in action=block
```

### Action: Revoke Sessions & Disable Account (svc_admin)
- **Category:** `account_containment` | **Risk:** `Medium (Disrupts user active sessions)` | **Status:** `DRY-RUN / STAGED`
```bash
Disable-LocalUser -Name "svc_admin"
Revoke-AzureADUserAllRefreshToken -ObjectId "svc_admin"
```

### Action: Revoke Sessions & Disable Account (administrator)
- **Category:** `account_containment` | **Risk:** `Medium (Disrupts user active sessions)` | **Status:** `DRY-RUN / STAGED`
```bash
Disable-LocalUser -Name "administrator"
Revoke-AzureADUserAllRefreshToken -ObjectId "administrator"
```
