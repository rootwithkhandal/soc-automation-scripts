## Alert Noise Reduction & Deduplication Report
**Generated:** 2026-11-18 16:28:06 UTC  
**Original Raw Alerts:** 135  
**Actionable Incidents:** 4  
**Noise Reduction:** **97.0%** (Window: 30 min)  

### Actionable Incident Queue
| ID | Severity | Rule Name | Target Host | IOC | Count | First Seen | Last Seen |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| `INC-0001` | **CRITICAL** *(was medium)* | Suspicious Authentication Failure Spike | `dc01.corp.local` | `198.51.100.205` | **50** | 2026-11-18T10:00:00+00:00 | 2026-11-18T10:14:42+00:00 |
| `INC-0004` | **CRITICAL** *(was medium)* | Suspicious Authentication Failure Spike | `dc01.corp.local` | `198.51.100.205` | **10** | 2026-11-18T12:00:00+00:00 | 2026-11-18T12:04:30+00:00 |
| `INC-0003` | **HIGH** | Network Beaconing to Untrusted Domain | `payment-gateway.prod` | `203.0.113.88` | **35** | 2026-11-18T10:05:00+00:00 | 2026-11-18T10:16:20+00:00 |
| `INC-0002` | **LOW** | Port Scan Detected | `ws-laptop-105` | `192.168.1.55` | **40** | 2026-11-18T10:02:00+00:00 | 2026-11-18T10:11:45+00:00 |

### Incident Detail Cards
#### Incident `INC-0001`: Suspicious Authentication Failure Spike
- **Target Asset:** `dc01.corp.local` (Criticality: `CRITICAL`)
- **Severity:** **CRITICAL** (Promoted from `MEDIUM`)
- **Alert Count:** Collapsed **50** duplicate events (Timeline: 2026-11-18T10:00:00+00:00 → 2026-11-18T10:14:42+00:00)
- **Associated IOC:** `198.51.100.205` | **Users Involved:** `svc_admin`, `administrator`
- ℹ️ Severity promoted to CRITICAL: Target asset 'dc01.corp.local' is classified as CRITICAL infrastructure.

#### Incident `INC-0004`: Suspicious Authentication Failure Spike
- **Target Asset:** `dc01.corp.local` (Criticality: `CRITICAL`)
- **Severity:** **CRITICAL** (Promoted from `MEDIUM`)
- **Alert Count:** Collapsed **10** duplicate events (Timeline: 2026-11-18T12:00:00+00:00 → 2026-11-18T12:04:30+00:00)
- **Associated IOC:** `198.51.100.205` | **Users Involved:** `administrator`
- ℹ️ Severity promoted to CRITICAL: Target asset 'dc01.corp.local' is classified as CRITICAL infrastructure.

#### Incident `INC-0003`: Network Beaconing to Untrusted Domain
- **Target Asset:** `payment-gateway.prod` (Criticality: `CRITICAL`)
- **Severity:** **HIGH**
- **Alert Count:** Collapsed **35** duplicate events (Timeline: 2026-11-18T10:05:00+00:00 → 2026-11-18T10:16:20+00:00)
- **Associated IOC:** `203.0.113.88` | **Users Involved:** `SYSTEM`

#### Incident `INC-0002`: Port Scan Detected
- **Target Asset:** `ws-laptop-105` (Criticality: `LOW`)
- **Severity:** **LOW**
- **Alert Count:** Collapsed **40** duplicate events (Timeline: 2026-11-18T10:02:00+00:00 → 2026-11-18T10:11:45+00:00)
- **Associated IOC:** `192.168.1.55` | **Users Involved:** `—`
- ℹ️ Target asset 'ws-laptop-105' is tagged as LOW priority/test environment.
