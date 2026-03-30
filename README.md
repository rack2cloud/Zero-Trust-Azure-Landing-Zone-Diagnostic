# Zero-Trust Azure Landing Zone Diagnostic

A local PowerShell script that extracts sanitized architectural metadata from your Azure environment — no access granted, no secrets exposed, no data leaving your control. Upload the output JSON to [rack2cloud.com/audit](https://rack2cloud.com/audit) for a scored 3-page Architecture Brief with a prioritized remediation plan.

---

## The Problem

Landing zone mistakes don't fail immediately. They compound silently into 4–5 figure monthly waste. Most teams only discover architectural flaws after production, when refactoring requires downtime and is 10x harder to execute.

By the time your Azure costs spike or a security compliance review fails, the architecture is already deployed — and unwinding it is expensive.

## The Solution

Run this script locally in your own authenticated Azure environment. It collects **only structural metadata**: counts, booleans, and percentages. It permanently strips all IPs, subscription IDs, resource names, tag values, and secrets before writing the output file.

You get a console teaser with named findings immediately. Upload the JSON for the full scored brief.

---

## What Is (and Isn't) Collected

### ✅ Collected — Structural Metadata Only

| Category | Examples |
|---|---|
| **Identity / RBAC** | Count of privileged role assignments at subscription scope, PIM configuration state, guest user flag |
| **Networking** | NSG count with unrestricted inbound/outbound rules, % of subnets without NSG association, unattached public IP count |
| **Governance** | Budget alert configured (boolean), % of resource groups without tags, policy assignment count |
| **Compute / Cost** | Unattached disk count + total GiB, stopped-not-deallocated VM count, NIC-level NSG coverage % |

### ❌ Never Collected

- Subscription IDs or Tenant IDs
- IP addresses (public or private)
- Resource names or display names
- Tag keys or tag values
- User principal names or email addresses
- Secrets, keys, or connection strings
- Any data that could identify your organization or workloads

---

## Verification: Confirm Zero Exfiltration Before Running

Use the `-DryRun` flag to print exactly what the script would collect — with no API calls made:

```powershell
.\Invoke-R2CTriage.ps1 -DryRun
```

This lists every field name and data type that would be written to the JSON. Review it. Audit the source code directly on GitHub. Only run live when you're satisfied.

---

## Prerequisites

### Option A: Azure Cloud Shell (Recommended)

Cloud Shell is pre-authenticated and has all Az modules installed. No local setup required.

1. Open [shell.azure.com](https://shell.azure.com) or launch Cloud Shell from the Azure Portal
2. Select **PowerShell** mode
3. Upload or clone this script
4. Run it

### Option B: Local PowerShell

**Requirements:**
- PowerShell 5.1+ or PowerShell 7+
- Az PowerShell module

**Install Az module (if not already installed):**

```powershell
Install-Module Az -Scope CurrentUser -Force -AllowClobber
```

**Authenticate:**

```powershell
Connect-AzAccount
```

---

## Usage

### Basic — Run against current subscription context

```powershell
.\Invoke-R2CTriage.ps1
```

### Target a specific subscription

```powershell
.\Invoke-R2CTriage.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000"
```

### Specify output directory

```powershell
.\Invoke-R2CTriage.ps1 -OutputPath "C:\AuditExports"
```

### Dry run — verify collection scope before execution

```powershell
.\Invoke-R2CTriage.ps1 -DryRun
```

---

## Console Output

When you run the script live, you'll see a teaser output immediately — before uploading anything:

```
  ════════════════════════════════════════════
  RACK2CLOUD TRIAGE — PRELIMINARY RESULTS
  ════════════════════════════════════════════

  ESTIMATED SCORE:  58 / 100   [50–65 range]
  RISK BAND:        HIGH RISK
  FLAGS DETECTED:   5

  CRITICAL FINDINGS:

    ├─ [IDENTITY]   MFA enforcement gap — permanent privileged assignments without PIM coverage detected
    ├─ [IDENTITY]   Excessive Owner assignments at subscription scope (4 detected)
    ├─ [NETWORKING] Unrestricted inbound rules on 2 NSG(s) — SSH/RDP exposure likely
    ├─ [GOVERNANCE] No budget alerts configured — cost overruns will not be detected automatically
    └─ [COST]       3 unattached managed disk(s) detected (512 GiB billing with no workload)

  ─────────────────────────────────────────────
  Full remediation roadmap locked in r2c_payload.json

  NEXT STEP:
  Upload r2c_payload.json at rack2cloud.com/audit
  to unlock your scored 3-page Architecture Brief.

  ════════════════════════════════════════════
```

The teaser names the **category and specific finding** — but not the remediation. That's in the full brief.

---

## Output File: r2c_payload.json

The script writes a single file to your working directory (or the path specified by `-OutputPath`).

**Review it before uploading.** Open it in any text editor. Confirm that no IPs, resource names, or identifiers are present. The file contains only counts, booleans, percentages, and your subscription fingerprint (a one-way SHA-256 hash — not the raw ID).

**Sample payload structure:**

```json
{
  "schema_version": "1.0.0",
  "generated_at_utc": "2026-03-30T09:15:00Z",
  "subscription_fingerprint": "a3f19d2b84c1",
  "teaser": {
    "status": "Scrubbed and Sanitized",
    "estimated_score_range": "50–65",
    "estimated_score": 58,
    "risk_band": "HIGH RISK",
    "critical_flags_detected": 5,
    "action": "Upload r2c_payload.json to rack2cloud.com/audit to unlock full remediation report."
  },
  "identity": {
    "privileged_role_assignments_at_sub_scope_count": 6,
    "owners_at_subscription_scope_count": 4,
    "mfa_enforcement_gap_likely": true,
    "pim_appears_configured": false,
    "guest_users_with_privileged_roles": false,
    "service_principals_with_owner_rights_count": 1,
    "custom_roles_count": 2
  },
  "networking": {
    "nsg_count": 8,
    "nsgs_with_unrestricted_inbound_count": 2,
    "nsgs_with_unrestricted_outbound_count": 0,
    "vnet_count": 3,
    "subnets_without_nsg_count": 4,
    "subnets_without_nsg_pct": 28.6,
    "public_ip_total_count": 7,
    "public_ips_unattached_count": 2
  },
  "governance": {
    "budget_alerts_configured": false,
    "budget_count": 0,
    "policy_assignments_count": 12,
    "enforced_policy_assignments_count": 4,
    "resource_group_count": 14,
    "resource_groups_without_tags_pct": 42.9,
    "subscription_activity_log_diagnostic_configured": false
  },
  "compute": {
    "vm_count": 11,
    "vms_stopped_not_deallocated_count": 1,
    "unattached_disks_count": 3,
    "unattached_disks_total_gib": 512,
    "vms_with_nic_without_nsg_pct": 18.2
  }
}
```

---

## The Scored Report

Upload your `r2c_payload.json` at **[rack2cloud.com/audit](https://rack2cloud.com/audit)** to receive:

- **Architecture Score** (0–100) across Identity, Networking, Governance, and Cost
- **Risk Band** with prescriptive messaging mapped to your score
- **Cost & Risk Leak Analysis** — orphaned resources, NSG gaps, RBAC overexposure
- **"Fix This First" Remediation Roadmap** — prioritized by effort vs. impact

Delivered as a 3-page tactical PDF within 48 hours.

---

## Scoring Framework

The full score weights five domains:

| Domain | Weight | What It Measures |
|---|---|---|
| Identity | 25% | MFA coverage, RBAC blast radius, PIM configuration, SPN rights |
| Networking | 20% | NSG hygiene, subnet coverage, DDoS protection, open rules |
| Governance | 20% | Budget alerts, tag compliance, policy enforcement, audit logging |
| Cost | 20% | Orphaned resources, stopped VMs, unattached disks and IPs |
| Security | 15% | Defender for Cloud coverage, diagnostic settings, activity log routing |

Score bands:

| Score | Risk Level | Meaning |
|---|---|---|
| 85–100 | Production Ready | Architecture is sound. Minor optimizations recommended. |
| 70–84 | Moderate Risk | Structural gaps detected. Fix before scaling workloads. |
| 50–69 | High Risk | Severe compliance and cost leakage issues. Immediate remediation required. |
| < 50 | Critical | Do not deploy. High probability of breach or compounding cost failure. |

---

## Required Permissions

The script requires **Reader** role on the target subscription. It does not require Contributor, Owner, or any write permissions. It makes no changes to your environment.

For the PIM check, `Azure AD Reader` or equivalent Graph API read scope is required. If unavailable, PIM status will be reported as `false` (conservative assumption).

---

## Audit the Source

This script is fully open source. Every line is reviewable. There are no obfuscated sections, no external network calls, no telemetry, and no data transmission. The only network call made is to the Azure Resource Manager API — the same API used by the Azure Portal.

If you identify a data collection concern or a bug, open an issue or submit a PR.

---

## License

MIT License — see [LICENSE](LICENSE)

---

## About

Built by [The Architect](https://rack2cloud.com) — 25+ years of enterprise infrastructure delivery across financial services, healthcare, manufacturing, and public sector.

**rack2cloud.com** | [Azure Architecture Blog](https://rack2cloud.com) | [Contact](https://rack2cloud.com/contact)
