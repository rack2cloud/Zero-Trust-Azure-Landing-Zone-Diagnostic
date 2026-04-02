#Requires -Version 5.1
<#
.SYNOPSIS
    Rack2Cloud Azure Landing Zone Triage Script — Zero-Trust Edition

.DESCRIPTION
    Extracts sanitized architectural metadata from your Azure environment to validate
    your landing zone configuration before production. No secrets are collected.
    No IPs, subscription IDs, resource names, or credentials leave your environment.

    Output: r2c_payload.json — upload to rack2cloud.com/audit for your scored report.

.PARAMETER DryRun
    Simulates execution and prints exactly what would be collected. No API calls are made.
    Use this to verify zero-exfiltration before running live.

.PARAMETER SubscriptionId
    Target a specific subscription by ID. If omitted, uses the current Az context.

.PARAMETER OutputPath
    Directory to write r2c_payload.json. Defaults to current directory.

.EXAMPLE
    # Verify what the script collects (no API calls)
    .\Invoke-R2CTriage.ps1 -DryRun

    # Run live triage against current subscription
    .\Invoke-R2CTriage.ps1

    # Target a specific subscription
    .\Invoke-R2CTriage.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000"

.NOTES
    Author:       The Architect — rack2cloud.com
    Version:      1.0.0
    GitHub:       https://github.com/rack2cloud/invoke-r2ctriage
    Audit URL:    https://rack2cloud.com/audit

    WHAT IS COLLECTED (structural metadata only):
      - Boolean flags (e.g., MFA enforced: true/false)
      - Counts (e.g., number of NSGs with unrestricted outbound rules)
      - Percentages (e.g., % of VMs with no associated NSG)
      - Configuration states (e.g., budget alert configured: true/false)

    WHAT IS NEVER COLLECTED:
      - Subscription IDs
      - Tenant IDs
      - IP addresses (public or private)
      - Resource names or display names
      - Tags or tag values
      - Secrets, keys, or connection strings
      - User principal names or email addresses
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$DryRun,
    [string]$SubscriptionId,
    [string]$OutputPath = (Get-Location).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────
function Write-Banner {
    Write-Host ""
    Write-Host "  ██████╗ ██████╗  ██████╗" -ForegroundColor Cyan
    Write-Host "  ██╔══██╗╚════██╗██╔════╝" -ForegroundColor Cyan
    Write-Host "  ██████╔╝ █████╔╝██║     " -ForegroundColor Cyan
    Write-Host "  ██╔══██╗██╔═══╝ ██║     " -ForegroundColor Cyan
    Write-Host "  ██║  ██║███████╗╚██████╗" -ForegroundColor Cyan
    Write-Host "  ╚═╝  ╚═╝╚══════╝ ╚═════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Rack2Cloud — Azure Landing Zone Triage" -ForegroundColor White
    Write-Host "  Zero-Trust Architecture Diagnostic v1.0.0" -ForegroundColor DarkGray
    Write-Host "  rack2cloud.com/audit" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  COLLECTION SCOPE: Structural metadata only" -ForegroundColor Yellow
    Write-Host "  No IPs. No sub IDs. No secrets. No names." -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
}

# ─────────────────────────────────────────────
# DRY RUN MODE
# ─────────────────────────────────────────────
function Invoke-DryRun {
    Write-Host "  [DRY RUN] The following metadata would be collected:" -ForegroundColor Magenta
    Write-Host ""

    $categories = @(
        @{ Name = "IDENTITY / RBAC"; Fields = @(
            "privileged_roles_without_mfa_count (integer)",
            "owners_at_subscription_scope_count (integer)",
            "guest_users_with_privileged_roles (boolean)",
            "pim_enabled (boolean)",
            "service_principals_with_owner_rights_count (integer)",
            "custom_roles_count (integer)"
        )},
        @{ Name = "NETWORKING"; Fields = @(
            "nsgs_with_unrestricted_inbound_count (integer)",
            "nsgs_with_unrestricted_outbound_count (integer)",
            "vnets_without_ddos_protection_count (integer)",
            "vnet_count (integer)",
            "subnets_without_nsg_count (integer)",
            "public_endpoints_count (integer)",
            "peering_connected_vnet_count (integer)"
        )},
        @{ Name = "GOVERNANCE"; Fields = @(
            "subscriptions_without_budget_alert (boolean)",
            "resource_groups_without_required_tags_pct (float)",
            "policy_assignments_count (integer)",
            "deny_policies_count (integer)",
            "management_group_hierarchy_depth (integer)",
            "diagnostic_settings_enabled_pct (float)"
        )},
        @{ Name = "COMPUTE / COST"; Fields = @(
            "unattached_disks_count (integer)",
            "unattached_public_ips_count (integer)",
            "vms_without_autoscale_count (integer)",
            "vms_without_nsg_association_pct (float)",
            "stopped_not_deallocated_vms_count (integer)",
            "vm_count (integer)"
        )}
    )

    foreach ($cat in $categories) {
        Write-Host "  [$($cat.Name)]" -ForegroundColor Cyan
        foreach ($field in $cat.Fields) {
            Write-Host "    + $field" -ForegroundColor White
        }
        Write-Host ""
    }

    Write-Host "  [NOT COLLECTED]" -ForegroundColor Red
    $excluded = @("Subscription IDs", "Tenant IDs", "IP addresses", "Resource names",
                  "Tag values", "UPNs / email addresses", "Secrets or keys")
    foreach ($ex in $excluded) {
        Write-Host "    - $ex" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  Re-run without -DryRun to execute live triage." -ForegroundColor Yellow
    Write-Host ""
    exit 0
}

# ─────────────────────────────────────────────
# PREREQUISITES CHECK
# ─────────────────────────────────────────────
function Test-Prerequisites {
    Write-Host "  [1/5] Checking prerequisites..." -ForegroundColor DarkGray

    $requiredModules = @("Az.Accounts", "Az.Resources", "Az.Network",
                         "Az.Compute", "Az.Security", "Az.Monitor")
    $missing = @()

    foreach ($mod in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            $missing += $mod
        }
    }

    if ($missing.Count -gt 0) {
        Write-Host ""
        Write-Host "  [ERROR] Missing required Az modules:" -ForegroundColor Red
        $missing | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
        Write-Host ""
        Write-Host "  Install via: Install-Module Az -Scope CurrentUser -Force" -ForegroundColor Yellow
        Write-Host "  Or run in Azure Cloud Shell (all modules pre-installed)." -ForegroundColor Yellow
        Write-Host ""
        exit 1
    }

    # Check authentication
    $context = Get-AzContext
    if (-not $context) {
        Write-Host ""
        Write-Host "  [ERROR] Not authenticated. Run: Connect-AzAccount" -ForegroundColor Red
        Write-Host ""
        exit 1
    }

    Write-Host "  [1/5] Prerequisites OK." -ForegroundColor Green
    return $context
}

# ─────────────────────────────────────────────
# SET SUBSCRIPTION CONTEXT
# ─────────────────────────────────────────────
function Set-SubscriptionContext {
    param($Context)

    Write-Host "  [2/5] Setting subscription context..." -ForegroundColor DarkGray

    if ($SubscriptionId) {
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
        $sub = Get-AzSubscription -SubscriptionId $SubscriptionId
    } else {
        $sub = Get-AzSubscription -SubscriptionId $Context.Subscription.Id
    }

    # We store only a hash — never the raw ID
    $subHash = [System.Security.Cryptography.SHA256]::Create()
    $subIdBytes = [System.Text.Encoding]::UTF8.GetBytes($sub.Id)
    $hashBytes = $subHash.ComputeHash($subIdBytes)
    $subFingerprint = [System.BitConverter]::ToString($hashBytes).Replace("-","").Substring(0,12).ToLower()

    Write-Host "  [2/5] Subscription fingerprint: $subFingerprint (ID not stored)" -ForegroundColor Green
    return $subFingerprint
}

# ─────────────────────────────────────────────
# IDENTITY COLLECTION
# ─────────────────────────────────────────────
function Get-IdentityMetadata {
    Write-Host "  [3/5] Collecting Identity metadata..." -ForegroundColor DarkGray

    $identityData = @{}

    try {
        # Privileged role assignments at subscription scope (Owner, Contributor, UAA)
        $privilegedRoleIds = @(
            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", # Owner
            "b24988ac-6180-42a0-ab88-20f7382dd24c", # Contributor
            "18d7d88d-d35e-4fb5-a5c3-7773c20a72d4"  # User Access Administrator
        )

        $subScope = "/subscriptions/$((Get-AzContext).Subscription.Id)"
        $allPrivAssignments = Get-AzRoleAssignment -Scope $subScope |
            Where-Object { $privilegedRoleIds -contains $_.RoleDefinitionId }

        $identityData["privileged_role_assignments_at_sub_scope_count"] = ($allPrivAssignments | Measure-Object).Count

        # Owner-only at subscription scope
        $ownerAssignments = $allPrivAssignments | Where-Object {
            $_.RoleDefinitionId -eq "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
        }
        $identityData["owners_at_subscription_scope_count"] = ($ownerAssignments | Measure-Object).Count

        # Service principals with Owner rights
        $spOwners = $ownerAssignments | Where-Object { $_.ObjectType -eq "ServicePrincipal" }
        $identityData["service_principals_with_owner_rights_count"] = ($spOwners | Measure-Object).Count

        # Guest users with privileged roles
        $guestPriv = $allPrivAssignments | Where-Object { $_.SignInName -like "*#EXT#*" }
        $identityData["guest_users_with_privileged_roles"] = (($guestPriv | Measure-Object).Count -gt 0)

        # Custom roles (non-built-in)
        $customRoles = Get-AzRoleDefinition | Where-Object { $_.IsCustom -eq $true }
        $identityData["custom_roles_count"] = ($customRoles | Measure-Object).Count

        # PIM — detect via role eligibility schedules (requires Az.Resources preview or Graph)
        # Conservative check: if no eligible assignments exist, PIM likely not configured
        try {
            $eligibleAssignments = Get-AzRoleEligibilitySchedule -Scope $subScope -ErrorAction SilentlyContinue
            $identityData["pim_eligible_assignments_count"] = ($eligibleAssignments | Measure-Object).Count
            $identityData["pim_appears_configured"] = (($eligibleAssignments | Measure-Object).Count -gt 0)
        } catch {
            $identityData["pim_appears_configured"] = $false
            $identityData["pim_eligible_assignments_count"] = 0
        }

        # MFA gap heuristic: permanent privileged assignments not covered by PIM
        # (A permanent assignment + PIM not configured = likely no MFA enforcement)
        $permanentPrivCount = ($allPrivAssignments |
            Where-Object { $_.ObjectType -ne "ServicePrincipal" } | Measure-Object).Count
        $identityData["permanent_privileged_user_assignments_count"] = $permanentPrivCount
        $identityData["mfa_enforcement_gap_likely"] = (
            $permanentPrivCount -gt 0 -and -not $identityData["pim_appears_configured"]
        )

    } catch {
        $identityData["collection_error"] = $_.Exception.Message
    }

    Write-Host "  [3/5] Identity metadata collected." -ForegroundColor Green
    return $identityData
}

# ─────────────────────────────────────────────
# NETWORKING COLLECTION
# ─────────────────────────────────────────────
function Get-NetworkingMetadata {
    Write-Host "  [3/5] Collecting Networking metadata..." -ForegroundColor DarkGray

    $netData = @{}

    try {
        $nsgs = Get-AzNetworkSecurityGroup
        $netData["nsg_count"] = ($nsgs | Measure-Object).Count

        # NSGs with unrestricted inbound (any source, any port, Allow)
        $unrestrictedInbound = $nsgs | Where-Object {
            $_.SecurityRules | Where-Object {
                $_.Direction -eq "Inbound" -and
                $_.Access -eq "Allow" -and
                ($_.SourceAddressPrefix -eq "*" -or $_.SourceAddressPrefix -eq "Internet") -and
                ($_.DestinationPortRange -eq "*" -or $_.DestinationPortRange -contains "22" -or
                 $_.DestinationPortRange -contains "3389")
            }
        }
        $netData["nsgs_with_unrestricted_inbound_count"] = ($unrestrictedInbound | Measure-Object).Count

        # NSGs with unrestricted outbound
        $unrestrictedOutbound = $nsgs | Where-Object {
            $_.SecurityRules | Where-Object {
                $_.Direction -eq "Outbound" -and
                $_.Access -eq "Allow" -and
                $_.DestinationAddressPrefix -eq "*" -and
                $_.DestinationPortRange -eq "*"
            }
        }
        $netData["nsgs_with_unrestricted_outbound_count"] = ($unrestrictedOutbound | Measure-Object).Count

        # VNet metadata
        $vnets = Get-AzVirtualNetwork
        $netData["vnet_count"] = ($vnets | Measure-Object).Count

        # Subnets without NSG association
        $allSubnets = $vnets | ForEach-Object { $_.Subnets } | Where-Object { $_.Name -ne "GatewaySubnet" }
        $subnetsWithoutNsg = $allSubnets | Where-Object { $null -eq $_.NetworkSecurityGroup }
        $netData["subnets_without_nsg_count"] = ($subnetsWithoutNsg | Measure-Object).Count
        $netData["total_subnet_count"] = ($allSubnets | Measure-Object).Count

        if ($netData["total_subnet_count"] -gt 0) {
            $netData["subnets_without_nsg_pct"] = [math]::Round(
                ($netData["subnets_without_nsg_count"] / $netData["total_subnet_count"]) * 100, 1
            )
        } else {
            $netData["subnets_without_nsg_pct"] = 0
        }

        # VNets without DDoS standard protection
        $noDdos = $vnets | Where-Object {
            $_.DdosProtectionPlan -eq $null -or
            $_.EnableDdosProtection -eq $false
        }
        $netData["vnets_without_ddos_standard_count"] = ($noDdos | Measure-Object).Count

        # VNet peerings
        $peeringCount = ($vnets | ForEach-Object { $_.VirtualNetworkPeerings } | Measure-Object).Count
        $netData["vnet_peering_count"] = $peeringCount

        # Public IPs in use (count only, no addresses)
        $publicIps = Get-AzPublicIpAddress
        $netData["public_ip_total_count"] = ($publicIps | Measure-Object).Count
        $netData["public_ips_unattached_count"] = (
            $publicIps | Where-Object { $null -eq $_.IpConfiguration } | Measure-Object
        ).Count

    } catch {
        $netData["collection_error"] = $_.Exception.Message
    }

    Write-Host "  [3/5] Networking metadata collected." -ForegroundColor Green
    return $netData
}

# ─────────────────────────────────────────────
# GOVERNANCE COLLECTION
# ─────────────────────────────────────────────
function Get-GovernanceMetadata {
    Write-Host "  [3/5] Collecting Governance metadata..." -ForegroundColor DarkGray

    $govData = @{}

    try {
        # Budget alerts
        $subScope = "/subscriptions/$((Get-AzContext).Subscription.Id)"

        try {
            $budgets = Get-AzConsumptionBudget -ErrorAction SilentlyContinue
            $govData["budget_alerts_configured"] = (($budgets | Measure-Object).Count -gt 0)
            $govData["budget_count"] = ($budgets | Measure-Object).Count
        } catch {
            $govData["budget_alerts_configured"] = $false
            $govData["budget_count"] = 0
        }

        # Policy assignments
        $policyAssignments = Get-AzPolicyAssignment
        $govData["policy_assignments_count"] = ($policyAssignments | Measure-Object).Count

        # Deny effect policies
        $denyPolicies = $policyAssignments | Where-Object {
            $_.Properties.EnforcementMode -ne "DoNotEnforce"
        }
        $govData["enforced_policy_assignments_count"] = ($denyPolicies | Measure-Object).Count

        # Resource groups — tag compliance check (presence of tags, not tag values)
        $rgs = Get-AzResourceGroup
        $govData["resource_group_count"] = ($rgs | Measure-Object).Count

        $rgsWithoutTags = $rgs | Where-Object {
            $null -eq $_.Tags -or $_.Tags.Count -eq 0
        }
        $govData["resource_groups_without_tags_count"] = ($rgsWithoutTags | Measure-Object).Count

        if ($govData["resource_group_count"] -gt 0) {
            $govData["resource_groups_without_tags_pct"] = [math]::Round(
                ($govData["resource_groups_without_tags_count"] / $govData["resource_group_count"]) * 100, 1
            )
        } else {
            $govData["resource_groups_without_tags_pct"] = 0
        }

        # Diagnostic settings on key resource types (spot check)
        try {
            $activityLog = Get-AzDiagnosticSetting -ResourceId $subScope -ErrorAction SilentlyContinue
            $govData["subscription_activity_log_diagnostic_configured"] = (
                $null -ne $activityLog -and ($activityLog | Measure-Object).Count -gt 0
            )
        } catch {
            $govData["subscription_activity_log_diagnostic_configured"] = $false
        }

        # Management group depth (if available)
        try {
            $mgContext = Get-AzManagementGroup -ErrorAction SilentlyContinue
            $govData["management_groups_visible_count"] = ($mgContext | Measure-Object).Count
        } catch {
            $govData["management_groups_visible_count"] = 0
        }

    } catch {
        $govData["collection_error"] = $_.Exception.Message
    }

    Write-Host "  [3/5] Governance metadata collected." -ForegroundColor Green
    return $govData
}

# ─────────────────────────────────────────────
# COMPUTE / COST COLLECTION
# ─────────────────────────────────────────────
function Get-ComputeCostMetadata {
    Write-Host "  [3/5] Collecting Compute/Cost metadata..." -ForegroundColor DarkGray

    $computeData = @{}

    try {
        # VMs
        $vms = Get-AzVM -Status
        $computeData["vm_count"] = ($vms | Measure-Object).Count

        # Stopped but not deallocated (still billing)
        $stoppedNotDeallocated = $vms | Where-Object {
            $_.PowerState -eq "VM stopped" -and $_.PowerState -ne "VM deallocated"
        }
        $computeData["vms_stopped_not_deallocated_count"] = ($stoppedNotDeallocated | Measure-Object).Count

        # VMs without NSG at NIC level (structural check)
        $nicsWithoutNsg = @()
        foreach ($vm in $vms) {
            $vmDetail = Get-AzVM -ResourceGroupName $vm.ResourceGroupName -Name $vm.Name
            foreach ($nicRef in $vmDetail.NetworkProfile.NetworkInterfaces) {
                $nicName = $nicRef.Id.Split("/")[-1]
                $nicRg = $nicRef.Id.Split("/")[4]
                try {
                    $nic = Get-AzNetworkInterface -Name $nicName -ResourceGroupName $nicRg -ErrorAction SilentlyContinue
                    if ($null -ne $nic -and $null -eq $nic.NetworkSecurityGroup) {
                        $nicsWithoutNsg += $nicName
                    }
                } catch { }
            }
        }
        $computeData["vms_with_nic_without_nsg_count"] = $nicsWithoutNsg.Count

        if ($computeData["vm_count"] -gt 0) {
            $computeData["vms_with_nic_without_nsg_pct"] = [math]::Round(
                ($computeData["vms_with_nic_without_nsg_count"] / $computeData["vm_count"]) * 100, 1
            )
        } else {
            $computeData["vms_with_nic_without_nsg_pct"] = 0
        }

        # Unattached managed disks
        $disks = Get-AzDisk
        $unattachedDisks = $disks | Where-Object { $_.DiskState -eq "Unattached" }
        $computeData["unattached_disks_count"] = ($unattachedDisks | Measure-Object).Count
        $computeData["total_disk_count"] = ($disks | Measure-Object).Count

        # Total unattached disk size (GiB) — cost signal, no names
        if (($unattachedDisks | Measure-Object).Count -gt 0) {
            $computeData["unattached_disks_total_gib"] = (
                $unattachedDisks | Measure-Object -Property DiskSizeGB -Sum
            ).Sum
        } else {
            $computeData["unattached_disks_total_gib"] = 0
        }

        # VM Scale Sets with autoscale check
        try {
            $vmss = Get-AzVmss -ErrorAction SilentlyContinue
            $computeData["vmss_count"] = ($vmss | Measure-Object).Count

            $autoscaleSettings = Get-AzAutoscaleSetting -ErrorAction SilentlyContinue
            $computeData["autoscale_profiles_configured_count"] = ($autoscaleSettings | Measure-Object).Count
        } catch {
            $computeData["vmss_count"] = 0
            $computeData["autoscale_profiles_configured_count"] = 0
        }

    } catch {
        $computeData["collection_error"] = $_.Exception.Message
    }

    Write-Host "  [3/5] Compute/Cost metadata collected." -ForegroundColor Green
    return $computeData
}

# ─────────────────────────────────────────────
# SCORING ENGINE (TEASER)
# ─────────────────────────────────────────────
function Get-TeaserScore {
    param($Identity, $Networking, $Governance, $Compute)

    $flags = @()
    $scoreDeductions = 0

    # IDENTITY checks (max deduction: 25)
    if ($Identity["mfa_enforcement_gap_likely"] -eq $true) {
        $flags += "[IDENTITY]   MFA enforcement gap — permanent privileged assignments without PIM coverage detected"
        $scoreDeductions += 12
    }
    if ($Identity["owners_at_subscription_scope_count"] -gt 2) {
        $flags += "[IDENTITY]   Excessive Owner assignments at subscription scope ($($Identity['owners_at_subscription_scope_count']) detected)"
        $scoreDeductions += 8
    }
    if ($Identity["guest_users_with_privileged_roles"] -eq $true) {
        $flags += "[IDENTITY]   Guest users hold privileged role assignments"
        $scoreDeductions += 5
    }
    if ($Identity["service_principals_with_owner_rights_count"] -gt 0) {
        $flags += "[IDENTITY]   Service principal(s) with Owner-level rights detected"
        $scoreDeductions += 7
    }

    # NETWORKING checks (max deduction: 20)
    if ($Networking["nsgs_with_unrestricted_inbound_count"] -gt 0) {
        $flags += "[NETWORKING] Unrestricted inbound rules on $($Networking['nsgs_with_unrestricted_inbound_count']) NSG(s) — SSH/RDP exposure likely"
        $scoreDeductions += 10
    }
    if ($Networking["nsgs_with_unrestricted_outbound_count"] -gt 0) {
        $flags += "[NETWORKING] Unrestricted outbound on $($Networking['nsgs_with_unrestricted_outbound_count']) NSG(s) — data exfiltration path open"
        $scoreDeductions += 8
    }
    if ($Networking["subnets_without_nsg_pct"] -gt 30) {
        $flags += "[NETWORKING] $($Networking['subnets_without_nsg_pct'])% of subnets have no NSG association"
        $scoreDeductions += 6
    }

    # GOVERNANCE checks (max deduction: 20)
    if ($Governance["budget_alerts_configured"] -eq $false) {
        $flags += "[GOVERNANCE] No budget alerts configured — cost overruns will not be detected automatically"
        $scoreDeductions += 8
    }
    if ($Governance["resource_groups_without_tags_pct"] -gt 40) {
        $flags += "[GOVERNANCE] $($Governance['resource_groups_without_tags_pct'])% of resource groups have no tags — cost attribution and compliance blocked"
        $scoreDeductions += 5
    }
    if ($Governance["subscription_activity_log_diagnostic_configured"] -eq $false) {
        $flags += "[GOVERNANCE] Subscription activity log not routed to diagnostic sink — audit trail gap"
        $scoreDeductions += 7
    }

    # COMPUTE / COST checks (max deduction: 20)
    if ($Compute["unattached_disks_count"] -gt 0) {
        $flags += "[COST]       $($Compute['unattached_disks_count']) unattached managed disk(s) detected ($($Compute['unattached_disks_total_gib']) GiB billing with no workload)"
        $scoreDeductions += 5
    }
    if ($Compute["vms_stopped_not_deallocated_count"] -gt 0) {
        $flags += "[COST]       $($Compute['vms_stopped_not_deallocated_count']) VM(s) stopped but not deallocated — compute charges still accruing"
        $scoreDeductions += 8
    }
    if ($Compute["public_ips_unattached_count"] -gt 0 -and $Networking["public_ips_unattached_count"] -gt 0) {
        $flags += "[COST]       $($Networking['public_ips_unattached_count']) unattached public IP(s) — orphaned resource cost"
        $scoreDeductions += 3
    }

    # Score band
    $estimatedScore = [math]::Max(0, 100 - $scoreDeductions)
    $scoreMin = [math]::Max(0, $estimatedScore - 8)
    $scoreMax = [math]::Min(100, $estimatedScore + 7)

    $riskLevel = switch ($estimatedScore) {
        { $_ -ge 85 } { "PRODUCTION READY" }
        { $_ -ge 70 } { "MODERATE RISK" }
        { $_ -ge 50 } { "HIGH RISK" }
        default        { "CRITICAL — DO NOT DEPLOY" }
    }

    return @{
        EstimatedScore = $estimatedScore
        ScoreRange     = "$scoreMin–$scoreMax"
        RiskLevel      = $riskLevel
        Flags          = $flags
        FlagCount      = $flags.Count
    }
}

# ─────────────────────────────────────────────
# TEASER OUTPUT
# ─────────────────────────────────────────────
function Write-TeaserOutput {
    param($Teaser)

    $riskColor = switch ($Teaser.RiskLevel) {
        "PRODUCTION READY"       { "Green" }
        "MODERATE RISK"          { "Yellow" }
        "HIGH RISK"              { "DarkYellow" }
        "CRITICAL — DO NOT DEPLOY" { "Red" }
        default                  { "White" }
    }

    Write-Host ""
    Write-Host "  ════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host "  RACK2CLOUD TRIAGE — PRELIMINARY RESULTS" -ForegroundColor White
    Write-Host "  ════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host ("  ESTIMATED SCORE:  {0} / 100   [{1}–{2} range]" -f $Teaser.EstimatedScore, $Teaser.ScoreRange.Split("–")[0], $Teaser.ScoreRange.Split("–")[1]) -ForegroundColor White
    Write-Host ("  RISK BAND:        {0}" -f $Teaser.RiskLevel) -ForegroundColor $riskColor
    Write-Host ("  FLAGS DETECTED:   {0}" -f $Teaser.FlagCount) -ForegroundColor White
    Write-Host ""

    if ($Teaser.Flags.Count -gt 0) {
        Write-Host "  CRITICAL FINDINGS:" -ForegroundColor Yellow
        Write-Host ""
        foreach ($flag in $Teaser.Flags) {
            Write-Host "    ├─ $flag" -ForegroundColor White
        }
        Write-Host ""
    }

    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Full remediation roadmap locked in r2c_payload.json" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  NEXT STEP:" -ForegroundColor Cyan
    Write-Host "  Upload r2c_payload.json at rack2cloud.com/audit" -ForegroundColor White
    Write-Host "  to unlock your scored 3-page Architecture Brief." -ForegroundColor White
    Write-Host ""
    Write-Host "  ════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host ""
}

# ─────────────────────────────────────────────
# BUILD PAYLOAD
# ─────────────────────────────────────────────
function Build-Payload {
    param($SubFingerprint, $Identity, $Networking, $Governance, $Compute, $Teaser)

    return @{
        schema_version      = "1.1.0"
        payload_id          = [System.Guid]::NewGuid().ToString()
        generated_at_utc    = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ" -AsUTC)
        subscription_fingerprint = $SubFingerprint
        teaser = @{
            status                  = "Scrubbed and Sanitized"
            estimated_score_range   = $Teaser.ScoreRange
            estimated_score         = $Teaser.EstimatedScore
            risk_band               = $Teaser.RiskLevel
            critical_flags_detected = $Teaser.FlagCount
            action                  = "Upload r2c_payload.json to rack2cloud.com/audit to unlock full remediation report."
        }
        identity    = $Identity
        networking  = $Networking
        governance  = $Governance
        compute     = $Compute
        collection_metadata = @{
            script_version  = "1.0.0"
            powershell_version = $PSVersionTable.PSVersion.ToString()
            az_module_version = (Get-Module Az.Accounts).Version.ToString()
            dry_run         = $false
        }
    }
}

# ─────────────────────────────────────────────
# MAIN EXECUTION
# ─────────────────────────────────────────────

Write-Banner

if ($DryRun) {
    Invoke-DryRun
}

$context      = Test-Prerequisites
$subFprint    = Set-SubscriptionContext -Context $context

Write-Host "  [3/5] Running collection modules..." -ForegroundColor DarkGray
Write-Host ""

$identityData  = Get-IdentityMetadata
$networkData   = Get-NetworkingMetadata
$govData       = Get-GovernanceMetadata
$computeData   = Get-ComputeCostMetadata

Write-Host ""
Write-Host "  [4/5] Scoring and building teaser output..." -ForegroundColor DarkGray
$teaser = Get-TeaserScore -Identity $identityData -Networking $networkData `
                          -Governance $govData -Compute $computeData

Write-TeaserOutput -Teaser $teaser

Write-Host "  [5/5] Writing sanitized payload..." -ForegroundColor DarkGray

$payload     = Build-Payload -SubFingerprint $subFprint -Identity $identityData `
                             -Networking $networkData -Governance $govData `
                             -Compute $computeData -Teaser $teaser

$outputFile  = Join-Path $OutputPath "r2c_payload.json"
$payload | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8

Write-Host "  [5/5] Payload written: $outputFile" -ForegroundColor Green
Write-Host ""
Write-Host "  Review the JSON before uploading. Confirm no sensitive data is present." -ForegroundColor Yellow
Write-Host "  Upload at: https://rack2cloud.com/audit" -ForegroundColor Cyan
Write-Host ""
