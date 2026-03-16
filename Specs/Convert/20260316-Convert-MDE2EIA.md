# Convert-MDE2EIA.ps1 Specification

## Document Information
- **Specification Version:** 1.0
- **Date:** 2026-03-16
- **Status:** Draft
- **Target Module:** Migrate2GSA
- **Function Name:** Convert-MDE2EIA
- **Author:** Andres Canello
---

## Overview

This PowerShell function converts Microsoft Defender for Endpoint (MDE) web filtering configuration to Microsoft Entra Internet Access (EIA) format. The function processes Web Content Filtering (WCF) policies and URL/Domain indicators exported by `Export-MDEWebFilteringConfig` to generate CSV files ready for import into EIA via `Start-EntraInternetAccessProvisioning`.

> **Note:** MDE IP indicators are **not converted** because EIA does not support IP addresses as policy destinations. IP indicators found in the input are logged as warnings and included in the conversion summary for manual review.

### Purpose
- Transform MDE WCF policies (blocked and audited web categories) into EIA web content filtering policies
- Convert MDE custom URL/Domain indicators into EIA FQDN filtering policies
- Log and skip MDE IP indicators (not supported as EIA destinations)
- Map MDE web category names to EIA web category identifiers using a hardcoded mapping (both are Microsoft products sharing the same taxonomy)
- Generate Security Profiles with a Default profile for broadly-scoped rules and Override profiles for device-group-scoped rules
- Produce import-ready CSV files for EIA configuration

### Design Alignment
This function follows the same architectural patterns as `Convert-ZIA2EIA.ps1`:
- Single function with internal helper functions
- Phased processing approach (Load → Process → Export)
- Comprehensive logging using `Write-LogMessage`
- Region-based code organization
- CSV export using shared utilities

---

## MDE Source Product Model

### Three Configuration Object Types

MDE web filtering consists of three distinct configuration object types, all exported to JSON files by `Export-MDEWebFilteringConfig`:

1. **Web Content Filtering (WCF) Policies** (`wcf_policies.json`) — Category-level filtering that blocks or audits web content by category. Contains:
   - `BlockedCategories` — array of web category names that are actively blocked
   - `AuditCategories` — array of web category names that are monitored (logged but not blocked)
   - `RbacGroupNames` — device group scoping (`"All device groups"` or array of group names)

2. **IP Indicators** (`ip_indicators.json`) — Custom threat indicators targeting IP addresses. **Not converted** — EIA does not support IP addresses as policy destinations. These are logged as warnings for manual review.

3. **URL/Domain Indicators** (`url_indicators.json`) — Custom threat indicators targeting URLs and domains. Contains:
   - `indicatorValue` — the URL or domain
   - `indicatorType` — `URL` or `DomainURL`
   - `action` — `AlertOnly`, `Allow`, `Block`, or `Warn`
   - `rbacGroupNames` — device group scoping
   - `isEnabled` — whether the indicator is active

### Supporting Data

- **Device Groups** (`device_groups.json`) — Used for cross-referencing device group names and Entra ID group assignments. Not directly converted but consumed for scoping resolution.

### Scoping Model

MDE uses **device groups** (also called machine groups) for policy scoping, which is fundamentally different from EIA's user/group-based scoping:
- **`RbacGroupNames = "All device groups"`** (or empty `rbacGroupIds`) — policy/indicator applies to all devices → maps to Default Security Profile
- **Specific device group names** — policy/indicator scoped to named device groups → maps to Override Security Profiles with placeholder group names derived from the device group name (requires manual review to assign correct Entra user/security groups)

### Category Taxonomy

MDE uses 28 web content categories that are a subset of the same Microsoft web category taxonomy used by EIA. Since both products share the same taxonomy, category mapping is hardcoded (no external mapping file required). The only naming differences are display format (MDE uses display names with spaces; EIA uses PascalCase identifiers).

---

## EIA Target Structure

### Security Profile Architecture

The conversion produces a tiered Security Profile structure:

**Default Security Profile (Priority: 50000)**
- Contains all policies converted from:
  - WCF policies scoped to "All device groups"
  - URL/Domain indicators scoped to "All device groups" (empty `rbacGroupIds`)
- Assigned via Conditional Access policy to `"All Internet Access Users"` (placeholder group name)
- Acts as the baseline

**Override Security Profiles (Priority: 1000, 1100, 1200, ...)**
- One per unique device group scope combination
- Policies/URL indicators targeting the same set of device groups are combined into the same Override Security Profile
- Each override gets its own Conditional Access policy with placeholder group names derived from MDE device group names
- All Override profiles are flagged with `ReviewNeeded=Yes` because device-group-to-user-group mapping requires manual verification
- Lower priority number = evaluated first = overrides the default

### Mapping Summary

| MDE Element | Converts To | EIA Element | Notes |
|-------------|-------------|-------------|-------|
| WCF blocked categories | → | WCF Policy (webCategory rules, `Block`) | Direct mapping via hardcoded table |
| WCF audited categories | → | WCF Policy (webCategory rules, `Block`) | `ReviewNeeded=Yes` — original was monitor-only |
| IP indicators (all actions) | → | **Skipped** | EIA does not support IP destinations; logged as WARN |
| URL/Domain indicator (`Block`) | → | WCF Policy (FQDN rule, `Block`) | Dual FQDN pattern; grouped by action + scope |
| URL/Domain indicator (`Allow`) | → | WCF Policy (FQDN rule, `Allow`) | Dual FQDN pattern; grouped by action + scope |
| URL/Domain indicator (`Warn`) | → | WCF Policy (FQDN rule, `Block`) | `ReviewNeeded=Yes`; dual FQDN pattern |
| URL/Domain indicator (`AlertOnly`) | → | WCF Policy (FQDN rule, `Allow`) | `ReviewNeeded=Yes`; dual FQDN pattern |
| `RbacGroupNames = "All device groups"` | → | Default Security Profile | Priority 50000 |
| Specific device group scope | → | Override Security Profile | Priority 1000+; placeholder group names |
| Disabled URL/Domain indicators | → | Skipped | Logged at DEBUG level |
| Expired URL/Domain indicators | → | Skipped | Logged at INFO level |

### Action Mapping

| MDE Action | EIA PolicyAction | ReviewNeeded | ReviewDetails |
|------------|-----------------|--------------|---------------|
| `Block` | `Block` | No | — |
| `Allow` | `Allow` | No | — |
| `Warn` | `Block` | Yes | "Original MDE action was 'Warn' (user bypass allowed) — converted to Block" |
| `AlertOnly` | `Allow` | Yes | "Original MDE action was 'AlertOnly' (monitor only, no enforcement) — converted to Allow" |

### Hardcoded Category Mapping

Since MDE and EIA share the same Microsoft web category taxonomy, categories are mapped via a hardcoded lookup table. The export function (`Export-MDEWebFilteringConfig`) resolves MDE numeric category IDs to display names; this conversion function maps those display names to EIA PascalCase identifiers.

| MDE Category Name | EIA Category Identifier |
|---|---|
| Chat | `Chat` |
| Child Abuse Images | `ChildAbuseImages` |
| Criminal activity | `CriminalActivity` |
| Cults | `Cults` |
| Download Sites | `DownloadSites` |
| Gambling | `Gambling` |
| Games | `Games` |
| Hacking | `Hacking` |
| Hate & intolerance | `HateAndIntolerance` |
| Illegal drug | `IllegalDrug` |
| Illegal software | `IllegalSoftware` |
| Image sharing | `ImageSharing` |
| Instant messaging | `InstantMessaging` |
| Newly registered domains | `NewlyRegisteredDomains` |
| Nudity | `Nudity` |
| Parked Domains | `ParkedDomains` |
| Peer-to-peer | `PeerToPeer` |
| Pornography/Sexually explicit | `PornographyAndSexuallyExplicit` |
| Professional networking | `ProfessionalNetworking` |
| School cheating | `Cheating` |
| Self-harm | `SelfHarm` |
| Sex education | `SexEducation` |
| Social networking | `SocialNetworking` |
| Streaming media & downloads | `StreamingMediaAndDownloads` |
| Tasteless | `Tasteless` |
| Violence | `Violence` |
| Weapons | `Weapons` |
| Web-based email | `WebBasedEmail` |

> **Note:** "School cheating" maps to `Cheating` — this is the only non-trivial name difference. All other mappings are straightforward PascalCase conversions.

---

## Policy & Rule Naming Conventions

### Policy Naming

| Source | EIA PolicyName Format | Example |
|--------|----------------------|---------|
| WCF blocked categories | `WCF-[PolicyName]-Blocked-Block` | `WCF-MDE-Policy1-Blocked-Block` |
| WCF audited categories | `WCF-[PolicyName]-Audited-Block` | `WCF-MDE-Policy1-Audited-Block` |
| URL/Domain indicators (Block, default scope) | `Indicators-FQDN-Block` | `Indicators-FQDN-Block` |
| URL/Domain indicators (Allow, default scope) | `Indicators-FQDN-Allow` | `Indicators-FQDN-Allow` |
| URL/Domain indicators (Block, specific scope) | `Indicators-FQDN-[DeviceGroupName]-Block` | `Indicators-FQDN-MDE-DeviceGroup1-Block` |

**Name sanitization:** Policy names are sanitized by replacing whitespace with hyphens and removing characters not in `[a-zA-Z0-9_-]`.

### Rule Naming

| Rule Type | RuleName Format | Notes |
|-----------|----------------|-------|
| WebCategory (blocked) | `BlockedCategories` | Never split |
| WebCategory (audited) | `AuditedCategories` | Never split |
| FQDN | `FQDNs`, `FQDNs-2`, `FQDNs-3` | Split at 300-char limit |

### Security Profile Naming

| Scope | SecurityProfileName | CADisplayName |
|-------|-------------------|---------------|
| Default (all device groups) | `Default-MDE` | `CA-EIA-Default-MDE` |
| Override (specific groups) | `Override-[DeviceGroupName]` | `CA-EIA-Override-[DeviceGroupName]` |

---

## Input Files

All input files are JSON files produced by `Export-MDEWebFilteringConfig`. The function also accepts an optional `device_groups.json` for cross-reference.

### 1. wcf_policies.json
**Source:** `Export-MDEWebFilteringConfig` output
**Required:** No (at least one of `wcf_policies.json` or `url_indicators.json` must be provided)

#### Description
Contains WCF policies with resolved category names and device group scoping.

#### Schema

```json
[
  {
    "PolicyName": "MDE-Policy1",
    "BlockedCategories": ["Gambling"],
    "AuditCategories": ["Criminal activity", "Hacking"],
    "RbacGroupNames": "All device groups",
    "CreatedBy": "admin@contoso.com",
    "LastUpdateTime": "2026-02-25T10:58:14.5302747"
  }
]
```

#### Key Fields to Process

| Field | Type | Description | Processing Notes |
|-------|------|-------------|------------------|
| `PolicyName` | string | MDE policy name | Used in EIA policy naming; subject to include/exclude filtering |
| `BlockedCategories` | string[] | Category names that are blocked | Map to EIA categories via hardcoded table |
| `AuditCategories` | string[] | Category names that are audited | Map to EIA categories; convert to Block with `ReviewNeeded=Yes` |
| `RbacGroupNames` | string or string[] | Device group scope | `"All device groups"` → Default profile; array of names → Override profile |
| `CreatedBy` | string | Creator UPN | Log for reference |
| `LastUpdateTime` | string (ISO 8601) | Last modification | Log for reference |

#### Processing Rules
1. Process all WCF policies (no state field — WCF policies are always active in MDE)
2. Apply `IncludePolicyName` / `ExcludePolicyName` filter on `PolicyName`
3. For each policy, create up to 2 EIA policies:
   - One `Block` policy for `BlockedCategories` (if non-empty)
   - One `Block` policy for `AuditCategories` with `ReviewNeeded=Yes` (if non-empty)
4. Map each category name to EIA PascalCase identifier using the hardcoded mapping
5. If a category name is not found in the mapping (e.g., `"Unknown (99)"`): use placeholder `UNMAPPED:CategoryName`, set `ReviewNeeded=Yes`

### 2. ip_indicators.json
**Source:** `Export-MDEWebFilteringConfig` output
**Required:** No
**Converted:** **No** — IP addresses are not supported as EIA destinations.

#### Description
Contains custom IP address indicators. **These are not converted to EIA policies.** Instead, the function reads the file, counts the indicators, and logs a warning summarizing how many IP indicators were skipped and their details (value, action, title). This information appears in the conversion summary so administrators know which rules require manual re-creation or alternative handling.

#### Processing Rules
1. If `IpIndicatorsPath` is provided, load the file and count the indicators
2. Log each IP indicator at WARN level: `"IP indicator '[title]' ([value], action: [action]) — skipped: EIA does not support IP address destinations"`
3. Track total count in `$stats.IpIndicatorsSkipped` for the conversion summary
4. Do **not** create any EIA policies from IP indicators

### 3. url_indicators.json
**Source:** `Export-MDEWebFilteringConfig` output
**Required:** No (at least one of `wcf_policies.json` or `url_indicators.json` must be provided)

#### Description
Contains custom URL and domain indicators with resolved action and type enums.

#### Schema

```json
[
  {
    "indicatorId": 57,
    "indicatorType": "URL",
    "indicatorValue": "facebook.com",
    "rbacGroupIds": [],
    "isEnabled": true,
    "expirationTime": null,
    "action": "Warn",
    "severity": "Medium",
    "title": "Facebook",
    "description": "Facebook desc",
    "rbacGroupNames": "All device groups"
  }
]
```

#### Key Fields to Process

| Field | Type | Description | Processing Notes |
|-------|------|-------------|------------------|
| `indicatorId` | int | Unique indicator ID | Log for reference |
| `indicatorType` | string | `"URL"` or `"DomainURL"` | Both treated as FQDN destinations |
| `indicatorValue` | string | URL or domain | Apply dual FQDN pattern |
| `isEnabled` | bool | Whether active | Only process `true` |
| `expirationTime` | string/null | Expiration timestamp | Skip expired with INFO log |
| `action` | string | `AlertOnly`, `Allow`, `Block`, `Warn` | Map per action mapping table |
| `title` | string | Indicator title | Log for reference |
| `description` | string | Indicator description | Log for reference |
| `rbacGroupNames` | string or string[] | Device group scope | Scoping resolution |

#### Processing Rules
1. Skip indicators where `isEnabled = false` (log at DEBUG level)
2. Skip indicators where `expirationTime` is in the past (log at INFO level)
3. Apply dual FQDN pattern: each `indicatorValue` produces two entries (`domain.com;*.domain.com`)
4. If `indicatorValue` contains a path (`/`), classify as URL type and use as-is (no dual pattern)
5. Group enabled, non-expired indicators by: (`mappedAction` × `scopeKey`)
6. Each group becomes one EIA policy with FQDN rules
7. Apply 300-character limit splitting for `RuleDestinations`

### 4. device_groups.json
**Source:** `Export-MDEWebFilteringConfig` output
**Required:** No (used for cross-reference when WCF policies or indicators reference specific device groups)

#### Description
Contains device group definitions with Entra ID group assignments. Used to derive placeholder group names for Override Security Profiles.

#### Key Fields to Process

| Field | Type | Description | Processing Notes |
|-------|------|-------------|------------------|
| `MachineGroupId` | int | Unique device group ID | Cross-reference key |
| `Name` | string | Device group name | Used in Override Security Profile naming |
| `IsUnassignedMachineGroup` | bool | Default catch-all group | Skip for override profiles |
| `MachineGroupAssignments` | array | Entra ID group assignments | Extract `DisplayName` for placeholder group in CA policy |
| `MachineGroupAssignments[].WcdAadGroup.DisplayName` | string | Entra group display name | Used as placeholder in `EntraGroups` (flagged for review) |
| `MachineGroupAssignments[].WcdAadGroup.ObjectId` | string (GUID) | Entra group object ID | Log for reference |

#### Processing Rules
1. Build a lookup table: device group name → Entra group display names (from `MachineGroupAssignments`)
2. Skip the unassigned machine group (`IsUnassignedMachineGroup = true`)
3. If a device group has no `MachineGroupAssignments`, use placeholder `_Replace_Me` for EntraGroups
4. Log each device group and its Entra assignments at INFO level

---

## Output Files

All output files are created in `$OutputBasePath` with consistent timestamp prefix.

### 1. Policies CSV
**Filename:** `[yyyyMMdd_HHmmss]_EIA_Policies.csv`

#### Description
Contains all web content filtering policies for WCF category rules and indicator rules.

#### Fields

| Field | Description | Example | Notes |
|-------|-------------|---------|-------|
| PolicyName | Policy name | `WCF-MDE-Policy1-Blocked-Block` | Unique identifier |
| PolicyType | Type of policy | `WebContentFiltering` | Always `WebContentFiltering` |
| PolicyAction | Block or Allow | `Block`, `Allow` | From action mapping |
| Description | Policy description | `Converted from MDE WCF policy: MDE-Policy1 (blocked categories)` | Source context |
| RuleType | Type of destination | `webCategory`, `FQDN` | One type per row |
| RuleDestinations | Semicolon-separated list | `Gambling;Hacking;CriminalActivity` | EIA PascalCase category names |
| RuleName | Sub-rule identifier | `BlockedCategories`, `FQDNs` | For grouping/splitting |
| ReviewNeeded | Manual review flag | `Yes`, `No` | See review conditions below |
| ReviewDetails | Reason for review | `Original MDE action was 'Warn'...` | Semicolon-separated reasons |
| Provision | Provisioning flag | `yes`, `no` | `no` if `ReviewNeeded=Yes` |

#### Review Conditions

`ReviewNeeded=Yes` is set when any of the following apply:
- Audited categories (original action was monitor-only, converted to Block)
- `Warn` action URL/Domain indicators (original allowed user bypass, converted to Block)
- `AlertOnly` action URL/Domain indicators (original was monitor-only, converted to Allow)
- Unmapped category names (should not occur with hardcoded mapping, but handled defensively)
- Override Security Profile scope (device-group-to-user-group mapping needs verification)

#### FQDN Dual-Entry Pattern

When converting URL/Domain indicator values, each domain produces two FQDN entries:
- `domain.com` — matches the bare domain
- `*.domain.com` — matches all subdomains

Example: An indicator with `indicatorValue = "facebook.com"` produces:
```
RuleDestinations: facebook.com;*.facebook.com
```

If the `indicatorValue` contains a path (e.g., `example.com/path`), it is treated as a URL and used as-is without dual pattern.

#### RuleDestinations Character Limit
- **FQDN rules**: 300-character limit per `RuleDestinations` field. If exceeded, split into multiple rules with numeric suffixes (`FQDNs`, `FQDNs-2`, `FQDNs-3`)
- **webCategory rules**: No character limit, never split

### 2. Security Profiles CSV
**Filename:** `[yyyyMMdd_HHmmss]_EIA_SecurityProfiles.csv`

#### Description
Contains security profile definitions that reference web content filtering policies and assign them to users/groups via Conditional Access.

#### Fields

| Field | Description | Example | Notes |
|-------|-------------|---------|-------|
| SecurityProfileName | Profile name | `Default-MDE` | Unique identifier |
| Priority | Profile priority | `50000` | Lower = higher precedence |
| SecurityProfileLinks | Policy links with priorities | `WCF-MDE-Policy1-Blocked-Block:100;Indicators-FQDN-Block:200` | `PolicyName:Priority` format |
| CADisplayName | Conditional Access policy name | `CA-EIA-Default-MDE` | Required |
| EntraUsers | Semicolon-separated UPNs | `""` | Empty for default; placeholder for overrides |
| EntraGroups | Semicolon-separated group names | `All Internet Access Users` | Placeholder names |
| Provision | Provisioning flag | `yes` | Always `yes` for security profiles |

#### Default Security Profile

| Field | Value |
|-------|-------|
| SecurityProfileName | `Default-MDE` |
| Priority | `50000` |
| SecurityProfileLinks | All policies from "All device groups" scope |
| CADisplayName | `CA-EIA-Default-MDE` |
| EntraGroups | `All Internet Access Users` |

#### Override Security Profiles

| Field | Value |
|-------|-------|
| SecurityProfileName | `Override-[DeviceGroupName]` |
| Priority | Starting at `1000`, incrementing by `100` |
| SecurityProfileLinks | Policies from rules targeting this device group scope |
| CADisplayName | `CA-EIA-Override-[DeviceGroupName]` |
| EntraGroups | Device group's Entra ID group `DisplayName` from `device_groups.json` (placeholder — flagged for review). If no Entra group assignment exists, `_Replace_Me` |
| EntraUsers | `""` |

### 3. Log File
**Filename:** `[yyyyMMdd_HHmmss]_Convert-MDE2EIA.log`
**Location:** Same directory as output CSV files (`$OutputBasePath`)

#### Description
Comprehensive log file created by `Write-LogMessage` with all processing details, warnings, and statistics.

---

## Processing Logic

### Phase 1: Data Loading and Validation

#### 1.1 Initialize Logging
```powershell
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath = Join-Path $OutputBasePath "${timestamp}_Convert-MDE2EIA.log"
```

#### 1.2 Load Input Files
1. Validate that at least one of `WcfPoliciesPath` or `UrlIndicatorsPath` is provided — Fatal error if none specified
2. If `WcfPoliciesPath` is provided: Load `wcf_policies.json` — Fatal error if invalid JSON
3. If `IpIndicatorsPath` is provided: Load `ip_indicators.json` — Non-fatal (used only for skip-and-log reporting)
4. If `UrlIndicatorsPath` is provided: Load `url_indicators.json` — Fatal error if invalid JSON
5. If `DeviceGroupsPath` is provided: Load `device_groups.json` — Non-fatal if missing (scoping will use names as-is)

#### 1.3 Build Lookup Tables

```powershell
# Hardcoded MDE category name → EIA PascalCase mapping
$mdeCategoryMap = @{
    "Chat"                            = "Chat"
    "Child Abuse Images"              = "ChildAbuseImages"
    "Criminal activity"               = "CriminalActivity"
    "Cults"                           = "Cults"
    "Download Sites"                  = "DownloadSites"
    "Gambling"                        = "Gambling"
    "Games"                           = "Games"
    "Hacking"                         = "Hacking"
    "Hate & intolerance"              = "HateAndIntolerance"
    "Illegal drug"                    = "IllegalDrug"
    "Illegal software"                = "IllegalSoftware"
    "Image sharing"                   = "ImageSharing"
    "Instant messaging"               = "InstantMessaging"
    "Newly registered domains"        = "NewlyRegisteredDomains"
    "Nudity"                          = "Nudity"
    "Parked Domains"                  = "ParkedDomains"
    "Peer-to-peer"                    = "PeerToPeer"
    "Pornography/Sexually explicit"   = "PornographyAndSexuallyExplicit"
    "Professional networking"         = "ProfessionalNetworking"
    "School cheating"                 = "Cheating"
    "Self-harm"                       = "SelfHarm"
    "Sex education"                   = "SexEducation"
    "Social networking"               = "SocialNetworking"
    "Streaming media & downloads"     = "StreamingMediaAndDownloads"
    "Tasteless"                       = "Tasteless"
    "Violence"                        = "Violence"
    "Weapons"                         = "Weapons"
    "Web-based email"                 = "WebBasedEmail"
}

# Device group name → Entra group display names (from device_groups.json)
$deviceGroupEntraMap = @{}
if ($deviceGroups) {
    foreach ($group in $deviceGroups) {
        if ($group.IsUnassignedMachineGroup) { continue }
        $groupName = if ([string]::IsNullOrEmpty($group.Name)) { "Unnamed-$($group.MachineGroupId)" } else { $group.Name }
        $entraGroups = @()
        if ($group.MachineGroupAssignments) {
            foreach ($assignment in @($group.MachineGroupAssignments)) {
                if ($assignment.WcdAadGroup.DisplayName) {
                    $entraGroups += $assignment.WcdAadGroup.DisplayName
                }
            }
        }
        $deviceGroupEntraMap[$groupName] = if ($entraGroups.Count -gt 0) { $entraGroups } else { @("_Replace_Me") }
    }
}

# Collections for output
$allPolicies = @()
$defaultScopePolicies = @()       # policy names for the Default Security Profile
$scopedPolicyBuckets = @{}        # scopeKey → { DeviceGroupNames, EntraGroups, Policies }

# Flags for what was provided
$hasWcfPolicies = -not [string]::IsNullOrWhiteSpace($WcfPoliciesPath)
$hasIpIndicators = -not [string]::IsNullOrWhiteSpace($IpIndicatorsPath)
$hasUrlIndicators = -not [string]::IsNullOrWhiteSpace($UrlIndicatorsPath)

# Statistics
$stats = @{
    WcfPoliciesProcessed         = 0
    WcfPoliciesSkippedByFilter   = 0
    CategoriesMapped             = 0
    CategoriesUnmapped           = 0
    IpIndicatorsSkipped          = 0
    UrlIndicatorsProcessed       = 0
    UrlIndicatorsSkippedDisabled = 0
    UrlIndicatorsSkippedExpired  = 0
    IndicatorsWarn               = 0
    IndicatorsAlertOnly          = 0
    PoliciesCreated              = 0
    SecurityProfilesCreated      = 0
}
```

### Phase 2: WCF Policy Processing

> **Conditional:** This phase is only executed when `WcfPoliciesPath` is provided. If not provided, skip to Phase 3.

#### 2.1 Process Each WCF Policy

```
For each WCF policy in wcf_policies.json:
    # Apply policy name filter
    If IncludePolicyName or ExcludePolicyName specified:
        Test PolicyName against include/exclude patterns (case-insensitive -like matching)
        If not included or excluded: skip, log at INFO, increment WcfPoliciesSkippedByFilter, continue

    Log PolicyName, category counts at INFO level

    # Determine scope
    $scopeKey = Resolve-ScopeKey -RbacGroupNames $policy.RbacGroupNames

    # Process BlockedCategories
    If BlockedCategories is non-empty:
        Map each category name via hardcoded $mdeCategoryMap
        Create WCF Block policy with webCategory rules
        Route to appropriate scope bucket

    # Process AuditCategories
    If AuditCategories is non-empty:
        Map each category name via hardcoded $mdeCategoryMap
        Create WCF Block policy with webCategory rules, ReviewNeeded=Yes
        Route to appropriate scope bucket

    Increment WcfPoliciesProcessed
```

#### 2.2 Category Mapping for WCF Policies

```powershell
function Resolve-MdeCategory {
    param(
        [Parameter(Mandatory)]
        [string]$CategoryName
    )

    if ($mdeCategoryMap.ContainsKey($CategoryName)) {
        $stats.CategoriesMapped++
        return @{
            EIACategory = $mdeCategoryMap[$CategoryName]
            IsMapped    = $true
        }
    }
    else {
        $stats.CategoriesUnmapped++
        Write-LogMessage "Unknown MDE category '$CategoryName' — not in hardcoded mapping" -Level WARN
        return @{
            EIACategory = "UNMAPPED:$CategoryName"
            IsMapped    = $false
        }
    }
}
```

#### 2.3 Create Block Policy for Blocked Categories

```powershell
$mappedCategories = @()
$hasUnmapped = $false
$reviewReasons = @()

foreach ($catName in $policy.BlockedCategories) {
    $result = Resolve-MdeCategory -CategoryName $catName
    $mappedCategories += $result.EIACategory
    if (-not $result.IsMapped) {
        $hasUnmapped = $true
        $reviewReasons += "Unmapped category: $catName"
    }
}

$policyNameClean = $policy.PolicyName -replace '\s+','-' -replace '[^a-zA-Z0-9_-]',''
$policyName = "WCF-$policyNameClean-Blocked-Block"

$policyEntry = @{
    PolicyName       = $policyName
    PolicyType       = "WebContentFiltering"
    PolicyAction     = "Block"
    Description      = "Converted from MDE WCF policy: $($policy.PolicyName) (blocked categories)"
    RuleType         = "webCategory"
    RuleDestinations = $mappedCategories -join ";"
    RuleName         = "BlockedCategories"
    ReviewNeeded     = if ($hasUnmapped) { "Yes" } else { "No" }
    ReviewDetails    = $reviewReasons -join "; "
    Provision        = if ($hasUnmapped) { "no" } else { "yes" }
}

$allPolicies += $policyEntry
# Route $policyName to Default or Override scope (see 2.5)
```

#### 2.4 Create Block Policy for Audited Categories

```powershell
$mappedCategories = @()
$reviewReasons = @("Original MDE action was 'Audit' (monitor only, no enforcement) — converted to Block")
# Audited categories always require review
$hasReview = $true

foreach ($catName in $policy.AuditCategories) {
    $result = Resolve-MdeCategory -CategoryName $catName
    $mappedCategories += $result.EIACategory
    if (-not $result.IsMapped) {
        $reviewReasons += "Unmapped category: $catName"
    }
}

$policyNameClean = $policy.PolicyName -replace '\s+','-' -replace '[^a-zA-Z0-9_-]',''
$policyName = "WCF-$policyNameClean-Audited-Block"

$policyEntry = @{
    PolicyName       = $policyName
    PolicyType       = "WebContentFiltering"
    PolicyAction     = "Block"
    Description      = "Converted from MDE WCF policy: $($policy.PolicyName) (audited categories — originally monitor-only)"
    RuleType         = "webCategory"
    RuleDestinations = $mappedCategories -join ";"
    RuleName         = "AuditedCategories"
    ReviewNeeded     = "Yes"
    ReviewDetails    = $reviewReasons -join "; "
    Provision        = "no"
}

$allPolicies += $policyEntry
# Route $policyName to Default or Override scope (see 2.5)
```

#### 2.5 Scope Routing for WCF Policies

```powershell
function Resolve-ScopeKey {
    param(
        [Parameter(Mandatory)]
        $RbacGroupNames
    )

    # "All device groups" or single-element string array containing it → default scope
    if ($RbacGroupNames -eq "All device groups" -or
        ($RbacGroupNames -is [array] -and $RbacGroupNames.Count -eq 1 -and $RbacGroupNames[0] -eq "All device groups")) {
        return "DEFAULT"
    }

    # Specific device groups — sort for consistent key
    $groupNames = @($RbacGroupNames) | Sort-Object
    return ($groupNames -join ";")
}

# Route policy name to scope
$scopeKey = Resolve-ScopeKey -RbacGroupNames $policy.RbacGroupNames

if ($scopeKey -eq "DEFAULT") {
    $defaultScopePolicies += $policyName
}
else {
    if (-not $scopedPolicyBuckets.ContainsKey($scopeKey)) {
        $groupNames = @($policy.RbacGroupNames) | Sort-Object

        # Resolve Entra groups from device group assignments
        $entraGroups = @()
        foreach ($gName in $groupNames) {
            if ($deviceGroupEntraMap.ContainsKey($gName)) {
                $entraGroups += $deviceGroupEntraMap[$gName]
            }
            else {
                $entraGroups += "_Replace_Me"
            }
        }

        $scopedPolicyBuckets[$scopeKey] = @{
            DeviceGroupNames = $groupNames
            EntraGroups      = $entraGroups | Select-Object -Unique
            Policies         = @()
        }
    }
    $scopedPolicyBuckets[$scopeKey].Policies += $policyName
}
```

### Phase 3: IP Indicator Logging (Skip — Not Supported)

> **Conditional:** This phase is only executed when `IpIndicatorsPath` is provided.

EIA does not support IP addresses as policy destinations. This phase reads the IP indicators file, logs each indicator as a warning, and records the total count for the conversion summary. No EIA policies are created.

```powershell
$ipIndicators = @($rawIpIndicators)

if ($ipIndicators.Count -gt 0) {
    Write-LogMessage "Found $($ipIndicators.Count) IP indicator(s) — these cannot be converted (EIA does not support IP address destinations)" -Level WARN

    foreach ($indicator in $ipIndicators) {
        $stats.IpIndicatorsSkipped++
        $enabledLabel = if ($indicator.isEnabled) { "enabled" } else { "disabled" }
        Write-LogMessage "  IP indicator '$($indicator.title)' ($($indicator.indicatorValue), action: $($indicator.action), $enabledLabel) — skipped: EIA does not support IP address destinations" -Level WARN
    }

    Write-LogMessage "ACTION REQUIRED: Review the $($ipIndicators.Count) skipped IP indicator(s) above and consider manually creating equivalent FQDN-based rules or alternative controls in EIA" -Level WARN
}
else {
    Write-LogMessage "No IP indicators found — nothing to skip" -Level INFO
}
```

### Phase 4: URL/Domain Indicator Processing

> **Conditional:** This phase is only executed when `UrlIndicatorsPath` is provided.

#### 4.1 Filter and Group URL/Domain Indicators

```powershell
$urlIndicators = @($rawUrlIndicators)

# Group structure: (mappedAction × scopeKey) → list of FQDN entries + review info
$fqdnGroups = @{}

foreach ($indicator in $urlIndicators) {
    # Skip disabled
    if (-not $indicator.isEnabled) {
        $stats.UrlIndicatorsSkippedDisabled++
        Write-LogMessage "URL indicator '$($indicator.title)' (ID: $($indicator.indicatorId)) is disabled — skipping" -Level DEBUG
        continue
    }

    # Skip expired
    if ($indicator.expirationTime) {
        $expiry = [datetime]::Parse($indicator.expirationTime)
        if ($expiry -lt (Get-Date)) {
            $stats.UrlIndicatorsSkippedExpired++
            Write-LogMessage "URL indicator '$($indicator.title)' (ID: $($indicator.indicatorId)) expired at $($indicator.expirationTime) — skipping" -Level INFO
            continue
        }
    }

    # Map action
    $mappedAction = switch ($indicator.action) {
        "Block"     { "Block" }
        "Allow"     { "Allow" }
        "Warn"      { "Block" }
        "AlertOnly" { "Allow" }
    }
    $hasReview = $indicator.action -in @("Warn", "AlertOnly")
    $reviewDetail = switch ($indicator.action) {
        "Warn"      { "Original MDE action was 'Warn' (user bypass allowed) — converted to Block" }
        "AlertOnly" { "Original MDE action was 'AlertOnly' (monitor only, no enforcement) — converted to Allow" }
        default     { "" }
    }

    if ($indicator.action -eq "Warn") { $stats.IndicatorsWarn++ }
    if ($indicator.action -eq "AlertOnly") { $stats.IndicatorsAlertOnly++ }

    # Build FQDN entries
    $value = $indicator.indicatorValue
    $fqdnEntries = @()
    if ($value -match '/') {
        # Contains path — treat as URL, use as-is
        $fqdnEntries += $value
    }
    else {
        # Domain — apply dual FQDN pattern
        $fqdnEntries += $value
        $fqdnEntries += "*.$value"
    }

    # Determine scope
    $scopeKey = Resolve-ScopeKey -RbacGroupNames $indicator.rbacGroupNames

    # Group key
    $groupKey = "${mappedAction}|${scopeKey}"

    if (-not $fqdnGroups.ContainsKey($groupKey)) {
        $fqdnGroups[$groupKey] = @{
            Action        = $mappedAction
            ScopeKey      = $scopeKey
            FqdnEntries   = @()
            ReviewReasons = @()
            HasReview     = $false
        }
    }

    $fqdnGroups[$groupKey].FqdnEntries += $fqdnEntries
    if ($hasReview) {
        $fqdnGroups[$groupKey].HasReview = $true
        $fqdnGroups[$groupKey].ReviewReasons += "$reviewDetail (indicator: $($indicator.title))"
    }

    $stats.UrlIndicatorsProcessed++
    Write-LogMessage "URL indicator '$($indicator.title)': $value → $mappedAction (scope: $scopeKey)" -Level DEBUG
}
```

#### 4.2 Create Policies from URL/Domain Indicator Groups

```powershell
foreach ($groupKey in $fqdnGroups.Keys) {
    $group = $fqdnGroups[$groupKey]
    $action = $group.Action
    $scopeKey = $group.ScopeKey

    # Build policy name
    if ($scopeKey -eq "DEFAULT") {
        $policyName = "Indicators-FQDN-$action"
    }
    else {
        $scopeLabel = ($scopeKey -split ";")[0] -replace '\s+','-' -replace '[^a-zA-Z0-9_-]',''
        $policyName = "Indicators-FQDN-$scopeLabel-$action"
    }

    $uniqueReviewReasons = $group.ReviewReasons | Select-Object -Unique

    # Split by character limit
    $groups = Split-ByCharacterLimit -Entries $group.FqdnEntries -MaxLength 300

    for ($i = 0; $i -lt $groups.Count; $i++) {
        $ruleName = if ($i -eq 0) { "FQDNs" } else { "FQDNs-$($i + 1)" }

        $policyEntry = @{
            PolicyName       = $policyName
            PolicyType       = "WebContentFiltering"
            PolicyAction     = $action
            Description      = "Converted from MDE URL/Domain indicators ($action)"
            RuleType         = "FQDN"
            RuleDestinations = $groups[$i] -join ";"
            RuleName         = $ruleName
            ReviewNeeded     = if ($group.HasReview) { "Yes" } else { "No" }
            ReviewDetails    = $uniqueReviewReasons -join "; "
            Provision        = if ($group.HasReview) { "no" } else { "yes" }
        }

        $allPolicies += $policyEntry
    }

    # Route to scope
    if ($scopeKey -eq "DEFAULT") {
        $defaultScopePolicies += $policyName
    }
    else {
        Add-ToScopeBucket -ScopeKey $scopeKey -PolicyName $policyName -RbacGroupNames ($scopeKey -split ";")
    }
}
```

### Phase 5: Security Profile Assembly

#### 5.1 Create Default Security Profile

```powershell
$uniqueDefaultPolicies = $defaultScopePolicies | Select-Object -Unique

if ($uniqueDefaultPolicies.Count -gt 0) {
    # Build SecurityProfileLinks with priority numbering
    $linkPriority = 100
    $profileLinks = @()
    foreach ($policyName in $uniqueDefaultPolicies) {
        $profileLinks += "${policyName}:${linkPriority}"
        $linkPriority += 100
    }

    $defaultProfile = @{
        SecurityProfileName  = "Default-MDE"
        Priority             = 50000
        SecurityProfileLinks = $profileLinks -join ";"
        CADisplayName        = "CA-EIA-Default-MDE"
        EntraUsers           = ""
        EntraGroups          = "All Internet Access Users"
        Provision            = "yes"
    }

    $securityProfiles += $defaultProfile
    $stats.SecurityProfilesCreated++
}
```

#### 5.2 Create Override Security Profiles

```powershell
$overridePriority = 1000

foreach ($scopeKey in $scopedPolicyBuckets.Keys) {
    $scopeData = $scopedPolicyBuckets[$scopeKey]

    $uniquePolicies = $scopeData.Policies | Select-Object -Unique

    # Build SecurityProfileLinks
    $linkPriority = 100
    $profileLinks = @()
    foreach ($policyName in $uniquePolicies) {
        $profileLinks += "${policyName}:${linkPriority}"
        $linkPriority += 100
    }

    # Generate profile name from device group names (truncate if needed)
    $groupLabel = ($scopeData.DeviceGroupNames | Select-Object -First 2) -join "-"
    $groupLabel = $groupLabel -replace '\s+','-' -replace '[^a-zA-Z0-9_-]',''
    $profileName = "Override-$groupLabel"

    $overrideProfile = @{
        SecurityProfileName  = $profileName
        Priority             = $overridePriority
        SecurityProfileLinks = $profileLinks -join ";"
        CADisplayName        = "CA-EIA-$profileName"
        EntraUsers           = ""
        EntraGroups          = $scopeData.EntraGroups -join ";"
        Provision            = "yes"
    }

    $securityProfiles += $overrideProfile
    $overridePriority += 100
    $stats.SecurityProfilesCreated++
}
```

### Phase 6: Export and Summary

#### 6.1 Export Policies CSV
```powershell
$allPolicies | Export-Csv -Path $policiesCsvPath -NoTypeInformation
Write-LogMessage "Exported $($allPolicies.Count) policy rows to: $policiesCsvPath" -Level INFO
```

#### 6.2 Export Security Profiles CSV
```powershell
$securityProfiles | Export-Csv -Path $spCsvPath -NoTypeInformation
Write-LogMessage "Exported $($securityProfiles.Count) security profiles to: $spCsvPath" -Level INFO
```

#### 6.3 Generate Summary Statistics

Log the following at INFO level:

```
=== CONVERSION SUMMARY ===
WCF policies processed: X
WCF policies skipped by filter: Y

Categories mapped: A
Categories unmapped: B

IP indicators skipped (not supported): C

URL/Domain indicators processed: G
URL/Domain indicators skipped (disabled): H
URL/Domain indicators skipped (expired): I

URL/Domain indicators with Warn action (→ Block + review): J
URL/Domain indicators with AlertOnly action (→ Allow + review): K

Policies created: L
  - webCategory policies: L1
  - FQDN policies: L2

Security profiles created: M
  - Default: 0 or 1
  - Overrides: M-1

Output files:
  - Policies: [path]
  - Security Profiles: [path]
  - Log File: [path]
```

---

## Function Interface

### Parameters

| Parameter | Type | Default | Description | Validation |
|-----------|------|---------|-------------|------------|
| WcfPoliciesPath | string | `$null` | Path to WCF policies JSON file | ValidateScript — file must exist if provided. At least one of WcfPoliciesPath or UrlIndicatorsPath must be provided (validated at runtime) |
| IpIndicatorsPath | string | `$null` | Path to IP indicators JSON file. Not converted — used only for skip-and-log reporting | ValidateScript — file must exist if provided |
| UrlIndicatorsPath | string | `$null` | Path to URL/Domain indicators JSON file | ValidateScript — file must exist if provided |
| DeviceGroupsPath | string | `$null` | Path to device groups JSON file | ValidateScript — file must exist if provided. Optional — used for Entra group name resolution in override profiles |
| OutputBasePath | string | `$PWD` | Output directory for CSV and log files | ValidateScript — directory must exist |
| IncludePolicyName | string[] | `$null` | WCF policy name patterns to include. Supports wildcards via `-like`. Case-insensitive. When specified, only WCF policies matching at least one pattern are processed | None |
| ExcludePolicyName | string[] | `$null` | WCF policy name patterns to exclude. Supports wildcards via `-like`. Case-insensitive. Exclude wins over include when both match | None |
| EnableDebugLogging | switch | `false` | Enable DEBUG level logging | None |

### Parameter Definitions

```powershell
[CmdletBinding(SupportsShouldProcess = $false)]
param(
    [Parameter(HelpMessage = "Path to MDE WCF Policies JSON file exported by Export-MDEWebFilteringConfig. At least one of WcfPoliciesPath or UrlIndicatorsPath must be provided.")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$WcfPoliciesPath,

    [Parameter(HelpMessage = "Path to MDE IP Indicators JSON file exported by Export-MDEWebFilteringConfig. Not converted — used only for skip-and-log reporting.")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$IpIndicatorsPath,

    [Parameter(HelpMessage = "Path to MDE URL/Domain Indicators JSON file exported by Export-MDEWebFilteringConfig.")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$UrlIndicatorsPath,

    [Parameter(HelpMessage = "Path to MDE Device Groups JSON file exported by Export-MDEWebFilteringConfig. Optional — used for Entra group name resolution.")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$DeviceGroupsPath,

    [Parameter(HelpMessage = "Base directory for output files")]
    [ValidateScript({
        if (Test-Path $_ -PathType Container) { return $true }
        else { throw "Directory not found: $_" }
    })]
    [string]$OutputBasePath = $PWD,

    [Parameter(HelpMessage = "WCF policy name patterns to include. Supports wildcards. Case-insensitive.")]
    [string[]]$IncludePolicyName,

    [Parameter(HelpMessage = "WCF policy name patterns to exclude. Supports wildcards. Case-insensitive. Exclude wins over include.")]
    [string[]]$ExcludePolicyName,

    [Parameter(HelpMessage = "Enable verbose debug logging")]
    [switch]$EnableDebugLogging
)
```

---

## Internal Helper Functions

### Functions to Reuse (Existing)

| Function | Source | Purpose |
|----------|--------|---------|
| `Write-LogMessage` | Common internal | Logging with levels (INFO, WARN, DEBUG, ERROR) |
| `Split-ByCharacterLimit` | Common internal | Split destination arrays by 300-char limit |
| `Export-DataToFile` | Common internal | Export data to CSV with UTF-8 BOM encoding |
| `Test-PolicyNameFilter` | Common internal | Test policy name against include/exclude patterns |

### Functions to Create (New)

#### 1. Resolve-ScopeKey
**Purpose:** Determine whether a policy/indicator targets all device groups (default scope) or specific groups (override scope).

**Parameters:**
- `RbacGroupNames` (object, mandatory) — string `"All device groups"` or string array of group names

**Returns:** String — `"DEFAULT"` or semicolon-joined sorted group names

```powershell
function Resolve-ScopeKey {
    param(
        [Parameter(Mandatory)]
        $RbacGroupNames
    )

    if ($RbacGroupNames -eq "All device groups" -or
        ($RbacGroupNames -is [array] -and $RbacGroupNames.Count -eq 1 -and $RbacGroupNames[0] -eq "All device groups")) {
        return "DEFAULT"
    }

    $groupNames = @($RbacGroupNames) | Sort-Object
    return ($groupNames -join ";")
}
```

#### 2. Resolve-MdeCategory
**Purpose:** Map an MDE web category display name to the corresponding EIA PascalCase identifier using the hardcoded mapping table.

**Parameters:**
- `CategoryName` (string, mandatory) — MDE category display name

**Returns:** Hashtable with `EIACategory` (string) and `IsMapped` (bool)

#### 3. Add-ToScopeBucket
**Purpose:** Add a policy name to the appropriate scoped policy bucket, creating the bucket if it doesn't exist.

**Parameters:**
- `ScopeKey` (string, mandatory) — scope key from `Resolve-ScopeKey`
- `PolicyName` (string, mandatory) — policy name to add
- `RbacGroupNames` (string[], mandatory) — device group names for Entra group resolution

---

## Sample Conversion Walkthrough

Given the sample data from `Export-MDEWebFilteringConfig`:

### Input

**wcf_policies.json**: 2 policies (`MDE-Policy1`, `MDE-Policy2`), both scoped to "All device groups"
**ip_indicators.json**: 1 indicator (`20.20.20.20`, AlertOnly, all groups) — **skipped (not supported)**
**url_indicators.json**: 1 indicator (`facebook.com`, Warn, all groups)

### Expected Output — Policies CSV

| PolicyName | PolicyType | PolicyAction | RuleType | RuleDestinations | RuleName | ReviewNeeded | ReviewDetails | Provision |
|---|---|---|---|---|---|---|---|---|
| WCF-MDE-Policy1-Blocked-Block | WebContentFiltering | Block | webCategory | Gambling | BlockedCategories | No | | yes |
| WCF-MDE-Policy1-Audited-Block | WebContentFiltering | Block | webCategory | ChildAbuseImages;CriminalActivity;Hacking;HateAndIntolerance;IllegalDrug;IllegalSoftware;Cheating;SelfHarm;Weapons;Cults;Nudity;PornographyAndSexuallyExplicit;SexEducation;Tasteless;Violence;DownloadSites;ImageSharing;PeerToPeer;StreamingMediaAndDownloads;Chat;Games;InstantMessaging;ProfessionalNetworking;WebBasedEmail;SocialNetworking;ParkedDomains;NewlyRegisteredDomains | AuditedCategories | Yes | Original MDE action was 'Audit' (monitor only, no enforcement) — converted to Block | no |
| WCF-MDE-Policy2-Blocked-Block | WebContentFiltering | Block | webCategory | Cults;DownloadSites;ChildAbuseImages;Chat;ParkedDomains | BlockedCategories | No | | yes |
| WCF-MDE-Policy2-Audited-Block | WebContentFiltering | Block | webCategory | CriminalActivity;Hacking;HateAndIntolerance;IllegalDrug;IllegalSoftware;Cheating;SelfHarm;Weapons;Gambling;Nudity;PornographyAndSexuallyExplicit;SexEducation;Tasteless;Violence;ImageSharing;PeerToPeer;StreamingMediaAndDownloads;Games;InstantMessaging;ProfessionalNetworking;WebBasedEmail;SocialNetworking;NewlyRegisteredDomains | AuditedCategories | Yes | Original MDE action was 'Audit' (monitor only, no enforcement) — converted to Block | no |
| Indicators-FQDN-Block | WebContentFiltering | Block | FQDN | facebook.com;*.facebook.com | FQDNs | Yes | Original MDE action was 'Warn' (user bypass allowed) — converted to Block (indicator: Facebook) | no |

> **Note:** The IP indicator `20.20.20.20` (AlertOnly) is logged as a warning but does **not** appear in the Policies CSV because EIA does not support IP address destinations.

### Expected Output — Security Profiles CSV

| SecurityProfileName | Priority | SecurityProfileLinks | CADisplayName | EntraUsers | EntraGroups | Provision |
|---|---|---|---|---|---|---|
| Default-MDE | 50000 | WCF-MDE-Policy1-Blocked-Block:100;WCF-MDE-Policy1-Audited-Block:200;WCF-MDE-Policy2-Blocked-Block:300;WCF-MDE-Policy2-Audited-Block:400;Indicators-FQDN-Block:500 | CA-EIA-Default-MDE | | All Internet Access Users | yes |
