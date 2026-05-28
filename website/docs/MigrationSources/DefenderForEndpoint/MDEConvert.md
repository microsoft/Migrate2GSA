---
sidebar_position: 2
title: Convert MDE to EIA
description: Convert Microsoft Defender for Endpoint web filtering configuration to Entra Internet Access format for provisioning.
keywords: [Microsoft Defender for Endpoint, MDE, Entra Internet Access, EIA, convert, migration, web content filtering, URL indicators, Global Secure Access]
---

## Overview

`Convert-MDE2EIA` transforms Microsoft Defender for Endpoint (MDE) web filtering configuration — previously exported by `Export-MDEWebFilteringConfig` — into Entra Internet Access (EIA) CSV files ready for provisioning via `Start-EntraInternetAccessProvisioning`.

The conversion handles three categories of MDE objects:

| MDE Source Object | EIA Output | Notes |
|-------------------|------------|-------|
| WCF Policies (blocked categories) | Web category filtering policies (Block) | Hardcoded category mapping |
| WCF Policies (audited categories) | Web category filtering policies (Block + review) | No audit-only equivalent in EIA |
| URL/Domain Indicators | FQDN and URL filtering rules | Grouped by action and scope |
| IP Indicators | Not converted | Logged with skip reason |

### Conversion Highlights

- **Category Mapping**: MDE web category names are mapped to EIA PascalCase identifiers using a built-in mapping table (28 supported categories)
- **Dual FQDN Expansion**: Domain indicators (e.g., `facebook.com`) are expanded to both `facebook.com` and `*.facebook.com` for complete coverage
- **URL Preservation**: URL indicators containing a path or scheme (e.g., `https://www.bmw.com`) are preserved as-is with rule type `URL`
- **Action Translation**: MDE `Warn` → EIA `Block` (flagged for review); MDE `AlertOnly` → EIA `Allow` (flagged for review)
- **Scope-Aware Profiles**: Device group scoping is translated to security profiles with Entra group assignments
- **Review Workflow**: Policies requiring manual review are marked with `ReviewNeeded = Yes` and `Provision = no`

---

## Prerequisites

- PowerShell 7.0 or higher
- `Migrate2GSA` module installed
- MDE configuration exported via `Export-MDEWebFilteringConfig` (at minimum, one of `wcf_policies.json` or `url_indicators.json`)

---

## Syntax

```powershell
Convert-MDE2EIA
    [-WcfPoliciesPath <String>]
    [-IpIndicatorsPath <String>]
    [-UrlIndicatorsPath <String>]
    [-DeviceGroupsPath <String>]
    [-OutputBasePath <String>]
    [-IncludePolicyName <String[]>]
    [-ExcludePolicyName <String[]>]
    [-EnableDebugLogging]
    [<CommonParameters>]
```

---

## Parameters

### -WcfPoliciesPath

Path to the MDE Web Content Filtering policies JSON file exported by `Export-MDEWebFilteringConfig`.

- **Type**: String
- **Required**: No (but at least one of `-WcfPoliciesPath` or `-UrlIndicatorsPath` must be provided)
- **Validation**: File must exist

### -IpIndicatorsPath

Path to the MDE IP indicators JSON file. IP indicators are **not converted** — they are logged with a skip reason because EIA does not support IP address destinations.

- **Type**: String
- **Required**: No
- **Validation**: File must exist

### -UrlIndicatorsPath

Path to the MDE URL/Domain indicators JSON file exported by `Export-MDEWebFilteringConfig`.

- **Type**: String
- **Required**: No (but at least one of `-WcfPoliciesPath` or `-UrlIndicatorsPath` must be provided)
- **Validation**: File must exist

### -DeviceGroupsPath

Path to the MDE device groups JSON file. Used to resolve device group names to Entra ID group assignments for override security profiles.

- **Type**: String
- **Required**: No
- **Validation**: File must exist

### -OutputBasePath

Base directory where output CSV files and the log file are written.

- **Type**: String
- **Required**: No
- **Default value**: Current directory
- **Validation**: Directory must exist

### -IncludePolicyName

One or more WCF policy name patterns to include. Supports wildcards via `-like`. Case-insensitive. When specified, only WCF policies matching at least one pattern are processed.

- **Type**: String[]
- **Required**: No
- **Applies to**: WCF policies only (URL/Domain indicators are not filtered)

### -ExcludePolicyName

One or more WCF policy name patterns to exclude. Supports wildcards via `-like`. Case-insensitive. Exclude wins over include when both match the same policy.

- **Type**: String[]
- **Required**: No
- **Applies to**: WCF policies only

### -EnableDebugLogging

Enables verbose debug-level logging for detailed processing information in the log file.

- **Type**: Switch
- **Required**: No
- **Default value**: `$false`

---

## Examples

### Example 1: Convert URL/Domain Indicators Only

```powershell
Import-Module Migrate2GSA

Convert-MDE2EIA -UrlIndicatorsPath "C:\MDE-backup\url_indicators.json"
```

Converts URL and domain indicators to EIA FQDN/URL filtering rules.

### Example 2: Convert All Exported Configuration

```powershell
Convert-MDE2EIA `
    -WcfPoliciesPath "C:\MDE-backup\wcf_policies.json" `
    -IpIndicatorsPath "C:\MDE-backup\ip_indicators.json" `
    -UrlIndicatorsPath "C:\MDE-backup\url_indicators.json" `
    -DeviceGroupsPath "C:\MDE-backup\device_groups.json" `
    -OutputBasePath "C:\Migration\EIA-Output"
```

Processes WCF policies, URL/Domain indicators, and resolves device group scoping. IP indicators are logged but not converted.

### Example 3: Filter WCF Policies by Name

```powershell
Convert-MDE2EIA `
    -WcfPoliciesPath "C:\MDE-backup\wcf_policies.json" `
    -IncludePolicyName "Production*", "Critical*" `
    -ExcludePolicyName "*Test*" `
    -EnableDebugLogging
```

Processes only WCF policies matching "Production\*" or "Critical\*", excluding any containing "Test". Debug logging is enabled for detailed trace output.

### Example 4: End-to-End Migration Workflow

```powershell
# Step 1: Export from HAR file
Export-MDEWebFilteringConfig -HARFilePath "C:\captures\mde_portal.har" -OutputDirectory "C:\Migration"

# Step 2: Convert to EIA format
$backupFolder = Get-ChildItem "C:\Migration\MDE-backup_*" | Sort-Object Name -Descending | Select-Object -First 1
Convert-MDE2EIA `
    -WcfPoliciesPath (Join-Path $backupFolder "wcf_policies.json") `
    -UrlIndicatorsPath (Join-Path $backupFolder "url_indicators.json") `
    -DeviceGroupsPath (Join-Path $backupFolder "device_groups.json") `
    -OutputBasePath "C:\Migration\EIA-Output"

# Step 3: Review the generated CSV files, then provision
Start-EntraInternetAccessProvisioning `
    -PoliciesCSVPath "C:\Migration\EIA-Output\*_EIA_Policies.csv" `
    -SecurityProfilesCSVPath "C:\Migration\EIA-Output\*_EIA_SecurityProfiles.csv"
```

---

## Output

The function produces two CSV files and a log file in the `-OutputBasePath` directory:

```
{OutputBasePath}/
├── {timestamp}_EIA_Policies.csv
├── {timestamp}_EIA_SecurityProfiles.csv
└── {timestamp}_Convert-MDE2EIA.log
```

### Policies CSV Structure

| Column | Description |
|--------|-------------|
| `PolicyName` | EIA filtering policy name |
| `PolicyType` | Always `WebContentFiltering` |
| `PolicyAction` | `Block` or `Allow` |
| `Description` | Provenance note indicating the MDE source |
| `RuleType` | `webCategory`, `FQDN`, or `URL` |
| `RuleDestinations` | Semicolon-separated list of categories, FQDNs, or URLs |
| `RuleName` | Human-readable rule label |
| `ReviewNeeded` | `Yes` if manual review is required before provisioning |
| `ReviewDetails` | Explanation of why review is needed |
| `Provision` | `yes` or `no` — controls whether the provisioning cmdlet processes this row |

### Security Profiles CSV Structure

| Column | Description |
|--------|-------------|
| `SecurityProfileName` | Profile name (e.g., `Default-MDE`, `Override-GroupName`) |
| `Priority` | Profile priority (lower = higher precedence for overrides) |
| `SecurityProfileLinks` | Semicolon-separated `PolicyName:Priority` pairs |
| `CADisplayName` | Suggested Conditional Access policy display name |
| `EntraUsers` | Target Entra users (empty for group-based targeting) |
| `EntraGroups` | Semicolon-separated Entra group names |
| `Provision` | `yes` or `no` |

---

## Conversion Logic

### WCF Policy Processing

Each MDE Web Content Filtering policy produces one or two EIA policies:

- **Blocked categories** → Policy named `WCF-{PolicyName}-Blocked-Block` with action `Block`
- **Audited categories** → Policy named `WCF-{PolicyName}-Audited-Block` with action `Block`, marked `ReviewNeeded = Yes` (MDE audit is monitor-only, but EIA has no equivalent — converted to Block for review)

Category names are mapped using the built-in translation table:

| MDE Category | EIA Category |
|-------------|--------------|
| Chat | Chat |
| Child Abuse Images | ChildAbuseImages |
| Criminal activity | CriminalActivity |
| Gambling | Gambling |
| Hacking | Hacking |
| Hate & intolerance | HateAndIntolerance |
| Nudity | Nudity |
| Pornography/Sexually explicit | PornographyAndSexuallyExplicit |
| Social networking | SocialNetworking |
| Violence | Violence |
| *(28 categories total)* | |

Unmapped categories are prefixed with `UNMAPPED:` and flagged for review.

### URL/Domain Indicator Processing

Indicators are grouped by action and device group scope into a single policy per group, named `Indicators-URL/Domain-{Action}` (e.g., `Indicators-URL/Domain-Block`). Within each policy:

- **Domain indicators** (no `/` in value): Expanded to dual FQDN entries (`domain.com` + `*.domain.com`) with `RuleType = FQDN`
- **URL indicators** (contain `/` or scheme): Preserved as-is with `RuleType = URL`
- **Disabled indicators**: Skipped
- **Expired indicators**: Skipped

#### Action Mapping

| MDE Action | EIA Action | Review Required |
|-----------|------------|-----------------|
| Block | Block | No |
| Allow | Allow | No |
| Warn | Block | Yes — user bypass not supported in EIA |
| AlertOnly | Allow | Yes — monitor-only, no enforcement in EIA |

### IP Indicator Handling

IP indicators are **not converted**. EIA does not support IP address destinations. Each IP indicator is logged with its title, value, and action so administrators can review and create alternative controls manually.

### Security Profile Assembly

- **Default profile** (`Default-MDE`): Contains all policies scoped to "All device groups", assigned to "All Internet Access Users"
- **Override profiles** (`Override-{GroupName}`): Created for policies scoped to specific device groups, with Entra group assignments resolved from the device groups file

If a device group's Entra group assignment cannot be resolved, `_Replace_Me` is used as a placeholder requiring manual replacement before provisioning.

---

## Troubleshooting

### "At least one of WcfPoliciesPath or UrlIndicatorsPath must be provided"

You must supply at least one convertible input file. Providing only `-IpIndicatorsPath` is not sufficient because IP indicators cannot be converted.

### Unmapped categories appear in output

The function uses a hardcoded mapping of 28 MDE web categories. Categories not in the mapping (e.g., custom MDE categories or newly added ones) are output as `UNMAPPED:{CategoryName}` with `ReviewNeeded = Yes`. Manually update the `RuleDestinations` value in the output CSV with the correct EIA category identifier.

### `_Replace_Me` appears in security profile Entra groups

The device group's Entra ID group assignment could not be resolved. This occurs when:
- The `-DeviceGroupsPath` was not provided
- The device group has no Entra ID group assignments in MDE

Replace `_Replace_Me` with the appropriate Entra ID group name in the Security Profiles CSV before provisioning.

### Policies marked with `Provision = no`

These policies require manual review before deployment. Common reasons:
- MDE action was `Warn` or `AlertOnly` (no direct EIA equivalent)
- MDE audited categories were converted to Block
- Unmapped web categories were detected

Review the `ReviewDetails` column for specific guidance, then set `Provision` to `yes` after confirming the configuration is acceptable.

---

## Logging

All processing details are written to `{timestamp}_Convert-MDE2EIA.log` in the output directory. The log includes:

| Level | Description |
|-------|-------------|
| **INFO** | Progress indicators, file loading, phase completion, statistics |
| **WARN** | Unmapped categories, IP indicators skipped, action translation notes |
| **ERROR** | File load failures, validation errors |
| **DEBUG** | Per-indicator processing details, per-policy creation (requires `-EnableDebugLogging`) |

A conversion summary is appended at the end of the log with counts for all processed, skipped, and created objects.

---

## See Also

- [Export MDE Web Filtering Config](./MDEExport.md) — prerequisite export step
- [EIA CSV Configuration Reference](../../WorkingWithCSVs/eia-csv-configuration.md) — detailed CSV column documentation
- [Migration Workflow](../../migration-workflow.md) — end-to-end 4-phase workflow
- [Start-EntraInternetAccessProvisioning](../../Provision/start-eia-provisioning.md) — provisioning step
