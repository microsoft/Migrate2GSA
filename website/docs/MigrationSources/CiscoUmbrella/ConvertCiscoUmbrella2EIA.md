---
sidebar_position: 2
title: Cisco Umbrella to Entra Internet Access (EIA) Configuration Transformer
---

## Overview

`Convert-CiscoUmbrella2EIA` converts Cisco Umbrella DNS and web policy configuration to Microsoft Entra Internet Access (EIA) format. It processes DNS policies, web policies (proxy rulesets), destination lists, category settings, and application mappings to generate CSV files compatible with `Start-EntraInternetAccessProvisioning`.

The function supports processing DNS policies only, web policies only, or both together. It handles category mapping, application-to-FQDN conversion, identity-scoped security profiles, and automatic policy deduplication/merging.

## Prerequisites

- PowerShell 7.0 or higher
- `Migrate2GSA` PowerShell module installed
- Exported Umbrella configuration from `Export-CiscoUmbrellaConfig`
- Category and app mapping CSV files
- Write access to output directory

### Required Input Files

| File | Source | Required When |
|------|--------|---------------|
| `dns_policies.json` | `Export-CiscoUmbrellaConfig` | DNS mode |
| `web_policies.json` | `Export-CiscoUmbrellaConfig` | Web mode |
| `destination_lists.json` | `Export-CiscoUmbrellaConfig` | Always |
| `category_settings.json` | `Export-CiscoUmbrellaConfig` | DNS mode |
| `CiscoUmbrella2EIA-CategoryMappings.csv` | Provided in `Samples/CiscoUmbrella/` | Always |
| `CiscoUmbrella2EIA-AppMappings.csv` | Provided in `Samples/CiscoUmbrella/` | Web mode |

## Syntax

```powershell
Convert-CiscoUmbrella2EIA
    [-DnsPoliciesPath <String>]
    [-WebPoliciesPath <String>]
    [-DestinationListsPath <String>]
    [-CategorySettingsPath <String>]
    [-CategoryMappingsPath <String>]
    [-AppMappingsPath <String>]
    [-OutputBasePath <String>]
    [-IncludePolicyName <String[]>]
    [-ExcludePolicyName <String[]>]
    [-EnableDebugLogging]
    [<CommonParameters>]
```

At least one of `-DnsPoliciesPath` or `-WebPoliciesPath` must be provided.

## Parameters

### -DnsPoliciesPath

Path to Cisco Umbrella DNS Policies JSON export.

- **Type**: String
- **Required**: No (but at least one of DnsPoliciesPath or WebPoliciesPath is required)
- **Validation**: File must exist

### -WebPoliciesPath

Path to Cisco Umbrella Web Policies JSON export.

- **Type**: String
- **Required**: No (but at least one of DnsPoliciesPath or WebPoliciesPath is required)
- **Validation**: File must exist

### -DestinationListsPath

Path to Cisco Umbrella Destination Lists JSON export.

- **Type**: String
- **Default**: `destination_lists.json` in current directory
- **Validation**: File must exist

### -CategorySettingsPath

Path to Cisco Umbrella Category Settings JSON export. Required when DnsPoliciesPath is provided.

- **Type**: String
- **Default**: `category_settings.json` in current directory
- **Validation**: File must exist

### -CategoryMappingsPath

Path to Umbrella-to-EIA category mappings CSV. Maps Umbrella content categories to GSA web categories. A sample mapping file is provided in `Samples/CiscoUmbrella/`.

- **Type**: String
- **Default**: `CiscoUmbrella2EIA-CategoryMappings.csv` in current directory
- **Validation**: File must exist

### -AppMappingsPath

Path to Umbrella-to-EIA application mappings CSV. Maps Umbrella application IDs to FQDN endpoints. Required when WebPoliciesPath is provided. A sample mapping file is provided in `Samples/CiscoUmbrella/`.

The CSV must contain columns: `UmbrellaAppId`, `UmbrellaAppName`, `GSAAppName`, `MatchType`, `GSAEndpoints`.

- **Type**: String
- **Default**: `CiscoUmbrella2EIA-AppMappings.csv` in current directory
- **Validation**: File must exist

### -OutputBasePath

Base directory for output CSV and log files.

- **Type**: String
- **Default**: Current working directory
- **Validation**: Directory must exist

### -IncludePolicyName

One or more policy name patterns to include. Supports wildcards (e.g., `*Finance*`, `Corp-*`). Case-insensitive. When specified, only matching DNS/web policies are processed.

- **Type**: String[]
- **Required**: No

### -ExcludePolicyName

One or more policy name patterns to exclude. Supports wildcards. Case-insensitive. Exclude takes precedence over include.

- **Type**: String[]
- **Required**: No

### -EnableDebugLogging

Enable verbose debug logging for detailed processing information.

- **Type**: Switch
- **Default**: False

## Examples

### Example 1: Convert Both DNS and Web Policies

```powershell
Convert-CiscoUmbrella2EIA `
    -DnsPoliciesPath ".\dns_policies.json" `
    -WebPoliciesPath ".\web_policies.json"
```

### Example 2: Convert DNS Policies Only

```powershell
Convert-CiscoUmbrella2EIA -DnsPoliciesPath ".\dns_policies.json"
```

### Example 3: Convert Web Policies with Custom Output

```powershell
Convert-CiscoUmbrella2EIA `
    -WebPoliciesPath ".\web_policies.json" `
    -OutputBasePath "C:\Output" `
    -EnableDebugLogging
```

### Example 4: Filter Policies by Name

```powershell
# Include only specific policies
Convert-CiscoUmbrella2EIA `
    -DnsPoliciesPath ".\dns_policies.json" `
    -IncludePolicyName "Corp-*","*Finance*"

# Exclude test/dev policies (exclude wins over include)
Convert-CiscoUmbrella2EIA `
    -DnsPoliciesPath ".\dns_policies.json" `
    -WebPoliciesPath ".\web_policies.json" `
    -IncludePolicyName "Corp-*" `
    -ExcludePolicyName "Corp-Staging*"
```

### Example 5: End-to-End Pipeline

```powershell
# Step 1: Export from Umbrella (HAR-based)
Export-CiscoUmbrellaConfig -HARFilePath ".\umbrella_dashboard.har"

# Step 2: Convert to EIA format
Convert-CiscoUmbrella2EIA `
    -DnsPoliciesPath ".\dns_policies.json" `
    -WebPoliciesPath ".\web_policies.json"

# Step 3: Review CSVs, then provision
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\*_EIA_Policies.csv" `
    -SecurityProfilesCsvPath ".\*_EIA_SecurityProfiles.csv"
```

## Output Files

All output files are created with a timestamp prefix (`yyyyMMdd_HHmmss`):

```
20260306_143022_EIA_Policies.csv
20260306_143022_EIA_SecurityProfiles.csv
20260306_143022_Convert-CiscoUmbrella2EIA.log
```

### Policies CSV

| Column | Description |
|--------|-------------|
| `PolicyName` | Unique policy name (e.g., `DNS-MyPolicy-Categories-Block`) |
| `PolicyType` | Always `WebContentFiltering` |
| `PolicyAction` | `Block` or `Allow` |
| `Description` | Source policy/rule reference |
| `RuleType` | `FQDN` or `webCategory` |
| `RuleDestinations` | Semicolon-separated destinations or categories |
| `RuleName` | Rule identifier (e.g., `WebCategories`, `FQDNs`, base domain) |
| `ReviewNeeded` | `Yes` if unmapped items or action conversion occurred |
| `ReviewDetails` | Explanation of review flags |
| `Provision` | `yes` or `no` |

### Security Profiles CSV

| Column | Description |
|--------|-------------|
| `SecurityProfileName` | Profile name (e.g., `Default-CiscoUmbrella`, `Override-FinanceGroup`) |
| `Priority` | Numeric priority (1000+ for overrides, 50000 for default) |
| `SecurityProfileLinks` | Policy references with priorities (e.g., `PolicyName:100;PolicyName2:200`) |
| `CADisplayName` | Conditional Access policy display name |
| `EntraUsers` | Semicolon-separated user UPNs |
| `EntraGroups` | Semicolon-separated group names |
| `Provision` | `yes` or `no` |

## Conversion Process

### Phase 1: Data Loading
Loads all input JSON and CSV files, validates schemas, and builds lookup tables for destination lists, category settings, category mappings, and app mappings.

### Phase 2: DNS Policy Processing
For each DNS policy:
- Maps blocked categories to GSA web categories using the category mappings CSV
- Resolves destination lists to FQDN rules with dual-entry pattern (`domain.com` + `*.domain.com`)
- Splits FQDN rules at 300-character limit
- Routes all policies to the Default scope (DNS policies lack identity assignments)

### Phase 3: Web Policy Processing
For each enabled web policy rule:
- Converts application-based conditions to FQDN policies using the app mappings CSV
- Resolves destination list conditions to FQDN policies
- Maps content category conditions to GSA web categories
- Routes policies to Default or Override scope based on identity assignments (AD groups, AD users)
- Converts `warn` and `isolate` actions to `Block` with review flags

### Phase 4: Deduplication and Merging
Merges policies within each scope (Default and per-identity-set overrides) by rule type and action:
- WebCategory policies are merged by combining unique categories
- FQDN policies are merged and re-grouped by base domain

### Phase 5: Security Profile Assembly
- Creates a **Default** security profile (priority 50000) for all-user policies
- Creates **Override** security profiles (priority 1000+) for identity-scoped policies with group/user assignments

### Phase 6: Export
Exports policies and security profiles to timestamped CSV files with UTF-8 BOM encoding.

## Action Mapping

| Umbrella Action | EIA Action | Review Flag |
|------------------|------------|-------------|
| `block` | Block | No |
| `allow` | Allow | No |
| `warn` | Block | Yes — "Original action was 'warn' (user click-through)" |
| `isolate` | Block | Yes — "Original action was 'isolate' (remote browser isolation)" |

## Category and Application Mapping

### Category Mappings CSV Format

```csv
UmbrellaCategory,GSACategory
Gambling,Gambling
Social Networking,SocialNetworking
```

Unmapped categories (missing from file or empty GSACategory) are output with `UNMAPPED:CategoryName` placeholder, `ReviewNeeded=Yes`, and `Provision=no`.

### App Mappings CSV Format

```csv
UmbrellaAppId,UmbrellaAppName,GSAAppName,MatchType,GSAEndpoints
12345,Slack,Slack,Exact,slack.com;*.slack.com
```

Applications without endpoints in the mapping file are flagged for review.

## Known Limitations

- **DNS policy identity assignment**: Not available in Umbrella export — all DNS policies are treated as applying to all users
- **Warn/Isolate actions**: Converted to Block with review flag (no equivalent in EIA)
- **Application controls**: Converted to FQDN-based rules using the app mappings CSV
- **Security/file inspection settings**: Logged as warnings — must be configured separately in EIA (Threat Intelligence, TLS Inspection policies)
- **Selective Decryption**: Not converted — TLS Inspection policies must be configured separately in EIA

## Next Steps

After conversion:

1. **Review CSVs** — Check `ReviewNeeded=Yes` rows for unmapped categories, unmapped apps, or converted warn/isolate actions
2. **Update placeholders** — Replace `UNMAPPED:*` entries or remove them
3. **Verify group names** — Ensure `EntraGroups` values match actual Entra group names
4. **Provision to EIA** — Use `Start-EntraInternetAccessProvisioning` to deploy
