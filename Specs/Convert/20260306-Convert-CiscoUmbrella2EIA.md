# Convert-CiscoUmbrella2EIA.ps1 Specification

## Document Information
- **Specification Version:** 1.0
- **Date:** 2026-03-06
- **Status:** Draft
- **Target Module:** Migrate2GSA
- **Function Name:** Convert-CiscoUmbrella2EIA
- **Author:** Andres Canello
---

## Overview

This PowerShell function converts Cisco Umbrella DNS and Web policy configuration to Microsoft Entra Internet Access (EIA) format. The function processes DNS policies, web policies (including proxy rulesets), destination lists, category settings, and application mappings to generate CSV files ready for import into EIA via `Start-EntraInternetAccessProvisioning`.

### Purpose
- Transform Cisco Umbrella DNS and/or web policies into EIA web content filtering policies
- Support DNS-only, Web-only, or combined DNS+Web conversion (Umbrella can be configured with either or both)
- Convert Umbrella web categories to EIA web categories using a provided mapping file
- Convert Umbrella application-based rules to EIA FQDN-based policies using a provided application mapping CSV file
- Resolve destination lists to FQDN rules with dual-entry pattern (`domain.com;*.domain.com`)
- Generate Security Profiles with a Default profile for broad rules and Override profiles for identity-scoped rules
- Produce import-ready CSV files for EIA configuration

### Design Alignment
This function follows the same architectural patterns as `Convert-ZIA2EIA.ps1`:
- Single function with internal helper functions
- Phased processing approach (Load → Process → Merge/Dedup → Export)
- Comprehensive logging using `Write-LogMessage`
- Region-based code organization
- CSV export using shared utilities

---

## Cisco Umbrella Policy Model

### Two Policy Types

Cisco Umbrella uses two layers of policy enforcement:

1. **DNS Policies** (`bundleTypeId: 1`) — DNS-level filtering that blocks domains before connection. Contains:
   - `categorySetting` — blocked web categories (bitmask-encoded, resolved via `category_settings.json`)
   - `domainlists` — referenced allow/block destination lists
   - `securitySetting` — threat protection toggles (bypass in conversion)
   - `fileInspectionSetting` — file inspection settings (bypass in conversion)
   - `policySetting` — proxy/inspection settings (bypass in conversion)
   - `settingGroupBypassInspectionGroup` — TLS decryption bypass (warn in conversion)
   - No identity details in export (only `identityCount`)

2. **Web Policies** (`bundleTypeId: 2`) — Proxy-level filtering with granular rules. Contains:
   - All the same policy-level settings as DNS policies
   - `proxyRuleset.rules[]` — ordered rules with multi-attribute conditions:
     - `umbrella.source.all_policy_identities` — rule applies to all policy identities
     - `umbrella.source.identity_ids` — rule applies to specific AD users/groups
     - `umbrella.destination.application_ids` — matches specific applications
     - `umbrella.destination.destination_list_ids` — matches destination lists
     - `umbrella.destination.content_category_ids` — matches content categories
   - `proxyRuleset.extradata` — denormalized lookup tables:
     - `identities[]` — resolves identity IDs to AD group/user names (type 3 = AD Groups, type 7 = AD Users)
     - `applications[]` — resolves application IDs to names with descriptions
     - `categories[]` — resolves category IDs to names
     - `destinationLists[]` — resolves destination list IDs to names
   - `restriction` — tenant controls (bypass silently in conversion)

### Supporting Data Files

- **`destination_lists.json`** — Contains destination lists with `access` (allow/block) and `destinations[]` array of domain entries
- **`category_settings.json`** — Contains category setting groups with `categories[]` arrays mapping `categoryId` to `name`. DNS policy `categorySetting.id` cross-references to entries in this file for category name resolution.

### Identity Assignment Model

- **DNS policies**: No identity details in export. Only `identityCount` is present. Treated as applying to all users.
- **Web policies — policy level**: Only `identityCount` present, no identity list. Treated as applying to all users.
- **Web policies — rule level**: Rules with `umbrella.source.identity_ids` target specific AD users/groups, resolved via `extradata.identities[]`. Rules with `umbrella.source.all_policy_identities = true` apply to everyone assigned to the policy.

---

## EIA Target Structure

### Security Profile Architecture

The conversion produces a tiered Security Profile structure:

**Default Security Profile (Priority: 50000)**
- Contains all web content filtering policies converted from:
  - DNS policy category blocks and domain lists (all DNS policies assumed to apply to all users)
  - Web policy rules where `all_policy_identities = true`
- Assigned via Conditional Access policy to `"All Internet Access Users"` (placeholder group name)
- Acts as the baseline — blocks/allows that apply to everyone

**Override Security Profiles (Priority: 1000, 1100, 1200, ...)**
- One per unique identity group combination from web policy rules with `identity_ids` conditions
- Rules targeting the same set of AD groups/users are combined into a single Override Security Profile
- Each override gets its own Conditional Access policy targeting the specific Entra groups (pre-populated from AD group names in `extradata.identities[]`)
- Lower priority number = evaluated first = overrides the default

### Policy Naming Conventions

| Source | EIA PolicyName Format | Example |
|--------|----------------------|---------|
| DNS category blocks | `DNS-[PolicyName]-Categories-Block` | `DNS-DefaultPolicy-Categories-Block` |
| DNS domain list (block) | `DNS-[PolicyName]-[ListName]-Block` | `DNS-DefaultPolicy-GlobalBlockList-Block` |
| DNS domain list (allow) | `DNS-[PolicyName]-[ListName]-Allow` | `DNS-DefaultPolicy-GlobalAllowList-Allow` |
| Web rule (category-based) | `Web-[RuleName]-Categories-[Action]` | `Web-BlockContentCategories-Categories-Block` |
| Web rule (destination-based) | `Web-[RuleName]-Destinations-[Action]` | `Web-BlockDestinationLists-Destinations-Block` |
| Web rule (application-based) | `Web-[RuleName]-Apps-[Action]` | `Web-BlockYandex-Apps-Block` |

### Mapping Summary

| Umbrella Element | Converts To | EIA Element | Notes |
|-----------------|-------------|-------------|-------|
| DNS `categorySetting` | → | WCF Policy (webCategory rules) | Resolve category IDs via `category_settings.json`, map via category mapping file |
| DNS `domainlists` | → | WCF Policy (FQDN rules) | Resolve domains from `destination_lists.json`, dual FQDN pattern |
| Web rule (`content_category_ids`) | → | WCF Policy (webCategory rules) | Resolve via `extradata.categories[]`, map via category mapping file |
| Web rule (`destination_list_ids`) | → | WCF Policy (FQDN rules) | Resolve domains from `destination_lists.json`, dual FQDN pattern |
| Web rule (`application_ids`) | → | WCF Policy (FQDN rules) | Resolve via `extradata.applications[]`, look up by UmbrellaAppId in app mapping CSV |
| Web rule (`all_policy_identities`) | → | Default Security Profile | Priority 50000, `EntraGroups = "All Internet Access Users"` |
| Web rule (`identity_ids`) | → | Override Security Profile | Priority 1000+, resolved AD group/user names |
| DNS `securitySetting` | → | Warn & bypass | Advise to configure Threat Intelligence policies in EIA |
| DNS/Web `fileInspectionSetting` | → | Warn & bypass | Advise to configure File Policies in EIA |
| DNS/Web `settingGroupBypassInspectionGroup` | → | Warn & advise | Review and configure TLS Inspection Policy in EIA |
| Web `restriction` | → | Bypass silently | No EIA equivalent |
| Firewall rules | → | Out of scope | Not converted |

### Rule Action Mapping

| Umbrella Action | EIA PolicyAction | Notes |
|----------------|-----------------|-------|
| `block` | `Block` | Direct mapping |
| `allow` | `Allow` | Direct mapping |
| `warn` | `Block` | Flag for review — original allowed user click-through |
| `isolate` | `Block` | Flag for review — original used remote browser isolation |

---

## Input Files

### 1. dns_policies.json
**Source:** Cisco Umbrella configuration export
**Required:** At least one of `dns_policies.json` or `web_policies.json` must be provided

#### Description
Contains all DNS filtering policies configured in Cisco Umbrella, including category settings, domain lists, and security settings.

#### Key Fields to Process

| Field | Type | Description | Processing Notes |
|-------|------|-------------|------------------|
| `id` | integer | Unique policy identifier | Log for reference |
| `name` | string | Policy name | Used in EIA policy naming |
| `priority` | integer | Policy priority (lower = higher) | Log for reference |
| `isDefault` | boolean | Whether this is the default catch-all policy | All DNS policies treated as applying to all users |
| `identityCount` | integer | Count of assigned identities | Log only — no identity details available |
| `categorySetting.id` | integer | Category setting ID | Cross-reference to `category_settings.json` for category names |
| `domainlists[]` | array | Referenced domain lists | Look up in `destination_lists.json` for actual domains |
| `domainlists[].id` | integer | Domain list ID | Key for `destination_lists.json` lookup |
| `domainlists[].access` | string | "allow" or "block" | Maps to EIA PolicyAction |
| `domainlists[].name` | string | Domain list name | Used in EIA policy naming |

#### Processing Rules
1. Process all DNS policies (no state filtering — Umbrella DNS policies are always active)
2. For each policy, resolve `categorySetting.id` against `category_settings.json` to get category names
3. For each policy, resolve `domainlists[].id` against `destination_lists.json` to get domain entries
4. Treat all DNS policies as applying to all users (no identity details available)
5. Skip: `securitySetting` (warn, advise threat intel), `fileInspectionSetting` (warn, advise file policies), `policySetting` (bypass), `settingGroupBypassInspectionGroup` (warn, advise TLS inspection)

### 2. web_policies.json
**Source:** Cisco Umbrella configuration export
**Required:** At least one of `dns_policies.json` or `web_policies.json` must be provided

#### Description
Contains all web filtering policies with proxy rulesets, including granular rules with identity, application, destination, and category conditions.

#### Key Fields to Process

| Field | Type | Description | Processing Notes |
|-------|------|-------------|------------------|
| `id` | integer | Unique policy identifier | Log for reference |
| `name` | string | Policy name | Log for reference |
| `priority` | integer | Policy priority | Log for reference |
| `proxyRuleset.rules[]` | array | Ordered proxy rules | Primary conversion source |
| `proxyRuleset.rules[].ruleId` | integer | Unique rule identifier | Log for reference |
| `proxyRuleset.rules[].ruleName` | string | Rule name | Used in EIA policy naming |
| `proxyRuleset.rules[].rulePriority` | integer | Rule priority within policy | Informs ordering within Security Profile |
| `proxyRuleset.rules[].ruleAction` | string | "block", "allow", "warn", "isolate" | Maps to EIA PolicyAction |
| `proxyRuleset.rules[].ruleIsEnabled` | boolean | Whether rule is active | Only process enabled rules |
| `proxyRuleset.rules[].ruleConditions[]` | array | Multi-attribute conditions (AND logic) | See condition types below |
| `proxyRuleset.extradata.identities[]` | array | Identity lookup table | Resolves `identity_ids` to names |
| `proxyRuleset.extradata.applications[]` | array | Application lookup table | Resolves `application_ids` to names |
| `proxyRuleset.extradata.categories[]` | array | Category lookup table | Resolves `content_category_ids` to names |
| `proxyRuleset.extradata.destinationLists[]` | array | Destination list lookup table | Resolves `destination_list_ids` to names |

#### Rule Condition Types

| attributeName | attributeOperator | Description |
|--------------|-------------------|-------------|
| `umbrella.source.all_policy_identities` | `=` (value: `true`) | Rule applies to all identities in the policy |
| `umbrella.source.identity_ids` | `INTERSECT` (value: array of IDs) | Rule applies to specific AD users/groups |
| `umbrella.destination.application_ids` | `INTERSECT` (value: array of IDs) | Rule matches specific applications |
| `umbrella.destination.destination_list_ids` | `INTERSECT` (value: array of IDs) | Rule matches specific destination lists |
| `umbrella.destination.content_category_ids` | `INTERSECT` (value: array of IDs) | Rule matches specific content categories |
| `umbrella.bundle_id` | `=` (value: policy ID) | Scopes rule to parent policy (internal) |

#### Processing Rules
1. Process all web policies
2. For each policy, iterate through `proxyRuleset.rules[]`
3. Skip rules where `ruleIsEnabled = false` (log at DEBUG level)
4. For each enabled rule, process all `ruleConditions[]` to determine: WHO (identity scope), WHAT (destinations/categories/apps), and ACTION
5. Resolve IDs using `extradata` lookup tables
6. Skip: `categorySetting` at policy level (handled via rules), `securitySetting` (warn, advise threat intel), `fileInspectionSetting` (warn, advise file policies), `restriction` (bypass silently), `settingGroupBypassInspectionGroup` (warn, advise TLS inspection)

### 3. destination_lists.json
**Source:** Cisco Umbrella configuration export
**Required:** Yes

#### Description
Contains all destination lists with their domain entries. Referenced by both DNS and web policies.

#### Key Fields to Process

| Field | Type | Description | Processing Notes |
|-------|------|-------------|------------------|
| `id` | integer | Unique list identifier | Key for lookups |
| `name` | string | List name | Used in EIA policy naming |
| `access` | string | "allow" or "block" | Maps to EIA PolicyAction |
| `isGlobal` | boolean | Whether list is global | Log for reference |
| `destinations[]` | array | Domain entries | Convert to FQDN rules |
| `destinations[].destination` | string | Domain name | Apply dual FQDN pattern |
| `destinations[].type` | string | Entry type (typically "domain") | Validate is "domain" |

### 4. category_settings.json
**Source:** Cisco Umbrella configuration export
**Required:** Yes when `dns_policies.json` is provided (used to resolve DNS policy `categorySetting.id`)

#### Description
Contains category setting groups with named category arrays. Used to resolve DNS policy `categorySetting.id` to actual category names.

#### Key Fields to Process

| Field | Type | Description | Processing Notes |
|-------|------|-------------|------------------|
| `id` | integer | Setting group identifier | Key for cross-reference from DNS policies |
| `name` | string | Setting group name | Log for reference |
| `bundleTypeId` | integer | 1 = DNS, 2 = Web | Both types may be present |
| `categories[]` | array | Category entries | Source for category name resolution |
| `categories[].categoryId` | integer | Category identifier | Used in mapping lookup |
| `categories[].name` | string | Category display name | Looked up in category mapping file |

### 5. CiscoUmbrella2EIA-CategoryMappings.csv
**Source:** Manual configuration file (maintained by user)
**Required:** Yes

#### Description
Provides mapping between Cisco Umbrella web category names and Microsoft EIA web category names.

#### Schema

```csv
UmbrellaCategory,GSACategory,Note
Pornography,PornographyAndSexuallyExplicit,Partial match - pornography maps to broader category
Gambling,Gambling,Exact match
Some Unmapped Category,,No match
```

| Column | Description |
|--------|-------------|
| UmbrellaCategory | Cisco Umbrella category name (case-insensitive lookup) |
| GSACategory | Corresponding EIA/GSA web category name. Leave blank if no mapping exists |
| Note | Optional free-text note explaining the mapping rationale (not used in processing) |

#### Processing Rules
1. Import CSV and build a hashtable keyed by `UmbrellaCategory` (case-insensitive) storing the full row object for lookup
2. For each Umbrella category name, call `Resolve-CategoryMapping` which checks:
   - **Category not in mapping file** (`NoMappingRow`): Row doesn't exist → use placeholder `UNMAPPED:CategoryName`, flag for review
   - **Row exists but GSACategory is blank** (`NoGSAValue`): Row exists but `GSACategory` is empty or whitespace → use placeholder `UNMAPPED:CategoryName`, flag for review
   - **Successfully mapped** (`Success`): Use the `GSACategory` value directly
3. Track unmapped categories separately by failure type for summary statistics
4. The `Note` column is informational only — not used in processing

### 6. CiscoUmbrella2EIA-AppMappings.csv
**Source:** Generated by `Export-UmbrellaAppMappingTemplate`, then manually reviewed and populated by user
**Required:** Yes when `web_policies.json` is provided (used to resolve application-based rules)

#### Description
Provides pre-populated mapping between Cisco Umbrella application IDs/names and their corresponding GSA application names, match types, and FQDN endpoints for use in EIA web content filtering policies. This CSV is analogous to how `CiscoUmbrella2EIA-CategoryMappings.csv` works for web categories.

#### Schema

```csv
UmbrellaAppId,UmbrellaAppName,GSAAppName,MatchType,GSAEndpoints
12345,Dropbox,Dropbox,Exact,dropbox.com;dropboxapi.com
67890,Atlassian Confluence,Confluence,Approximate,atlassian.net;confluence.com
11111,SomeInternalApp,,,
```

| Column | Description |
|--------|-------------|
| UmbrellaAppId | Cisco Umbrella application ID (integer). Used as the hashtable lookup key |
| UmbrellaAppName | Cisco Umbrella application display name (informational) |
| GSAAppName | Corresponding GSA/EIA application name. Leave blank if no mapping exists |
| MatchType | `Exact` or `Approximate`. Leave blank if no mapping exists |
| GSAEndpoints | Semicolon-separated FQDN endpoints for the GSA application. Leave blank if no mapping exists |

#### Processing Rules — CSV Lookup by UmbrellaAppId

For each Umbrella application (resolved from `extradata.applications[]`):

1. **Look up by `UmbrellaAppId`** (integer key) in the app mappings hashtable
2. **Not in file** (`NotInFile`): Row doesn't exist for this AppId → use placeholder `UNMAPPED:AppName`, set `ReviewNeeded = Yes`
3. **No match** (`NoMatch`): Row exists but `GSAAppName` or `MatchType` is blank → use placeholder `UNMAPPED:AppName`, set `ReviewNeeded = Yes`
4. **Mapped with endpoints**: Row has `GSAAppName`, `MatchType`, and non-empty `GSAEndpoints` → parse endpoints (semicolon-split), apply dual FQDN pattern to each, no review flag (applies to both `Exact` and `Approximate` match types)
5. **Mapped but no endpoints**: Row has `GSAAppName` and `MatchType` but `GSAEndpoints` is empty → use placeholder `UNMAPPED:AppName`, set `ReviewNeeded = Yes`, log warning

---

## Output Files

All output files are created in `$OutputBasePath` with consistent timestamp prefix.

### 1. Policies CSV
**Filename:** `[yyyyMMdd_HHmmss]_EIA_Policies.csv`

#### Description
Contains all web content filtering policies with FQDN and webCategory rules.

#### Fields

| Field | Description | Example | Notes |
|-------|-------------|---------|-------|
| PolicyName | Policy name | "Web-BlockYandex-Apps-Block" | Unique identifier |
| PolicyType | Type of policy | "WebContentFiltering" | Always "WebContentFiltering" |
| PolicyAction | Block or Allow | "Block", "Allow" | From rule action mapping |
| Description | Policy description | "Converted from Umbrella rule: Block - Yandex" | Source context |
| RuleType | Type of destination | "FQDN", "webCategory" | One type per row |
| RuleDestinations | Semicolon-separated list | "yandex.com;*.yandex.com;yandex.ru;*.yandex.ru" | Dual FQDN pattern for domains |
| RuleName | Sub-rule identifier | "FQDNs", "WebCategories" | For grouping/splitting |
| ReviewNeeded | Manual review flag | "Yes", "No" | "Yes" if unmapped category, unmapped/missing app, or warn/isolate action |
| ReviewDetails | Reason for review | "App 'SomeApp' (ID: 123) not found in app mapping file" | Semicolon-separated reasons |
| Provision | Provisioning flag | "yes", "no" | "no" if ReviewNeeded is "Yes" |

#### FQDN Dual-Entry Pattern

When converting domain destinations (from destination lists or application mapping endpoints), each domain produces two FQDN entries in the same rule:
- `domain.com` — matches the bare domain
- `*.domain.com` — matches all subdomains

Both entries are semicolon-separated in the `RuleDestinations` column of the same rule row.

Example: A destination list with domains `example.com` and `contoso.com` produces:
```
RuleDestinations: example.com;*.example.com;contoso.com;*.contoso.com
```

#### RuleDestinations Character Limit
- **FQDN rules**: 300-character limit per `RuleDestinations` field. If exceeded, split into multiple rules with numeric suffixes (e.g., `FQDNs`, `FQDNs-2`, `FQDNs-3`)
- **webCategory rules**: No character limit, never split

### 2. Security Profiles CSV
**Filename:** `[yyyyMMdd_HHmmss]_EIA_SecurityProfiles.csv`

#### Description
Contains security profile definitions that reference web content filtering policies and assign them to users/groups via Conditional Access.

#### Fields

| Field | Description | Example | Notes |
|-------|-------------|---------|-------|
| SecurityProfileName | Profile name | "Default-CiscoUmbrella" | Unique identifier |
| Priority | Profile priority | "50000" | Lower = higher precedence |
| SecurityProfileLinks | Policy links with priorities | "DNS-Default-Categories-Block:100;Web-BlockApps-Block:200" | `PolicyName:Priority` format, semicolon-separated |
| CADisplayName | Conditional Access policy name | "CA-EIA-Default-CiscoUmbrella" | Required when users/groups specified |
| EntraUsers | Semicolon-separated UPNs | "" | Parsed from AD user labels |
| EntraGroups | Semicolon-separated group names | "All Internet Access Users" | From identity resolution |
| Provision | Provisioning flag | "yes" | Always "yes" for security profiles |

#### Default Security Profile

| Field | Value |
|-------|-------|
| SecurityProfileName | `"Default-CiscoUmbrella"` |
| Priority | `50000` |
| SecurityProfileLinks | All policies from broad rules (`all_policy_identities` + DNS policies) |
| CADisplayName | `"CA-EIA-Default-CiscoUmbrella"` |
| EntraGroups | `"All Internet Access Users"` |

#### Override Security Profiles

| Field | Value |
|-------|-------|
| SecurityProfileName | `"Override-[GroupNames]"` (derived from identity set) |
| Priority | Starting at `1000`, incrementing by `100` |
| SecurityProfileLinks | Policies from rules targeting this identity set |
| CADisplayName | `"CA-EIA-Override-[GroupNames]"` |
| EntraGroups | AD group names from `extradata.identities[]` (semicolon-separated) |
| EntraUsers | AD user UPNs from `extradata.identities[]` (semicolon-separated) |

### 3. Log File
**Filename:** `[yyyyMMdd_HHmmss]_Convert-CiscoUmbrella2EIA.log`
**Location:** Same directory as output CSV files (`$OutputBasePath`)

#### Description
Comprehensive log file created by `Write-LogMessage` with all processing details, warnings, and statistics.

---

## Processing Logic

### Phase 1: Data Loading and Validation

#### 1.1 Initialize Logging
```powershell
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath = Join-Path $OutputBasePath "${timestamp}_Convert-CiscoUmbrella2EIA.log"
```

#### 1.2 Load Input Files
1. Validate that at least one of `DnsPoliciesPath` or `WebPoliciesPath` is provided — Fatal error if neither is specified
2. If `DnsPoliciesPath` is provided: Load `dns_policies.json` — Fatal error if invalid JSON
3. If `WebPoliciesPath` is provided: Load `web_policies.json` — Fatal error if invalid JSON
4. Load `destination_lists.json` — Fatal error if missing or invalid JSON
5. If `DnsPoliciesPath` is provided: Load `category_settings.json` — Fatal error if missing or invalid JSON
6. Load `CiscoUmbrella2EIA-CategoryMappings.csv` — Fatal error if missing or invalid CSV
7. If `WebPoliciesPath` is provided: Load `CiscoUmbrella2EIA-AppMappings.csv` — Fatal error if missing or invalid CSV

#### 1.3 Build Lookup Tables

```powershell
# Destination lists: id → list object (with destinations[])
$destinationListsHashtable = @{}
foreach ($list in $destinationLists) {
    $destinationListsHashtable[$list.id] = $list
}

# Category settings: id → setting object (with categories[])
$categorySettingsHashtable = @{}
foreach ($setting in $categorySettings) {
    $categorySettingsHashtable[$setting.id] = $setting
}

# Category mappings: UmbrellaCategory (lowercase) → full row object (loaded from CSV)
$categoryMappingsHashtable = @{}
foreach ($mapping in $categoryMappings) {
    $categoryMappingsHashtable[$mapping.UmbrellaCategory.ToLower()] = $mapping
}

# App mappings: UmbrellaAppId (int) → full CSV row object
$appMappingsHashtable = @{}
foreach ($row in $appMappings) {
    $appMappingsHashtable[[int]$row.UmbrellaAppId] = $row
}

# Collections for output
$allPolicies = @()
$identityScopedRules = @{}  # key = sorted identity set hash, value = { identities, policies }
$defaultScopePolicies = @()  # policies for the Default Security Profile

# Flags for what was provided
$hasDnsPolicies = -not [string]::IsNullOrWhiteSpace($DnsPoliciesPath)
$hasWebPolicies = -not [string]::IsNullOrWhiteSpace($WebPoliciesPath)
```

### Phase 2: DNS Policy Processing

> **Conditional:** This phase is only executed when `DnsPoliciesPath` is provided. If not provided, skip entirely to Phase 3.

#### 2.1 Process Each DNS Policy

```
For each DNS policy in dns_policies.json:
    # Apply policy name filter
    If IncludePolicyName or ExcludePolicyName specified:
        Test policy name against include/exclude patterns (case-insensitive -like matching)
        If not included or excluded: skip, log at INFO, increment DnsPoliciesSkippedByFilter, continue

    Log policy name, priority, identityCount at INFO level
    
    # Process categorySetting
    Resolve categorySetting.id against category_settings.json
    If categories found:
        Map each category name via category mapping file
        Create WCF Block policy with webCategory rules
        Add to $defaultScopePolicies
    
    # Process domainlists
    For each domainlist reference:
        Resolve list ID against destination_lists.json
        Get access (allow/block) and domain entries
        Create WCF policy with FQDN rules (dual pattern)
        Add to $defaultScopePolicies
    
    # Log warnings for bypassed settings
    If securitySetting present:
        Log WARN: "Advise configuring Threat Intelligence policies in EIA"
    If fileInspectionSetting present:
        Log WARN: "Advise configuring File Policies in EIA"
    If settingGroupBypassInspectionGroup present:
        Log WARN: "Advise reviewing and configuring TLS Inspection Policy in EIA"
```

#### 2.2 Category Resolution for DNS Policies

```powershell
# Resolve DNS policy category setting to category names
$categorySettingId = $dnsPolicy.categorySetting.id
$categorySetting = $categorySettingsHashtable[$categorySettingId]

if ($null -ne $categorySetting -and $categorySetting.categories.Count -gt 0) {
    $mappedCategories = @()
    $hasUnmapped = $false
    $reviewReasons = @()
    
    foreach ($category in $categorySetting.categories) {
        $mappingResult = Resolve-CategoryMapping -CategoryName $category.name -CategoryMappingsHashtable $categoryMappingsHashtable
        
        if ($mappingResult.IsMapped) {
            $mappedCategories += $mappingResult.GSACategory
            $stats.CategoriesMapped++
        }
        else {
            $mappedCategories += $mappingResult.GSACategory  # "UNMAPPED:CategoryName"
            $hasUnmapped = $true
            $reviewReasons += $mappingResult.LogMessage
            if ($mappingResult.MappingType -eq 'NoMappingRow') {
                $stats.UnmappedCategories_MissingInFile++
            } else {
                $stats.UnmappedCategories_NoGSAValue++
            }
            Write-LogMessage -Message "DNS policy '$($dnsPolicy.name)': $($mappingResult.LogMessage)" -Level WARN
        }
    }
    
    # Create policy entry
    $policyName = "DNS-$($dnsPolicy.name -replace '\s+','')-Categories-Block"
    $policyEntry = @{
        PolicyName       = $policyName
        PolicyType       = "WebContentFiltering"
        PolicyAction     = "Block"
        Description      = "Converted from Umbrella DNS policy: $($dnsPolicy.name)"
        RuleType         = "webCategory"
        RuleDestinations = $mappedCategories -join ";"
        RuleName         = "WebCategories"
        ReviewNeeded     = if ($hasUnmapped) { "Yes" } else { "No" }
        ReviewDetails    = $reviewReasons -join "; "
        Provision        = if ($hasUnmapped) { "no" } else { "yes" }
    }
    
    $allPolicies += $policyEntry
    $defaultScopePolicies += $policyName
}
```

#### 2.3 Domain List Resolution for DNS Policies

```powershell
foreach ($domainlistRef in $dnsPolicy.domainlists) {
    $fullList = $destinationListsHashtable[$domainlistRef.id]
    
    if ($null -eq $fullList -or $fullList.destinations.Count -eq 0) {
        Write-LogMessage "Domain list $($domainlistRef.name) (ID: $($domainlistRef.id)) has no destinations, skipping" -Level WARN
        continue
    }
    
    # Build FQDN entries with dual pattern
    $fqdnEntries = @()
    foreach ($dest in $fullList.destinations) {
        if ($dest.type -eq "domain") {
            $fqdnEntries += $dest.destination
            $fqdnEntries += "*.$($dest.destination)"
        }
    }
    
    $action = if ($domainlistRef.access -eq "allow") { "Allow" } else { "Block" }
    $actionSuffix = if ($domainlistRef.access -eq "allow") { "Allow" } else { "Block" }
    $listNameClean = $domainlistRef.name -replace '\s+','' -replace '[^a-zA-Z0-9_-]',''
    $policyName = "DNS-$($dnsPolicy.name -replace '\s+','')-$listNameClean-$actionSuffix"
    
    # Split by character limit if needed
    $groups = Split-ByCharacterLimit -Entries $fqdnEntries -MaxLength 300
    
    for ($i = 0; $i -lt $groups.Count; $i++) {
        $ruleName = if ($i -eq 0) { "FQDNs" } else { "FQDNs-$($i + 1)" }
        
        $policyEntry = @{
            PolicyName       = $policyName
            PolicyType       = "WebContentFiltering"
            PolicyAction     = $action
            Description      = "Converted from Umbrella DNS policy: $($dnsPolicy.name), list: $($domainlistRef.name)"
            RuleType         = "FQDN"
            RuleDestinations = $groups[$i] -join ";"
            RuleName         = $ruleName
            ReviewNeeded     = "No"
            ReviewDetails    = ""
            Provision        = "yes"
        }
        
        $allPolicies += $policyEntry
    }
    
    $defaultScopePolicies += $policyName
}
```

### Phase 3: Web Policy Processing

> **Conditional:** This phase is only executed when `WebPoliciesPath` is provided. If not provided, skip entirely to Phase 4.

#### 3.1 Build Extradata Lookup Tables (Per Web Policy)

For each web policy:
1. Apply policy name filter — if `IncludePolicyName` or `ExcludePolicyName` specified, test `webPolicy.name` against patterns. If not included or excluded: skip, log at INFO, increment `WebPoliciesSkippedByFilter`, continue.
2. Build lookup tables from its `extradata`:

```powershell
# Identity lookup: id → { label, type, typeLabel }
$identityLookup = @{}
foreach ($identity in $webPolicy.proxyRuleset.extradata.identities) {
    $identityLookup[$identity.id] = $identity
}

# Application lookup: id → { label, description }
$appLookup = @{}
foreach ($app in $webPolicy.proxyRuleset.extradata.applications) {
    $appLookup[$app.id] = $app
}

# Category lookup: id → { label }
$categoryLookup = @{}
foreach ($cat in $webPolicy.proxyRuleset.extradata.categories) {
    $categoryLookup[$cat.id] = $cat
}

# Destination list lookup: id → { label }
$destListLookup = @{}
foreach ($dl in $webPolicy.proxyRuleset.extradata.destinationLists) {
    $destListLookup[$dl.id] = $dl
}
```

#### 3.2 Process Each Enabled Rule

```
For each rule in webPolicy.proxyRuleset.rules:
    If ruleIsEnabled == false:
        Log at DEBUG level, skip
        Continue
    
    # Parse rule conditions
    $identityScope = "all"  # default
    $identityIds = @()
    $applicationIds = @()
    $destinationListIds = @()
    $contentCategoryIds = @()
    
    For each condition in rule.ruleConditions:
        Switch on attributeName:
            "umbrella.source.all_policy_identities":
                $identityScope = "all"
            "umbrella.source.identity_ids":
                $identityScope = "specific"
                $identityIds = condition.attributeValue
            "umbrella.destination.application_ids":
                $applicationIds = condition.attributeValue
            "umbrella.destination.destination_list_ids":
                $destinationListIds = condition.attributeValue
            "umbrella.destination.content_category_ids":
                $contentCategoryIds = condition.attributeValue
            "umbrella.bundle_id":
                # Internal scoping, skip
    
    # Determine EIA action
    $eiaAction = switch ($rule.ruleAction) {
        "block"   { "Block" }
        "allow"   { "Allow" }
        "warn"    { "Block" }  # Flag for review
        "isolate" { "Block" }  # Flag for review
    }
    
    # Create policies from rule destinations (see 3.3, 3.4, 3.5)
    # Route to identity scope bucket (see 3.6)
```

#### 3.3 Convert Application-Based Conditions

For rules with `application_ids`:

```powershell
$allEndpoints = @()
$unmappedApps = @()
$appReviewReasons = @()

foreach ($appId in $applicationIds) {
    $umbrellaApp = $appLookup[$appId]
    if ($null -eq $umbrellaApp) {
        Write-LogMessage "Application ID $appId not found in extradata" -Level WARN
        $appReviewReasons += "Unknown application ID: $appId"
        continue
    }
    
    $appName = $umbrellaApp.label
    $appMatch = Resolve-AppMapping -AppId $appId -AppName $appName -AppMappingsHashtable $appMappingsHashtable
    
    if ($appMatch.IsMapped) {
        if ($appMatch.Endpoints.Count -gt 0) {
            # Mapped with endpoints — apply dual FQDN pattern
            foreach ($endpoint in $appMatch.Endpoints) {
                $dualEntries = ConvertTo-DualFqdnEntries -Domain $endpoint
                foreach ($entry in $dualEntries) {
                    $allEndpoints += $entry
                }
            }
        }
        else {
            # Mapped but no endpoints — treat as unmapped
            $unmappedApps += "UNMAPPED:$appName"
            $appReviewReasons += "App '$appName' mapped to '$($appMatch.GSAAppName)' but has no endpoints"
        }
        
        if ($appMatch.MatchType -eq 'Exact') {
            $stats.AppsMatchedExact++
        }
        else {
            $stats.AppsMatchedApproximate++
        }
    }
    else {
        # Not mapped — add UNMAPPED placeholder
        $unmappedApps += "UNMAPPED:$appName"
        $appReviewReasons += $appMatch.LogMessage
        
        if ($appMatch.MatchType -eq 'NotInFile') {
            $stats.AppsUnmatched_NotInFile++
        }
        else {
            $stats.AppsUnmatched_NoMatch++
        }
    }
}

# Create FQDN policy if endpoints or unmapped apps exist
if ($allEndpoints.Count -gt 0 -or $unmappedApps.Count -gt 0) {
    $ruleNameClean = $rule.ruleName -replace '\s+','' -replace '[^a-zA-Z0-9_-]',''
    $policyName = "Web-$ruleNameClean-Apps-$eiaAction"
    $hasReview = $appReviewReasons.Count -gt 0
    
    # Handle warn/isolate action review
    if ($rule.ruleAction -eq "warn") {
        $appReviewReasons += "Original action was 'warn' (user click-through) — converted to Block"
        $hasReview = $true
    }
    if ($rule.ruleAction -eq "isolate") {
        $appReviewReasons += "Original action was 'isolate' (remote browser isolation) — converted to Block"
        $hasReview = $true
    }
    
    # Combine real endpoints and unmapped app placeholders
    $allRuleDestinations = $allEndpoints + $unmappedApps
    $hasUnmappedApps = $unmappedApps.Count -gt 0
    
    $groups = Split-ByCharacterLimit -Entries $allRuleDestinations -MaxLength 300
    
    for ($i = 0; $i -lt $groups.Count; $i++) {
        $ruleName = if ($i -eq 0) { "FQDNs" } else { "FQDNs-$($i + 1)" }
        
        $policyEntry = @{
            PolicyName       = $policyName
            PolicyType       = "WebContentFiltering"
            PolicyAction     = $eiaAction
            Description      = "Converted from Umbrella web rule: $($rule.ruleName)"
            RuleType         = "FQDN"
            RuleDestinations = $groups[$i] -join ";"
            RuleName         = $ruleName
            ReviewNeeded     = if ($hasUnmappedApps) { "Yes" } else { "No" }
            ReviewDetails    = $appReviewReasons -join "; "
            Provision        = if ($hasUnmappedApps) { "no" } else { "yes" }
        }
        
        $allPolicies += $policyEntry
    }
    
    # Route policy to identity scope (see 3.6)
}
```

#### 3.4 Convert Destination List Conditions

For rules with `destination_list_ids`:

```powershell
foreach ($listId in $destinationListIds) {
    $fullList = $destinationListsHashtable[$listId]
    
    if ($null -eq $fullList) {
        Write-LogMessage "Destination list ID $listId not found" -Level WARN
        continue
    }
    
    if ($fullList.destinations.Count -eq 0) {
        Write-LogMessage "Destination list $($fullList.name) has no entries, skipping" -Level WARN
        continue
    }
    
    # Build FQDN entries with dual pattern
    $fqdnEntries = @()
    foreach ($dest in $fullList.destinations) {
        if ($dest.type -eq "domain") {
            $fqdnEntries += $dest.destination
            $fqdnEntries += "*.$($dest.destination)"
        }
    }
    
    $listNameClean = $fullList.name -replace '\s+','' -replace '[^a-zA-Z0-9_-]',''
    $ruleNameClean = $rule.ruleName -replace '\s+','' -replace '[^a-zA-Z0-9_-]',''
    $policyName = "Web-$ruleNameClean-$listNameClean-$eiaAction"
    
    $reviewReasons = @()
    if ($rule.ruleAction -eq "warn") {
        $reviewReasons += "Original action was 'warn' — converted to Block"
    }
    if ($rule.ruleAction -eq "isolate") {
        $reviewReasons += "Original action was 'isolate' — converted to Block"
    }
    $hasReview = $reviewReasons.Count -gt 0
    
    $groups = Split-ByCharacterLimit -Entries $fqdnEntries -MaxLength 300
    
    for ($i = 0; $i -lt $groups.Count; $i++) {
        $ruleName = if ($i -eq 0) { "FQDNs" } else { "FQDNs-$($i + 1)" }
        
        $policyEntry = @{
            PolicyName       = $policyName
            PolicyType       = "WebContentFiltering"
            PolicyAction     = $eiaAction
            Description      = "Converted from Umbrella web rule: $($rule.ruleName), list: $($fullList.name)"
            RuleType         = "FQDN"
            RuleDestinations = $groups[$i] -join ";"
            RuleName         = $ruleName
            ReviewNeeded     = if ($hasReview) { "Yes" } else { "No" }
            ReviewDetails    = $reviewReasons -join "; "
            Provision        = if ($hasReview) { "no" } else { "yes" }
        }
        
        $allPolicies += $policyEntry
    }
    
    # Route policy to identity scope (see 3.6)
}
```

#### 3.5 Convert Content Category Conditions

For rules with `content_category_ids`:

```powershell
$mappedCategories = @()
$reviewReasons = @()

foreach ($catId in $contentCategoryIds) {
    $umbrellaCat = $categoryLookup[$catId]
    $catName = if ($null -ne $umbrellaCat) { $umbrellaCat.label } else { "UnknownCategory_$catId" }
    
    $mappingResult = Resolve-CategoryMapping -CategoryName $catName -CategoryMappingsHashtable $categoryMappingsHashtable
    
    if ($mappingResult.IsMapped) {
        $mappedCategories += $mappingResult.GSACategory
        $stats.CategoriesMapped++
    }
    else {
        $mappedCategories += $mappingResult.GSACategory  # "UNMAPPED:CategoryName"
        $reviewReasons += $mappingResult.LogMessage
        if ($mappingResult.MappingType -eq 'NoMappingRow') {
            $stats.UnmappedCategories_MissingInFile++
        } else {
            $stats.UnmappedCategories_NoGSAValue++
        }
        Write-LogMessage -Message "Web rule '$($rule.ruleName)': $($mappingResult.LogMessage)" -Level WARN
    }
}

if ($mappedCategories.Count -gt 0) {
    $ruleNameClean = $rule.ruleName -replace '\s+','' -replace '[^a-zA-Z0-9_-]',''
    $policyName = "Web-$ruleNameClean-Categories-$eiaAction"
    
    if ($rule.ruleAction -eq "warn") {
        $reviewReasons += "Original action was 'warn' — converted to Block"
    }
    if ($rule.ruleAction -eq "isolate") {
        $reviewReasons += "Original action was 'isolate' — converted to Block"
    }
    $hasReview = $reviewReasons.Count -gt 0
    
    $policyEntry = @{
        PolicyName       = $policyName
        PolicyType       = "WebContentFiltering"
        PolicyAction     = $eiaAction
        Description      = "Converted from Umbrella web rule: $($rule.ruleName)"
        RuleType         = "webCategory"
        RuleDestinations = $mappedCategories -join ";"
        RuleName         = "WebCategories"
        ReviewNeeded     = if ($hasReview) { "Yes" } else { "No" }
        ReviewDetails    = $reviewReasons -join "; "
        Provision        = if ($hasReview) { "no" } else { "yes" }
    }
    
    $allPolicies += $policyEntry
    
    # Route policy to identity scope (see 3.6)
}
```

#### 3.6 Identity Scope Routing

After creating policies from a rule's conditions, route the policy names to the appropriate scope:

```powershell
if ($identityScope -eq "all") {
    # Add to Default Security Profile
    $defaultScopePolicies += $policyName
}
else {
    # Resolve identity IDs to names
    $resolvedGroups = @()
    $resolvedUsers = @()
    
    foreach ($idVal in $identityIds) {
        $identity = $identityLookup[$idVal]
        if ($null -ne $identity) {
            if ($identity.type -eq 3) {
                # AD Group — extract group name from label (e.g., "Security Group1 (contoso.local\SecurityGroup1)")
                $groupName = $identity.label -replace '\s*\(.*\)$', ''
                $resolvedGroups += $groupName
            }
            elseif ($identity.type -eq 7) {
                # AD User — extract UPN from label (e.g., "John (John.Smith@contoso.com)")
                if ($identity.label -match '\(([^)]+@[^)]+)\)') {
                    $resolvedUsers += $Matches[1]
                }
                else {
                    $resolvedUsers += $identity.label
                }
            }
        }
        else {
            Write-LogMessage "Identity ID $idVal not found in extradata" -Level WARN
        }
    }
    
    # Create a unique key for this identity set (sorted for consistency)
    $identityKey = ($resolvedGroups + $resolvedUsers | Sort-Object) -join ";"
    
    if (-not $identityScopedRules.ContainsKey($identityKey)) {
        $identityScopedRules[$identityKey] = @{
            Groups   = $resolvedGroups
            Users    = $resolvedUsers
            Policies = @()
        }
    }
    
    $identityScopedRules[$identityKey].Policies += $policyName
}
```

### Phase 4: Deduplication and Merging

After all DNS and web policies are processed, deduplicate the collected policies.

#### 4.1 Merge Category Rules

Combine all webCategory rules with the same `PolicyAction` targeting the same identity scope into a single policy:

```powershell
# Collect all category Block policies destined for the Default Security Profile
$defaultCategoryBlocks = $allPolicies | Where-Object {
    $_.PolicyName -in $defaultScopePolicies -and
    $_.RuleType -eq "webCategory" -and
    $_.PolicyAction -eq "Block"
}

if ($defaultCategoryBlocks.Count -gt 1) {
    # Merge all webCategory destinations into a single deduplicated set
    $allCategories = @()
    $allReviewReasons = @()
    
    foreach ($policy in $defaultCategoryBlocks) {
        $categories = $policy.RuleDestinations -split ";"
        $allCategories += $categories
        if ($policy.ReviewDetails) {
            $allReviewReasons += ($policy.ReviewDetails -split "; ")
        }
    }
    
    $uniqueCategories = $allCategories | Select-Object -Unique
    $uniqueReviewReasons = $allReviewReasons | Select-Object -Unique
    $hasReview = $uniqueReviewReasons.Count -gt 0
    
    # Remove individual category policies
    $allPolicies = $allPolicies | Where-Object { $_ -notin $defaultCategoryBlocks }
    $defaultScopePolicies = $defaultScopePolicies | Where-Object {
        $_ -notin ($defaultCategoryBlocks | ForEach-Object { $_.PolicyName })
    }
    
    # Create single merged policy
    $mergedPolicyName = "Default-Categories-Block"
    $mergedPolicy = @{
        PolicyName       = $mergedPolicyName
        PolicyType       = "WebContentFiltering"
        PolicyAction     = "Block"
        Description      = "Merged category blocks from DNS and web policies"
        RuleType         = "webCategory"
        RuleDestinations = $uniqueCategories -join ";"
        RuleName         = "WebCategories"
        ReviewNeeded     = if ($hasReview) { "Yes" } else { "No" }
        ReviewDetails    = $uniqueReviewReasons -join "; "
        Provision        = if ($hasReview) { "no" } else { "yes" }
    }
    
    $allPolicies += $mergedPolicy
    $defaultScopePolicies += $mergedPolicyName
}

# Repeat for Allow policies if any exist
# Repeat for each Override identity scope
```

#### 4.2 Merge FQDN Rules

Same approach for FQDN rules — merge all FQDN entries with the same `PolicyAction` targeting the same identity scope, then re-split by character limit:

```powershell
# Collect all FQDN Block policies destined for the Default Security Profile
$defaultFqdnBlocks = $allPolicies | Where-Object {
    $_.PolicyName -in $defaultScopePolicies -and
    $_.RuleType -eq "FQDN" -and
    $_.PolicyAction -eq "Block"
}

if ($defaultFqdnBlocks.Count -gt 1) {
    # Merge all FQDN destinations into a single deduplicated set
    $allFqdns = @()
    foreach ($policy in $defaultFqdnBlocks) {
        $fqdns = $policy.RuleDestinations -split ";"
        $allFqdns += $fqdns
    }
    $uniqueFqdns = $allFqdns | Select-Object -Unique
    
    # Remove individual FQDN policies
    $allPolicies = $allPolicies | Where-Object { $_ -notin $defaultFqdnBlocks }
    $defaultScopePolicies = $defaultScopePolicies | Where-Object {
        $_ -notin ($defaultFqdnBlocks | ForEach-Object { $_.PolicyName })
    }
    
    # Re-split by character limit and create merged policy
    $mergedPolicyName = "Default-Destinations-Block"
    $groups = Split-ByCharacterLimit -Entries $uniqueFqdns -MaxLength 300
    
    for ($i = 0; $i -lt $groups.Count; $i++) {
        $ruleName = if ($i -eq 0) { "FQDNs" } else { "FQDNs-$($i + 1)" }
        
        $policyEntry = @{
            PolicyName       = $mergedPolicyName
            PolicyType       = "WebContentFiltering"
            PolicyAction     = "Block"
            Description      = "Merged FQDN blocks from DNS and web policies"
            RuleType         = "FQDN"
            RuleDestinations = $groups[$i] -join ";"
            RuleName         = $ruleName
            ReviewNeeded     = "No"
            ReviewDetails    = ""
            Provision        = "yes"
        }
        
        $allPolicies += $policyEntry
    }
    
    $defaultScopePolicies += $mergedPolicyName
}

# Repeat for Allow policies
# Repeat for each Override identity scope
```

### Phase 5: Security Profile Assembly

#### 5.1 Create Default Security Profile

```powershell
# Deduplicate policy names for the default scope
$uniqueDefaultPolicies = $defaultScopePolicies | Select-Object -Unique

# Build SecurityProfileLinks with priority numbering
$linkPriority = 100
$profileLinks = @()
foreach ($policyName in $uniqueDefaultPolicies) {
    $profileLinks += "${policyName}:${linkPriority}"
    $linkPriority += 100
}

$defaultProfile = @{
    SecurityProfileName  = "Default-CiscoUmbrella"
    Priority             = 50000
    SecurityProfileLinks = $profileLinks -join ";"
    CADisplayName        = "CA-EIA-Default-CiscoUmbrella"
    EntraUsers           = ""
    EntraGroups          = "All Internet Access Users"
    Provision            = "yes"
}
```

#### 5.2 Create Override Security Profiles

```powershell
$overridePriority = 1000

foreach ($identityKey in $identityScopedRules.Keys) {
    $scopeData = $identityScopedRules[$identityKey]
    
    # Deduplicate policy names for this scope
    $uniquePolicies = $scopeData.Policies | Select-Object -Unique
    
    # Build SecurityProfileLinks
    $linkPriority = 100
    $profileLinks = @()
    foreach ($policyName in $uniquePolicies) {
        $profileLinks += "${policyName}:${linkPriority}"
        $linkPriority += 100
    }
    
    # Generate profile name from group names (truncate if too long)
    $groupLabel = if ($scopeData.Groups.Count -gt 0) {
        ($scopeData.Groups | Select-Object -First 2) -join "-"
    }
    elseif ($scopeData.Users.Count -gt 0) {
        "Users-$($scopeData.Users.Count)"
    }
    else { "Unknown" }
    
    $profileName = "Override-$groupLabel"
    
    $overrideProfile = @{
        SecurityProfileName  = $profileName
        Priority             = $overridePriority
        SecurityProfileLinks = $profileLinks -join ";"
        CADisplayName        = "CA-EIA-$profileName"
        EntraUsers           = $scopeData.Users -join ";"
        EntraGroups          = $scopeData.Groups -join ";"
        Provision            = "yes"
    }
    
    $securityProfiles += $overrideProfile
    $overridePriority += 100
}
```

### Phase 6: Export and Summary

#### 6.1 Export Policies CSV
```powershell
$allPolicies | Export-Csv -Path $policiesCsvPath -NoTypeInformation
Write-LogMessage "Exported $($allPolicies.Count) policy rows to: $policiesCsvPath" -Level "INFO"
```

#### 6.2 Export Security Profiles CSV
```powershell
$securityProfiles | Export-Csv -Path $spCsvPath -NoTypeInformation
Write-LogMessage "Exported $($securityProfiles.Count) security profiles to: $spCsvPath" -Level "INFO"
```

#### 6.3 Generate Summary Statistics

Log the following at INFO level:

```
=== CONVERSION SUMMARY ===
Input mode: [DNS only | Web only | DNS + Web]
DNS policies processed: X (or "N/A — DNS policies not provided")
Web policies processed: Y (or "N/A — Web policies not provided")
Web rules processed (enabled): Z
Web rules skipped (disabled): W

Categories mapped: A
Unmapped categories:
  - Missing in mapping file: B1
  - No GSA category value: B2
Applications matched (exact): C
Applications matched (approximate): D
Applications unmatched:
  - No match in mapping file: E1
  - Missing from mapping file: E2

Destination lists resolved: F
Total FQDN entries generated: G

Policies created: H
  - webCategory policies: H1
  - FQDN policies: H2
Security profiles created: I
  - Default: 1
  - Overrides: I-1

Policies merged during deduplication: J

Warnings:
  - Configure Threat Intelligence policies in EIA
  - Configure File Policies in EIA
  - Review TLS Inspection Policy configuration in EIA

Output files:
  - Policies: [path]
  - Security Profiles: [path]
  - Log File: [path]
```

---

## Function Parameters

### Required Parameters
None (all have defaults)

### Optional Parameters

| Parameter | Type | Default | Description | Validation |
|-----------|------|---------|-------------|------------|
| DnsPoliciesPath | string | `$null` | Path to DNS policies file | ValidateScript - file must exist if provided. At least one of DnsPoliciesPath or WebPoliciesPath must be provided (validated at runtime) |
| WebPoliciesPath | string | `$null` | Path to web policies file | ValidateScript - file must exist if provided. At least one of DnsPoliciesPath or WebPoliciesPath must be provided (validated at runtime) |
| DestinationListsPath | string | `destination_lists.json` | Path to destination lists file | ValidateScript - file must exist |
| CategorySettingsPath | string | `category_settings.json` | Path to category settings file | ValidateScript - file must exist. Required when DnsPoliciesPath is provided |
| CategoryMappingsPath | string | `CiscoUmbrella2EIA-CategoryMappings.csv` | Path to category mappings CSV file | ValidateScript - file must exist |
| AppMappingsPath | string | `CiscoUmbrella2EIA-AppMappings.csv` | Path to app mappings CSV file | ValidateScript - file must exist. Required when WebPoliciesPath is provided |
| OutputBasePath | string | `$PWD` | Output directory for CSV and log files | ValidateScript - directory must exist |
| IncludePolicyName | string[] | `$null` | Policy name patterns to include. Supports wildcards via `-like`. Case-insensitive. When specified, only DNS and Web policies matching at least one pattern are processed | None |
| ExcludePolicyName | string[] | `$null` | Policy name patterns to exclude. Supports wildcards via `-like`. Case-insensitive. When specified, matching policies are skipped. Exclude wins over include when both match | None |
| EnableDebugLogging | switch | `false` | Enable DEBUG level logging | None |

### Parameter Definitions

```powershell
[CmdletBinding(SupportsShouldProcess = $false)]
param(
    [Parameter(HelpMessage = "Path to Cisco Umbrella DNS Policies JSON export. At least one of DnsPoliciesPath or WebPoliciesPath must be provided.")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$DnsPoliciesPath,
    
    [Parameter(HelpMessage = "Path to Cisco Umbrella Web Policies JSON export. At least one of DnsPoliciesPath or WebPoliciesPath must be provided.")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$WebPoliciesPath,
    
    [Parameter(HelpMessage = "Path to Cisco Umbrella Destination Lists JSON export")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$DestinationListsPath = (Join-Path $PWD "destination_lists.json"),
    
    [Parameter(HelpMessage = "Path to Cisco Umbrella Category Settings JSON export")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$CategorySettingsPath = (Join-Path $PWD "category_settings.json"),
    
    [Parameter(HelpMessage = "Path to Umbrella to EIA category mappings CSV file")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$CategoryMappingsPath = (Join-Path $PWD "CiscoUmbrella2EIA-CategoryMappings.csv"),
    
    [Parameter(HelpMessage = "Path to Umbrella to EIA application mappings CSV file")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$AppMappingsPath = (Join-Path $PWD "CiscoUmbrella2EIA-AppMappings.csv"),
    
    [Parameter(HelpMessage = "Base directory for output files")]
    [ValidateScript({
        if (Test-Path $_ -PathType Container) { return $true }
        else { throw "Directory not found: $_" }
    })]
    [string]$OutputBasePath = $PWD,
    
    [Parameter(HelpMessage = "Policy name patterns to include. Supports wildcards. Case-insensitive.")]
    [string[]]$IncludePolicyName,
    
    [Parameter(HelpMessage = "Policy name patterns to exclude. Supports wildcards. Case-insensitive. Exclude wins over include.")]
    [string[]]$ExcludePolicyName,
    
    [Parameter(HelpMessage = "Enable verbose debug logging")]
    [switch]$EnableDebugLogging
)
```

---

## Internal Helper Functions

### Functions to Create (New)

#### 1. Test-PolicyNameFilter
**Purpose:** Test whether a source policy name passes the include/exclude filter.

**Parameters:**
- `PolicyName` (string, mandatory) — the source policy name to test
- `IncludePatterns` (string[]) — patterns to include (wildcards via `-like`)
- `ExcludePatterns` (string[]) — patterns to exclude (wildcards via `-like`)

**Logic:**
```powershell
function Test-PolicyNameFilter {
    param(
        [Parameter(Mandatory)]
        [string]$PolicyName,
        [string[]]$IncludePatterns,
        [string[]]$ExcludePatterns
    )

    # If include patterns specified, policy must match at least one
    if ($IncludePatterns.Count -gt 0) {
        $included = $false
        foreach ($pattern in $IncludePatterns) {
            if ($PolicyName -like $pattern) { $included = $true; break }
        }
        if (-not $included) { return $false }
    }

    # If exclude patterns specified, policy must not match any (exclude wins)
    if ($ExcludePatterns.Count -gt 0) {
        foreach ($pattern in $ExcludePatterns) {
            if ($PolicyName -like $pattern) { return $false }
        }
    }

    return $true
}
```

**Notes:**
- Case-insensitive by default (PowerShell `-like` is case-insensitive)
- Both exact names and wildcard patterns work (e.g., `"Default Policy"`, `"*Finance*"`, `"Corp-*"`)
- When neither include nor exclude is specified, all policies pass (returns `$true`)
- When both include and exclude match the same policy, exclude wins

#### 2. Split-ByCharacterLimit
**Purpose:** Split destination arrays by character limit without truncating entries (for FQDN only — NOT for webCategory)

**Logic:** Same as `Convert-ZIA2EIA.ps1` implementation. See that spec for details.

**Limit:** 300 characters (excluding field quotes, including semicolons)
**Applies to:** FQDN rules only (NOT webCategory)

#### 3. ConvertTo-DualFqdnEntries
**Purpose:** Convert a single domain into the dual FQDN entry pair (`domain.com` + `*.domain.com`)

**Logic:**
```powershell
function ConvertTo-DualFqdnEntries {
    param([string]$Domain)
    
    $cleanDomain = $Domain.Trim().TrimEnd('.')
    
    if ([string]::IsNullOrWhiteSpace($cleanDomain)) { return @() }
    
    # If already a wildcard, return as-is
    if ($cleanDomain.StartsWith('*.')) {
        return @($cleanDomain)
    }
    
    return @($cleanDomain, "*.$cleanDomain")
}
```

#### 3. Resolve-CategoryMapping
**Purpose:** Resolve an Umbrella category name to its GSA category mapping, distinguishing between missing rows and blank values.

**Returns:** Hashtable with `GSACategory`, `IsMapped` (boolean), `MappingType` ('Success', 'NoMappingRow', 'NoGSAValue'), and `LogMessage`

**Logic:**
```powershell
function Resolve-CategoryMapping {
    param(
        [string]$CategoryName,
        [hashtable]$CategoryMappingsHashtable
    )
    
    $mapping = $CategoryMappingsHashtable[$CategoryName.ToLower()]
    
    if ($null -eq $mapping) {
        # Category not found in mapping file
        return @{
            GSACategory = "UNMAPPED:$CategoryName"
            IsMapped = $false
            MappingType = 'NoMappingRow'
            LogMessage = "Category '$CategoryName' not found in mapping file"
        }
    }
    
    if ([string]::IsNullOrWhiteSpace($mapping.GSACategory)) {
        # Mapping row exists but no GSA category value
        return @{
            GSACategory = "UNMAPPED:$CategoryName"
            IsMapped = $false
            MappingType = 'NoGSAValue'
            LogMessage = "Category '$CategoryName' found in mapping file but GSACategory is empty"
        }
    }
    
    # Successfully mapped
    return @{
        GSACategory = $mapping.GSACategory
        IsMapped = $true
        MappingType = 'Success'
        LogMessage = "Category '$CategoryName' mapped to '$($mapping.GSACategory)'"
    }
}
```

#### 4. Resolve-AppMapping
**Purpose:** Look up an application in the app mappings CSV hashtable by UmbrellaAppId, returning mapping status, endpoints, and match type

**Returns:** Hashtable with `GSAAppName`, `Endpoints` (array), `MatchType` ('Exact', 'Approximate', 'NotInFile', 'NoMatch'), `IsMapped` (boolean), and `LogMessage`

**Logic:**
```powershell
function Resolve-AppMapping {
    param(
        [Parameter(Mandatory)]
        [int]$AppId,

        [Parameter(Mandatory)]
        [string]$AppName,

        [Parameter(Mandatory)]
        [hashtable]$AppMappingsHashtable
    )
    
    $mapping = $AppMappingsHashtable[$AppId]
    
    if ($null -eq $mapping) {
        # AppId not found in mapping file
        return @{
            GSAAppName = $null
            Endpoints  = @()
            MatchType  = 'NotInFile'
            IsMapped   = $false
            LogMessage = "Application '$AppName' (ID: $AppId) not found in app mapping file"
        }
    }
    
    if ([string]::IsNullOrWhiteSpace($mapping.GSAAppName) -or [string]::IsNullOrWhiteSpace($mapping.MatchType)) {
        # Row exists but no GSA mapping
        return @{
            GSAAppName = $null
            Endpoints  = @()
            MatchType  = 'NoMatch'
            IsMapped   = $false
            LogMessage = "Application '$AppName' (ID: $AppId) found in mapping file but has no GSA match"
        }
    }

    # Parse endpoints from semicolon-separated string
    $endpoints = @()
    if (-not [string]::IsNullOrWhiteSpace($mapping.GSAEndpoints)) {
        $endpoints = @($mapping.GSAEndpoints -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    }
    
    # Successfully mapped
    return @{
        GSAAppName = $mapping.GSAAppName
        Endpoints  = $endpoints
        MatchType  = $mapping.MatchType
        IsMapped   = $true
        LogMessage = "Application '$AppName' mapped to '$($mapping.GSAAppName)' ($($mapping.MatchType))"
    }
}
```

**Notes:**
- Lookup key is `[int]$AppId`, not application name — eliminates ambiguity from name-based matching
- `MatchType` comes directly from the CSV (`Exact` or `Approximate`), pre-determined by the user during template review
- Neither `Exact` nor `Approximate` matches set ReviewNeeded — the user has already confirmed the mapping in the CSV
- `NotInFile` means the AppId was not found in the CSV at all (app was added after template was generated)
- `NoMatch` means the row exists but `GSAAppName`/`MatchType` are blank (user confirmed no GSA equivalent)
- `Find-AppMapping.ps1` remains in the codebase as a shared internal function but is no longer called by this converter

#### 5. Get-IdentityScopeKey
**Purpose:** Generate a unique, consistent key for a set of identity IDs (sorted, joined)

**Logic:**
```powershell
function Get-IdentityScopeKey {
    param(
        [array]$IdentityIds,
        [hashtable]$IdentityLookup
    )
    
    $resolvedNames = @()
    foreach ($id in $IdentityIds) {
        $identity = $IdentityLookup[$id]
        if ($null -ne $identity) {
            $resolvedNames += $identity.label
        }
        else {
            $resolvedNames += "Unknown_$id"
        }
    }
    
    return ($resolvedNames | Sort-Object) -join ";"
}
```

### Functions to Reuse from Shared Internal Module

#### 1. Write-LogMessage
**Location:** `Migrate2GSA\internal\functions\Write-LogMessage.ps1`
**Status:** Available in shared module

#### 2. Export-DataToFile
**Location:** `Migrate2GSA\internal\functions\Export-DataToFile.ps1`
**Status:** Available in shared module

#### 3. Find-AppMapping
**Location:** `Migrate2GSA\internal\functions\Find-AppMapping.ps1`
**Status:** Available in shared module. Provides two-pass name-based lookup (exact then approximate substring match). No longer called by this converter — replaced by CSV-based `Resolve-AppMapping` internal helper (see helper function #4 above).

---

## Logging Specifications

### Log Levels and Usage

| Level | Usage | Examples |
|-------|-------|----------|
| INFO | Major milestones, counts, file operations | "Loaded 4 DNS policies", "Exported 42 policy rows" |
| WARN | Skipped items, unmapped categories, unmapped app IDs, bypassed settings | "Application 'Yandex Browser' (ID: 12345) not found in app mapping file", "Advise configuring Threat Intel" |
| ERROR | Fatal errors, missing files, invalid JSON | "File not found", "Invalid JSON format" |
| DEBUG | Individual item processing, detailed flow | "Processing web rule: Block - Yandex", "Skipped disabled rule" |

### Statistics to Track and Log

```powershell
$stats = @{
    # Policies
    DnsPoliciesProcessed = 0
    WebPoliciesProcessed = 0
    WebRulesProcessed = 0
    WebRulesSkippedDisabled = 0
    
    # Categories
    CategoriesMapped = 0
    UnmappedCategories_MissingInFile = 0
    UnmappedCategories_NoGSAValue = 0
    
    # Applications
    AppsMatchedExact = 0
    AppsMatchedApproximate = 0
    AppsUnmatched = 0
    
    # Destinations
    DestinationListsResolved = 0
    TotalFqdnEntries = 0
    
    # Identities
    IdentityScopesAll = 0
    IdentityScopesSpecific = 0
    UniqueIdentitySets = 0
    
    # Outputs
    PolicyRowsCreated = 0
    PoliciesMergedDedup = 0
    SecurityProfilesCreated = 0
    
    # Splitting
    RulesSplitForCharLimit = 0
}
```

---

## Error Handling

### Fatal Errors (Stop Processing)

| Error | Condition | Action |
|-------|-----------|--------|
| Neither policy file provided | Neither `DnsPoliciesPath` nor `WebPoliciesPath` specified | Throw error, exit |
| Missing input file | Required file not found (includes conditional requirements: `category_settings.json` when DNS provided, `AppMappings` when Web provided) | Throw error, exit |
| Invalid JSON | JSON parse error | Throw error, exit |
| Empty policies | All provided policy files contain no policies | Throw error, exit |
| Invalid output path | Directory doesn't exist | Throw error, exit |

### Non-Fatal Errors (Log and Continue)

| Error | Condition | Action |
|-------|-----------|--------|
| Category missing from mapping file | Category name not found in CSV | WARN, use `UNMAPPED:CategoryName` placeholder, flag for review |
| Category has no GSA value | Row exists in CSV but `GSACategory` is blank | WARN, use `UNMAPPED:CategoryName` placeholder, flag for review |
| App not in mapping file | AppId not found in CSV | WARN, use `UNMAPPED:AppName` placeholder, flag for review |
| App has no GSA match | Row exists in CSV but `GSAAppName`/`MatchType` blank | WARN, use `UNMAPPED:AppName` placeholder, flag for review |
| App mapped but no endpoints | Row has GSAAppName but `GSAEndpoints` empty | WARN, use `UNMAPPED:AppName` placeholder, flag for review |
| Destination list empty | No domain entries | WARN, skip list |
| Destination list not found | ID not in `destination_lists.json` | WARN, skip |
| Identity not in extradata | ID not resolvable | WARN, use placeholder |
| Disabled web rule | `ruleIsEnabled = false` | DEBUG, skip |
| Warn/isolate action | No EIA equivalent | WARN, convert to Block, flag for review |

---

## Sample Output (Fictional Examples)

### Policies CSV

```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,ReviewNeeded,ReviewDetails,Provision
Default-Categories-Block,WebContentFiltering,Block,"Merged category blocks from DNS and web policies",webCategory,"Gambling;HackingAndCracking;Nudity;Drugs;Weapons",WebCategories,No,,yes
Default-Destinations-Block,WebContentFiltering,Block,"Merged FQDN blocks from DNS and web policies",FQDN,"malicious-site.example;*.malicious-site.example;bad-domain.example;*.bad-domain.example",FQDNs,No,,yes
Default-Destinations-Allow,WebContentFiltering,Allow,"Merged FQDN allows from DNS and web policies",FQDN,"trusted-vendor.example;*.trusted-vendor.example;safe-tools.example;*.safe-tools.example",FQDNs,No,,yes
Web-BlockSearchEngine-Apps-Block,WebContentFiltering,Block,"Converted from Umbrella web rule: Block - SearchEngine",FQDN,"searchengine.example;*.searchengine.example;search-mail.example;*.search-mail.example",FQDNs,No,,yes
Web-AllowCloudStorage-Apps-Allow,WebContentFiltering,Allow,"Converted from Umbrella web rule: Allow - CloudStorage",FQDN,"cloudstorage.example;*.cloudstorage.example;cloudstorageapi.example;*.cloudstorageapi.example",FQDNs,No,,yes
Web-AllowFileShare-Apps-Allow,WebContentFiltering,Allow,"Converted from Umbrella web rule: Allow - FileShare",FQDN,"UNMAPPED:FileShare Pro",FQDNs,Yes,"Application 'FileShare Pro' (ID: 99999) found in mapping file but has no GSA match",no
```

### Security Profiles CSV

```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Override-SG-Cloud-Storage-Users,1000,"Web-AllowCloudStorage-Apps-Allow:100;Web-AllowFileShare-Apps-Allow:200",CA-EIA-Override-SG-Cloud-Storage-Users,,SG-Cloud-Storage-Users,yes
Override-SG-Marketing-Social,1100,"Web-AllowSocialMedia-Apps-Allow:100",CA-EIA-Override-SG-Marketing-Social,,SG-Marketing-Social,yes
Default-CiscoUmbrella,50000,"Default-Categories-Block:100;Default-Destinations-Block:200;Default-Destinations-Allow:300;Web-BlockSearchEngine-Apps-Block:400",CA-EIA-Default-CiscoUmbrella,,All Internet Access Users,yes
```

---

## Code Organization

### Region Structure

```powershell
function Convert-CiscoUmbrella2EIA {
    <# .SYNOPSIS, .DESCRIPTION, .PARAMETER, .EXAMPLE, .NOTES #>
    
    [CmdletBinding()]
    param(...)
    
    Set-StrictMode -Version Latest
    
    #region Helper Functions
    # Split-ByCharacterLimit
    # ConvertTo-DualFqdnEntries
    # Resolve-CategoryMapping
    # Get-IdentityScopeKey
    #endregion
    
    #region Initialization
    # Logging setup
    # Variable initialization
    # Runtime validation: at least one of DnsPoliciesPath or WebPoliciesPath must be provided
    #endregion
    
    #region Phase 1: Data Loading
    # Load JSON files (conditionally based on which policy paths are provided)
    # Build lookup tables
    #endregion
    
    #region Phase 2: DNS Policy Processing (conditional — only if DnsPoliciesPath provided)
    # Process category settings
    # Process domain lists
    # Log warnings for bypassed settings
    #endregion
    
    #region Phase 3: Web Policy Processing (conditional — only if WebPoliciesPath provided)
    # Build extradata lookups per web policy
    # Process enabled rules
    # Convert application, destination, category conditions
    # Route to identity scope buckets
    #endregion
    
    #region Phase 4: Deduplication and Merging
    # Merge category rules by scope and action
    # Merge FQDN rules by scope and action
    #endregion
    
    #region Phase 5: Security Profile Assembly
    # Create Default Security Profile
    # Create Override Security Profiles
    #endregion
    
    #region Phase 6: Export and Summary
    # Export CSVs
    # Generate statistics
    # Display summary
    #endregion
}
```

---

## Implementation Checklist

### Phase 1: Foundation
- [ ] Create function skeleton with parameters (DnsPoliciesPath and WebPoliciesPath optional, at least one required)
- [ ] Implement runtime validation: at least one of DnsPoliciesPath or WebPoliciesPath must be provided
- [ ] Implement logging initialization
- [ ] Create conditional data loading logic (DNS-related files only when DNS provided, Web-related files only when Web provided)
- [ ] Add JSON validation
- [ ] Build lookup tables (destination lists, category settings when DNS provided, category mappings, app mappings when Web provided)

### Phase 2: Helper Functions
- [ ] Implement Split-ByCharacterLimit (reuse from ZIA2EIA)
- [ ] Implement ConvertTo-DualFqdnEntries
- [ ] Implement Resolve-CategoryMapping (NoMappingRow vs NoGSAValue, UNMAPPED: prefix)
- [x] ~~Create Find-AppMapping~~ — Already exists as shared internal function. No longer called by this converter; replaced by internal `Resolve-AppMapping` helper
- [ ] Implement Resolve-AppMapping (CSV lookup by UmbrellaAppId, NotInFile vs NoMatch, UNMAPPED: prefix)
- [ ] Implement Get-IdentityScopeKey

### Phase 3: DNS Policy Processing (conditional — only if DnsPoliciesPath provided)
- [ ] Resolve category settings via category_settings.json
- [ ] Map categories via category mapping file
- [ ] Resolve domain lists via destination_lists.json
- [ ] Apply dual FQDN pattern
- [ ] Log warnings for bypassed settings

### Phase 4: Web Policy Processing (conditional — only if WebPoliciesPath provided)
- [ ] Build per-policy extradata lookup tables
- [ ] Process enabled rules, skip disabled
- [ ] Parse rule conditions (identity, application, destination, category)
- [ ] Convert application conditions via app mapping CSV (Resolve-AppMapping by UmbrellaAppId)
- [ ] Convert destination list conditions
- [ ] Convert content category conditions
- [ ] Route policies to identity scope buckets
- [ ] Handle warn/isolate action mapping

### Phase 5: Deduplication
- [ ] Merge webCategory rules by scope and action
- [ ] Merge FQDN rules by scope and action
- [ ] Re-split merged FQDN rules by character limit

### Phase 6: Security Profile Assembly
- [ ] Create Default Security Profile (priority 50000)
- [ ] Create Override Security Profiles (priority 1000+, increment 100)
- [ ] Build SecurityProfileLinks with priority numbering
- [ ] Populate EntraGroups/EntraUsers from resolved identities

### Phase 7: Export
- [ ] Implement Policies CSV export
- [ ] Implement Security Profiles CSV export
- [ ] Implement summary statistics

### Phase 8: Testing
- [ ] Create sample input files with fictional data
- [ ] Create expected output files
- [ ] Test with real-world data
- [ ] Validate all edge cases
- [ ] Performance testing

---

## Known Limitations

1. **DNS policy identity assignment**: Not available in export. All DNS policies are assumed to apply to all users.
2. **Web policy-level identity assignment**: Not available in export. Only rule-level identity scoping is used.
3. **Application controls**: Converted to FQDN-based rules using a mapping file. Apps not in the mapping file are flagged for review. This is a lossy conversion — per-application granularity is not available in EIA.
4. **Warn/Isolate actions**: No EIA equivalent. Converted to Block with review flag.
5. **File inspection settings**: Not converted. User advised to configure File Policies in EIA.
6. **Security settings (threat protection)**: Not converted. User advised to configure Threat Intelligence policies in EIA.
7. **TLS inspection bypass**: Not converted. User advised to review and configure TLS Inspection Policy in EIA.
8. **Tenant restrictions**: Not converted (silently bypassed).
9. **Firewall rules**: Not converted (out of scope for web content filtering).
10. **Character limits**: 300-character limit per FQDN RuleDestinations field is hard-coded.
11. **Category mapping completeness**: Depends on the quality of the user-provided category mapping file.
12. **App mapping completeness**: Depends on the quality of the user-populated app mapping CSV. The `Export-UmbrellaAppMappingTemplate` function generates the initial template; users must populate `GSAAppName`, `MatchType`, and `GSAEndpoints` columns.

---

## Future Enhancements

1. Add support for TLS Inspection policy conversion (from `settingGroupBypassInspectionGroup`)
2. Add support for converting Umbrella `policySetting.safeSearch` to EIA equivalent
3. Add filtering parameters (specific DNS/web policy names)
4. Add WhatIf/dry-run support
5. Add validation mode to check mapping file completeness before conversion
6. Add parallel processing for large web policy rulesets
7. Add validation mode to check mapping file completeness before conversion

---

## References

### Cisco Umbrella Documentation
- Umbrella Policy Management: https://docs.umbrella.com/umbrella-user-guide/docs/add-a-policy
- Umbrella API: https://developer.cisco.com/docs/cloud-security/

### Related Functions
- Convert-ZIA2EIA.ps1: Template for design patterns
- Start-EntraInternetAccessProvisioning.ps1: Target provisioning function
- Write-LogMessage.ps1: Shared logging function

### Microsoft Documentation
- Entra Internet Access: https://learn.microsoft.com/en-us/entra/global-secure-access/
- Web Content Filtering: https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-web-content-filtering

---

**End of Specification**
