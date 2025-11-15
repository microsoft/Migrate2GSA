# Convert-NSWG2EIA.ps1 Specification

## Document Information
- **Specification Version:** 1.0
- **Date:** 2025-11-12
- **Status:** Final
- **Target Module:** Migrate2GSA
- **Function Name:** Convert-NSWG2EIA
- **Author:** Andres Canello
---

## Overview

This PowerShell function converts Netskope Secure Web Gateway (NSWG) Real-time Protection policies and custom categories to Microsoft Entra Internet Access (EIA) format. The function processes URL filtering policies, custom web categories, URL lists, and predefined category mappings to generate CSV files ready for import into EIA.

### Purpose
- Transform Netskope Real-time Protection policies to EIA security profiles
- Convert Netskope custom categories to EIA web content filtering policies
- Map Netskope predefined web categories to GSA (Global Secure Access) web categories
- Aggregate policies by user/group assignments for optimal security profile creation
- Generate import-ready CSV files for EIA configuration

### Design Alignment
This function follows the same architectural patterns as `Convert-ZIA2EIA.ps1`:
- Single function with internal helper functions
- Phased processing approach (Load → Process → Export)
- Comprehensive logging using `Write-LogMessage`
- Region-based code organization
- CSV export using shared utilities

---

## Policy and Rule Naming Conventions

This section describes the structure and naming conventions used when converting Netskope configurations to EIA policies and rules.

### Netskope Structure

**Netskope Real-time Protection Policies:**
- A Real-time Protection policy defines access control rules for web traffic
- Each policy has a `ruleName`, `user` assignment, `application` targets, and an `action`
- Policies reference applications, predefined categories, or custom categories

**Netskope Custom Categories:**
- Custom categories group destinations (URL lists and/or predefined categories)
- Can have `inclusion` arrays (processed destinations)
- Can have `exclusion` arrays (excluded destinations)
- Can reference predefined Netskope categories via `categories` array

**Netskope URL Lists:**
- Collections of URLs/FQDNs with a `type` field
- Type "exact": Plain URLs/FQDNs (process normally)
- Type "regex": Regular expressions (flag for review)

**Netskope Predefined Categories:**
- Built-in web categories (e.g., "Social", "Cloud Storage")
- Must be mapped to GSA categories using mapping file

### EIA Structure

**EIA Web Content Filtering Policies:**
- A web content filtering policy is the primary building block for traffic filtering in EIA
- Each policy has ONE action (Allow or Block) defined at the policy level
- Policies contain one or more rules that define destinations to match
- Rules are grouped by destination type (FQDN, URL, ipAddress, webCategory)

**EIA Rule Types:**
- `FQDN` - Fully qualified domain names (e.g., `*.example.com`, `site.com`)
- `URL` - URLs with paths or specific patterns (e.g., `*.domain.com/path`)
- `ipAddress` - IP addresses (IPv4 only, no CIDR ranges, no ports) - **Not yet supported in EIA**
- `webCategory` - GSA predefined web categories (e.g., `SocialNetworking`, `Gambling`)

**EIA Security Profiles:**
- Security profiles aggregate multiple web content filtering policies
- Assigned to users and/or groups via Conditional Access policies
- Each profile has a priority (lower number = higher priority)
- Security profiles link to web content filtering policies via PolicyLinks field

**EIA Conditional Access Policies:**
- Conditional Access (CA) policies assign security profiles to users/groups
- Define assignment scope (users, groups, "All users")
- Link to security profile for enforcement
- This function generates CSV files that reference CA assignment via EntraUsers/EntraGroups fields

### Conversion Logic

**URL List Conversion:**
- Each URL list creates TWO policies:
  - `"[URLListName]-Allow"` - For Allow actions
  - `"[URLListName]-Block"` - For Block actions
- URL lists referenced in custom categories are tracked for later linking
- Destinations are classified and grouped by type (FQDN, URL, ipAddress)
- Regex URL lists create policies flagged with ReviewNeeded=Yes, Provision=No, PolicyAction=Block
- Unreferenced URL list policies are cleaned up after aggregation

**Custom Category Conversion:**
- Custom categories create policies for predefined categories only:
  - `"[CategoryName]-WebCategories-Allow"` - For RT policies with Allow action
  - `"[CategoryName]-WebCategories-Block"` - For RT policies with Block action
- Each policy contains a single webCategory rule with all mapped GSA categories
- Predefined categories are always treated as inclusions
- Custom categories without predefined categories (only URL lists) create no custom category policies

**Linking Logic:**
- RT policies link to URL list policies based on:
  - Inclusion + Allow action → URLList-Allow
  - Inclusion + Block action → URLList-Block
  - Exclusion + Allow action → URLList-Block (INVERSE)
  - Exclusion + Block action → URLList-Allow (INVERSE)
- RT policies link to custom category webCategory policies based on RT action:
  - Allow action → CategoryName-WebCategories-Allow
  - Block action → CategoryName-WebCategories-Block

**Real-time Protection Policy Conversion:**
- Policies referencing custom categories → link to appropriate custom category policies based on action
- Policies referencing predefined categories → create "[RuleName]-WebCategories-[Action]" policy (using RT policy's ruleName)
- Policies referencing applications → flagged for review (no direct mapping)
- Multiple policies assigned to same users/groups → aggregated into single security profile

**Policy Naming Conventions:**
- URL list policies: `[URLListName]-Allow` or `[URLListName]-Block`
  - Example: `SSL Bypass URLs-Allow`, `Whitelist URLs-Block`
- Custom category predefined category policies: `[CategoryName]-WebCategories-Allow` or `[CategoryName]-WebCategories-Block`
  - Example: `Potentially malicious sites-WebCategories-Block`
- RT policy predefined category policies: `[RuleName]-WebCategories-[Action]`
  - Example: `Block Advertisements-WebCategories-Block`
- Application policies: `[RuleName]-Application-[Action]` (with ReviewNeeded=Yes)

**Rule Naming Conventions:**
- FQDN rules: Base domain name (e.g., `example.com`, `example.com-2`)
- URL rules: Base domain name (e.g., `contoso.com`, `contoso.com-2`)
- IP address rules: `IPs`, `IPs-2`, `IPs-3`
- Web category rules: `WebCategories` (no splitting)

**Security Profile Naming Conventions:**
- All users: `SecurityProfile-All-Users`
- Specific user/group sets: `SecurityProfile-001`, `SecurityProfile-002`, etc.

### Mapping Summary

| Netskope Element | Converts To | EIA Element | Notes |
|------------------|-------------|-------------|-------|
| URL List (type: exact) | → | 2 Web Content Filtering Policies | PolicyName: "URLListName-Allow" and "URLListName-Block" |
| URL List (type: regex) | → | 2 Web Content Filtering Policies (flagged) | ReviewNeeded=Yes, Provision=No, PolicyAction=Block |
| Custom Category (predefined categories only) | → | 2 Web Content Filtering Policies | PolicyName: "CategoryName-WebCategories-Allow" and "CategoryName-WebCategories-Block" |
| Custom Category (URL list references) | → | Tracked for linking | RT policy links to referenced URL list policies |
| Predefined Category in RT Policy | → | Web Content Filtering Policy | PolicyName: "RuleName-WebCategories-[Action]" |
| Application Object | → | Web Content Filtering Policy | Flagged for review (ReviewNeeded=Yes) |
| Real-time Protection Policies (same users) | → | Single Security Profile | Aggregated with deduplicated policy links (Allow policies first, then Block) |

---

## Input Files

### 1. real_time_protection_policies.json
**Source:** Netskope API/Export  
**Required:** Yes  
**Default Path:** None (must be provided via parameter)

#### Description
Contains all Real-time Protection policies configured in Netskope, including policy assignments, actions, and application/category references.

#### Key Fields to Process

| Field | Type | Description | Processing Notes |
|-------|------|-------------|------------------|
| `ruleName` | string | Policy name | Maps to SecurityProfileName or used in policy naming |
| `user` | string | Comma-separated users/groups | Parse emails and X500 group paths |
| `application` | string | Comma-separated app/category names | Parse and lookup in custom categories, mappings, or flag as app |
| `action` | string | Action to take | "Block*", "Allow", "Alert", "User Alert*" |
| `status` | string | Policy state | Only process "Enabled " (note trailing space) |
| `accessMethod` | string | Access method | Skip if "Client" (NPA policies) |
| `app_tags` | string | Application tags filter | Skip if not "Any" (app tag filtering not supported in EIA) |
| `groupOrder` | string | Policy priority | Convert to number, multiply by 10 for SecurityProfilePriority |
| `groupName` | string | Policy group | Log for reference |
| `description` | string | Policy description | Maps to Security Profile Description |

#### Processing Rules

1. **State Filtering:** Only process policies where `status` = "Enabled " (with trailing space)
   - Log count of disabled policies at INFO level
   - Log names of disabled policies at DEBUG level

2. **NPA Policy Filtering:** Skip policies where `accessMethod` = "Client"
   - These are Netskope Private Access policies, not web policies
   - Log count at INFO level

3. **App Tag Filtering:** Skip policies where `app_tags` is not "Any"
   - Log names of skipped policies at INFO level

4. **User Field Parsing:**
   - Split by comma and trim whitespace
   - Identify emails (contains @ but not /)
   - Identify X500 group paths (contains /)
   - Extract group name from X500 path (last segment after /)
   - Handle "All" → use placeholder "Replace_with_All_IA_Users_Group"

5. **Application Field Parsing:**
   - Split by comma and trim whitespace
   - For each entry, perform lookup:
     1. Check if it's a custom category name
     2. Check if it's a predefined category (in mapping file)
     3. Otherwise, treat as application object

6. **Action Mapping:**
   - "Allow" → PolicyAction "Allow"
   - "Block*" (any block variant) → PolicyAction "Block"
   - "Alert" → PolicyAction "Block" + ReviewNeeded = Yes
   - "User Alert*" → PolicyAction "Block" + ReviewNeeded = Yes

### 2. url_lists.json
**Source:** Netskope API/Export  
**Required:** Yes  
**Default Path:** None (must be provided via parameter)

#### Description
Contains all URL lists with their destinations and type information.

#### Key Fields to Process

| Field | Type | Description | Processing Notes |
|-------|------|-------------|------------------|
| `id` | integer | URL list ID | Used for lookups from custom categories |
| `name` | string | URL list name | For logging and reference |
| `data.urls` | array | Array of URLs/FQDNs/IPs | Main destination list |
| `data.type` | string | URL list type | "exact" or "regex" |

#### Processing Rules

1. **Type Handling:**
   - Type "exact": Process destinations normally
   - Type "regex": Log warning, flag entire URL list for review, skip processing

2. **Destination Processing:**
   - Clean destinations using `ConvertTo-CleanDestination`
   - Classify as FQDN, URL, or ipAddress
   - Deduplicate case-insensitively
   - Group by base domain (for FQDNs and URLs)
   - Split by 300-character limit

### 3. custom_categories.json
**Source:** Netskope API/Export  
**Required:** Yes  
**Default Path:** None (must be provided via parameter)

#### Description
Contains all custom web categories including inclusions, exclusions, and predefined category references.

#### Schema Example

```json
{
  "status": "success",
  "data": {
    "totalCount": 52,
    "data": [
      {
        "id": "10052",
        "name": "Custom Category Name",
        "data": {
          "inclusion": [
            {"id": "4", "name": "SSL Bypass URLs"}
          ],
          "exclusion": [
            {"id": "5", "name": "Blacklist URLs"}
          ],
          "categories": [
            {"id": "523", "name": "Chat, IM & other communication"}
          ]
        }
      }
    ]
  }
}
```

#### Key Fields to Process

| Field | Type | Description | Processing Notes |
|-------|------|-------------|------------------|
| `id` | string | Category ID | Unique identifier |
| `name` | string | Category name | Used for policy naming and lookups |
| `data.inclusion` | array | URL List references to include | Resolve via URL Lists lookup |
| `data.exclusion` | array | URL List references to exclude | Resolve via URL Lists lookup |
| `data.categories` | array | Predefined category references | Map using NSWG2EIA-CategoryMappings.csv |

#### Processing Rules

1. **Inclusion Processing:**
   - Collect URL list IDs from `inclusion` array for tracking
   - Track references to URL list policies created in Phase 2.1
   - RT policies will link to appropriate URL list policies based on action

2. **Exclusion Processing:**
   - Collect URL list IDs from `exclusion` array for tracking
   - Track references to URL list policies created in Phase 2.1
   - RT policies will link to opposite URL list policies (INVERSE action)

3. **Predefined Categories:**
   - Process predefined categories from `categories` array
   - Map each category using mapping file
   - Create TWO web content filtering policies (only if predefined categories exist):
     - `"CategoryName-WebCategories-Allow"` - For RT Allow actions
     - `"CategoryName-WebCategories-Block"` - For RT Block actions
   - Each policy contains a single webCategory rule with all mapped GSA categories

### 4. NSWG2EIA-CategoryMappings.csv
**Source:** Manual configuration file (maintained by user)  
**Required:** Yes  
**Default Path:** None (must be provided via parameter)

#### Description
Provides mapping between Netskope predefined web categories and Microsoft GSA (Global Secure Access) web categories.

#### Format
CSV file with header row and two columns:

```csv
NSWGCategory,GSACategory
Social,SocialNetworking
Cloud Storage,CloudStorage
Streaming Media,StreamingMedia
Business and Economy,Business
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `NSWGCategory` | string | Yes | Netskope category name (matches `application` or `categories[].name`) |
| `GSACategory` | string | Yes | Target GSA category name (leave empty or use "Unmapped" for unmapped categories) |

#### Processing Rules

1. **File Loading:**
   - Import CSV file using `Import-Csv`
   - Build hashtable with `NSWGCategory` as key

2. **Lookup:** For each predefined category reference, find matching `NSWGCategory`

3. **Unmapped Categories:**
   - If `GSACategory` is null, blank, or "Unmapped": use placeholder format
   - Placeholder: `"UNMAPPED:[NSWGCategory]"`
   - Set `ReviewNeeded` = "Yes" in output

4. **Mapped Categories:**
   - Use the `GSACategory` value
   - Set `ReviewNeeded` = "No" in output

---

## Output Files

All output files are created in `$OutputBasePath` with consistent timestamp prefix.

### 1. Policies CSV
**Filename:** `[yyyyMMdd_HHmmss]_EIA_Policies.csv`

#### Description
Contains all web content filtering policies including those from custom categories and real-time protection policies.

#### Fields

| Field | Description | Example | Notes |
|-------|-------------|---------|-------|
| PolicyName | Policy name | "Whitelist URLs-Allow" | Unique identifier |
| PolicyType | Type of policy | "WebContentFiltering" | Currently only "WebContentFiltering" supported |
| PolicyAction | Allow or Block | "Block", "Allow" | One action per policy in EIA |
| Description | Policy description | "Custom category for whitelisted sites" | From category or rule |
| RuleType | Type of destination | "FQDN", "URL", "webCategory", "ipAddress" | One type per row |
| RuleDestinations | Semicolon-separated list | "*.example.com;site.com;other.com" | Max 300 chars (except webCategory) |
| RuleName | Sub-rule identifier | "example.com", "URLs2", "WebCategories" | For grouping/splitting |
| ReviewNeeded | Manual review flag | "Yes", "No" | "Yes" if regex, unmapped categories, or application |
| ReviewDetails | Reason for review | "URL List contains regex patterns; Application object requires manual mapping" | Semicolon-separated reasons |
| Provision | Provisioning flag | "Yes", "No" | "No" if ReviewNeeded is "Yes" |

#### PolicyName Format

**Custom Categories:**
- Inclusion policies: `[CategoryName]-Inclusions-Allow` and `[CategoryName]-Inclusions-Block`
- Exclusion policies: `[CategoryName]-Exclusions-Allow` and `[CategoryName]-Exclusions-Block` (only if exclusions exist)
- Note: RT policy action determines which policies are linked (exclusions receive inverse action)

**Real-time Protection Policies:**
- Predefined categories: `[RuleName]-WebCategories-[Action]`
  - Example: `Block Advertisements-WebCategories-Block`
- Applications: `[RuleName]-Application-[Action]`
  - Example: `Allow GitHub Copilot-Application-Allow`
  - Always has ReviewNeeded=Yes

#### RuleType Values
- `FQDN` - Fully qualified domain names
- `URL` - URLs with paths or wildcards in domain
- `webCategory` - GSA web category references
- `ipAddress` - IP addresses (not yet supported in EIA - flagged for review)

#### RuleDestinations Field
- Semicolon-separated list of destinations
- Character limit: 300 characters (not including quotes) for FQDN, URL, and ipAddress types
- **Web categories (`webCategory` type) have NO character limit** and are never split
- If FQDN/URL/IP limit exceeded, split into multiple rules with "-2", "-3" suffix

#### Provision Field
- **Default:** "Yes" (entry is ready for provisioning)
- **Exception:** "No" when `ReviewNeeded = "Yes"`
  - Regex URL lists require manual review
  - Unmapped categories require manual mapping
  - Application objects require manual mapping
  - Alert/User Alert actions require review of coaching templates
  - IP addresses not yet supported in EIA

### 2. Security Profiles CSV
**Filename:** `[yyyyMMdd_HHmmss]_EIA_SecurityProfiles.csv`

#### Description
Contains security profile definitions aggregated by user/group assignments. Multiple real-time protection policies assigned to the same users/groups are combined into a single security profile.

#### Fields

| Field | Description | Example | Notes |
|-------|-------------|---------|-------|
| SecurityProfileName | Security profile name | "SecurityProfile-All-Users" | "SecurityProfile-All-Users" for all users, "SecurityProfile-NNN" for others |
| SecurityProfilePriority | Rule priority | "20" | Lowest `groupOrder × 10` from aggregated rules |
| EntraGroups | Semicolon-separated groups | "APP Finance Users;APP HR Users" | Parsed from X500 paths |
| EntraUsers | Semicolon-separated emails | "user1@domain.com;user2@domain.com" | Parsed from user field |
| PolicyLinks | Semicolon-separated policy names | "Whitelist URLs-Allow;Online Ads-Block" | References to policies |
| Description | Profile description | "Aggregated from 5 real-time protection policies" | Auto-generated |
| Provision | Provisioning flag | "Yes", "No" | "Yes" for auto-provision |
| Notes | Aggregated rule names | "Block Advertisements, Whitelist URLs, Block Malware" | Comma-separated list of real-time policy names |

#### SecurityProfileName Format
- **All users:** `SecurityProfile-All-Users`
- **Specific assignments:** `SecurityProfile-001`, `SecurityProfile-002`, etc. (zero-padded to 3 digits)

#### SecurityProfilePriority Calculation
1. For each aggregated real-time protection policy, calculate: `groupOrder × 10`
2. Use the **lowest** (highest priority) value from all aggregated policies
3. Validate uniqueness across all security profiles
4. If conflict detected:
   - Add 1 to subsequent occurrence: `SecurityProfilePriority + 1`
   - Continue until unique value found
   - Log conflict resolution at INFO level

#### EntraUsers Field
- Parse user field, extract emails (contains @ but not /)
- Join multiple users with semicolon separator
- Empty if no valid users

#### EntraGroups Field
- Parse user field, extract X500 group paths (contains /)
- Extract last segment (group name) from each path
- Join multiple groups with semicolon separator
- If no users and no groups: "Replace_with_All_IA_Users_Group"

#### PolicyLinks Field
- Semicolon-separated list of PolicyName values
- During aggregation (Phase 3.3): stored without priority suffixes (e.g., `Whitelist URLs-Allow;Online Ads-Block`)
- During CSV export (Phase 4.2): priority suffixes added in format `PolicyName:Priority` (e.g., `Whitelist URLs-Allow:100;Online Ads-Block:200`)
- Priorities start at 100 and increment by 100 for each policy
- Policy order determines priority assignment (lower number = higher priority):
  1. Allow policies (alphabetically sorted)
  2. Block policies (alphabetically sorted)
- Includes custom category policies (with -Allow or -Block based on rule action)
- Includes predefined category policies ([RuleName]-WebCategories-[Action], where RuleName is from RT policy)
- Includes application policies ([RuleName]-Application-[Action], where RuleName is from RT policy)
- Example in CSV: `Whitelist URLs-Allow:100;Custom Category-Allow:200;Online Ads-Block:300;GitHub Copilot-Application-Block:400`

#### Notes Field
- Comma-separated list of all real-time protection policy `ruleName` values that were aggregated
- Example: `Block Advertisements, Whitelist URLs, Block Malware Download and Upload`
- Used for traceability and auditing

### 3. Log File
**Filename:** `[yyyyMMdd_HHmmss]_Convert-NSWG2EIA.log`  
**Location:** Same directory as output CSV files (`$OutputBasePath`)

#### Description
Comprehensive log file created by `Write-LogMessage` internal function with all processing details, warnings, and statistics.

---

## Processing Logic

### Phase 1: Data Loading and Validation

#### 1.1 Initialize Logging
```powershell
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath = Join-Path $OutputBasePath "${timestamp}_Convert-NSWG2EIA.log"
```

#### 1.2 Load Input Files
1. Load `real_time_protection_policies.json`
   - Validate JSON structure
   - Fatal error if file missing or invalid
2. Load `url_lists.json`
   - Validate JSON structure
   - Fatal error if file missing or invalid
3. Load `custom_categories.json`
   - Validate JSON structure (handle nested data.data structure)
   - Fatal error if file missing or invalid
4. Load `NSWG2EIA-CategoryMappings.csv`
   - Validate CSV structure
   - Fatal error if file missing or invalid

#### 1.3 Build Lookup Tables

```powershell
# Category mappings for predefined categories
$categoryMappingsHashtable = @{}
foreach ($mapping in $categoryMappings) {
    $categoryMappingsHashtable[$mapping.NSWGCategory] = $mapping
}

# URL Lists for quick lookup
$urlListsHashtable = @{}
foreach ($urlList in $urlLists) {
    $urlListsHashtable[$urlList.id] = $urlList
}

# Custom categories for quick lookup by name
$customCategoriesByName = @{}
foreach ($category in $customCategories) {
    $customCategoriesByName[$category.name] = $category
}

# Custom category policies tracking (populated in Phase 2)
$customCategoryPoliciesHashtable = @{}

# Collections for output
$policies = [System.Collections.ArrayList]::new()
$securityProfiles = [System.Collections.ArrayList]::new()
```

### Phase 2: URL List and Custom Category Processing

#### 2.1 Process URL Lists

```powershell
foreach ($urlList in $urlLists) {
    Write-LogMessage "Processing URL list: $($urlList.name)" -Level "DEBUG"
    
    # Check for regex type
    $hasRegex = $false
    $reviewDetails = ""
    if ($urlList.data.type -eq "regex") {
        $hasRegex = $true
        $reviewDetails = "URL List contains regex patterns"
        Write-LogMessage "URL List '$($urlList.name)' is regex type - will flag for review" -Level "WARN"
    }
    
    # Collect and deduplicate destinations
    $uniqueDestinations = @($urlList.data.urls | Group-Object -Property { $_.ToLower() } | ForEach-Object { $_.Group[0] })
    
    # Clean destinations
    $cleanedDestinations = @()
    foreach ($dest in $uniqueDestinations) {
        $cleaned = ConvertTo-CleanDestination -Destination $dest
        if ($null -ne $cleaned) {
            $cleanedDestinations += $cleaned
        }
    }
    
    # Classify destinations
    $classified = @{
        'FQDN' = @()
        'URL' = @()
        'ipAddress' = @()
    }
    
    foreach ($dest in $cleanedDestinations) {
        $destType = Get-DestinationType -Destination $dest
        if ($destType -eq 'ipv4') {
            $classified['ipAddress'] += $dest
        } elseif ($destType -eq 'ipv6') {
            Write-LogMessage "IPv6 address not supported: $dest" -Level "WARN"
        } elseif ($destType -eq 'URL') {
            $classified['URL'] += $dest
        } else {
            $classified['FQDN'] += $dest
        }
    }
    
    # Create BOTH Allow and Block policies for this URL list
    foreach ($action in @('Allow', 'Block')) {
        $policyName = "$($urlList.name)-$action"
        
        # For regex lists, use Block action and flag for review
        $actualAction = if ($hasRegex) { 'Block' } else { $action }
        
        # Process each destination type
        foreach ($destType in @('FQDN', 'URL', 'ipAddress')) {
            if ($classified[$destType].Count -eq 0) { continue }
            
            # Group by base domain (for FQDN and URL)
            if ($destType -in @('FQDN', 'URL')) {
                $grouped = $classified[$destType] | Group-Object -Property { Get-BaseDomain -Destination $_ }
                
                foreach ($group in $grouped) {
                    $baseDomain = $group.Name
                    $destinations = $group.Group
                    
                    # Split by character limit
                    $splits = Split-ByCharacterLimit -Destinations $destinations -Limit 300
                    
                    for ($i = 0; $i -lt $splits.Count; $i++) {
                        $ruleName = if ($i -eq 0) { $baseDomain } else { "$baseDomain-$($i + 1)" }
                        
                        $policyEntry = [PSCustomObject]@{
                            PolicyName = $policyName
                            PolicyType = "WebContentFiltering"
                            PolicyAction = $actualAction
                            Description = "URL List: $($urlList.name)"
                            RuleType = $destType
                            RuleDestinations = ($splits[$i] -join ';')
                            RuleName = $ruleName
                            ReviewNeeded = if ($hasRegex) { "Yes" } else { "No" }
                            ReviewDetails = $reviewDetails
                            Provision = if ($hasRegex) { "No" } else { "Yes" }
                        }
                        [void]$policies.Add($policyEntry)
                    }
                }
            } else {
                # IP addresses - split by character limit
                $splits = Split-ByCharacterLimit -Destinations $classified[$destType] -Limit 300
                
                for ($i = 0; $i -lt $splits.Count; $i++) {
                    $ruleName = if ($i -eq 0) { "IPs" } else { "IPs-$($i + 1)" }
                    
                    # IP addresses are not yet supported in EIA
                    $ipReviewDetails = if ($hasRegex) { "$reviewDetails; IP addresses not yet supported in EIA" } else { "IP addresses not yet supported in EIA" }
                    
                    $policyEntry = [PSCustomObject]@{
                        PolicyName = $policyName
                        PolicyType = "WebContentFiltering"
                        PolicyAction = $actualAction
                        Description = "URL List: $($urlList.name)"
                        RuleType = $destType
                        RuleDestinations = ($splits[$i] -join ';')
                        RuleName = $ruleName
                        ReviewNeeded = "Yes"
                        ReviewDetails = $ipReviewDetails
                        Provision = "No"
                    }
                    [void]$policies.Add($policyEntry)
                }
            }
        }
    }
}
```

#### 2.2 Process Custom Categories

```powershell
foreach ($category in $customCategories) {
    Write-LogMessage "Processing custom category: $($category.name)" -Level "DEBUG"
    
    # Track URL list references for later linking
    $inclusionUrlListIds = @()
    $exclusionUrlListIds = @()
    $predefinedCategories = @()
    $hasUnmappedCategories = $false
    $unmappedCategoryNames = @()
    
    # Collect inclusion URL list IDs
    if ($category.data.inclusion) {
        foreach ($urlListRef in $category.data.inclusion) {
            $inclusionUrlListIds += $urlListRef.id
        }
    }
    
    # Collect exclusion URL list IDs
    if ($category.data.exclusion) {
        foreach ($urlListRef in $category.data.exclusion) {
            $exclusionUrlListIds += $urlListRef.id
        }
    }
    
    # Check for URL lists in both inclusion AND exclusion (warn if found)
    $duplicateUrlLists = $inclusionUrlListIds | Where-Object { $exclusionUrlListIds -contains $_ }
    if ($duplicateUrlLists.Count -gt 0) {
        Write-LogMessage "Custom category '$($category.name)' has URL lists in both inclusion and exclusion arrays: $(($duplicateUrlLists | ForEach-Object { $urlListsHashtable[$_].name }) -join ', ')" -Level "WARN"
    }
    
    # Process predefined categories
    if ($category.data.categories) {
        foreach ($catRef in $category.data.categories) {
            $mapping = $categoryMappingsHashtable[$catRef.name]
            if ($null -ne $mapping -and -not [string]::IsNullOrWhiteSpace($mapping.GSACategory) -and $mapping.GSACategory -ne "Unmapped") {
                $predefinedCategories += $mapping.GSACategory
            } else {
                $predefinedCategories += "UNMAPPED:$($catRef.name)"
                $hasUnmappedCategories = $true
                $unmappedCategoryNames += $catRef.name
            }
        }
    }
    
    # Create policies for predefined categories (if any)
    if ($predefinedCategories.Count -gt 0) {
        foreach ($action in @('Allow', 'Block')) {
            $policyName = "$($category.name)-WebCategories-$action"
            
            $policyEntry = [PSCustomObject]@{
                PolicyName = $policyName
                PolicyType = "WebContentFiltering"
                PolicyAction = $action
                Description = "$($category.name) - Predefined categories"
                RuleType = "webCategory"
                RuleDestinations = ($predefinedCategories -join ';')
                RuleName = "WebCategories"
                ReviewNeeded = if ($hasUnmappedCategories) { "Yes" } else { "No" }
                ReviewDetails = if ($hasUnmappedCategories) { "Unmapped categories: $(($unmappedCategoryNames -join ', '))" } else { "" }
                Provision = if ($hasUnmappedCategories) { "No" } else { "Yes" }
            }
            [void]$policies.Add($policyEntry)
        }
    }
    
    # Store custom category info for Phase 3 lookup
    $customCategoryPoliciesHashtable[$category.name] = @{
        InclusionUrlListIds = $inclusionUrlListIds
        ExclusionUrlListIds = $exclusionUrlListIds
        HasPredefinedCategories = ($predefinedCategories.Count -gt 0)
        HasDuplicateUrlLists = ($duplicateUrlLists.Count -gt 0)
        DuplicateUrlListIds = $duplicateUrlLists
    }
}
```

### Phase 3: Real-time Protection Policy Processing

#### 3.1 Filter Policies

```powershell
# Filter out disabled, NPA policies, and app-tag filtered policies
$webPolicies = $realTimePolicies | Where-Object {
    $_.status -eq "Enabled " -and 
    $_.accessMethod -ne "Client" -and
    ($_.app_tags -eq "Any" -or [string]::IsNullOrWhiteSpace($_.app_tags))
}

$skippedAppTagPolicies = $realTimePolicies | Where-Object {
    $_.status -eq "Enabled " -and 
    $_.accessMethod -ne "Client" -and
    -not ([string]::IsNullOrWhiteSpace($_.app_tags)) -and
    $_.app_tags -ne "Any"
}

Write-LogMessage "Filtered $($webPolicies.Count) enabled web policies from $($realTimePolicies.Count) total policies" -Level "INFO"

if ($skippedAppTagPolicies.Count -gt 0) {
    Write-LogMessage "Skipped $($skippedAppTagPolicies.Count) policies with app_tags filtering (not supported in EIA)" -Level "WARN"
    foreach ($policy in $skippedAppTagPolicies) {
        Write-LogMessage "Skipped policy '$($policy.ruleName)' with app_tags='$($policy.app_tags)'" -Level "DEBUG"
    }
}
```

#### 3.2 Parse and Process Each Policy

```powershell
foreach ($policy in $webPolicies) {
    # Parse user field
    $userEntries = $policy.user -split ',' | ForEach-Object { $_.Trim() }
    $emails = @()
    $groups = @()
    
    foreach ($entry in $userEntries) {
        if ($entry -eq "All") {
            $groups = @("Replace_with_All_IA_Users_Group")
            $emails = @()
            break
        } elseif ($entry -like "*/*") {
            # X500 group path
            $segments = $entry -split '/'
            $groupName = $segments[-1].Trim()
            $groups += $groupName
        } elseif ($entry -like "*@*") {
            # Email address
            $emails += $entry
        }
    }
    
    # Parse application field
    $appEntries = $policy.application -split ',' | ForEach-Object { $_.Trim() }
    $policyLinks = @()
    $needsReview = $false
    $reviewReasons = @()
    
    foreach ($appEntry in $appEntries) {
        # 1. Check if it's a custom category
        if ($customCategoriesByName.ContainsKey($appEntry)) {
            $categoryInfo = $customCategoryPoliciesHashtable[$appEntry]
            
            # Check for duplicate URL lists (in both inclusion and exclusion)
            if ($categoryInfo.HasDuplicateUrlLists) {
                $needsReview = $true
                $duplicateNames = $categoryInfo.DuplicateUrlListIds | ForEach-Object { $urlListsHashtable[$_].name }
                $reviewReasons += "Custom category '$appEntry' has URL lists in both inclusion and exclusion: $(($duplicateNames -join ', '))"
            }
            
            # Link to URL list policies based on RT action
            # Inclusions: normal action
            foreach ($urlListId in $categoryInfo.InclusionUrlListIds) {
                $urlList = $urlListsHashtable[$urlListId]
                if ($null -eq $urlList) {
                    Write-LogMessage "URL List ID $urlListId not found" -Level "WARN"
                    continue
                }
                
                $urlListPolicyName = if ($policy.action -like "Block*") {
                    "$($urlList.name)-Block"
                } elseif ($policy.action -eq "Allow") {
                    "$($urlList.name)-Allow"
                } elseif ($policy.action -like "Alert*" -or $policy.action -like "User Alert*") {
                    $needsReview = $true
                    $reviewReasons += "Action '$($policy.action)' requires review"
                    "$($urlList.name)-Block"
                } else {
                    "$($urlList.name)-Allow"
                }
                
                $policyLinks += $urlListPolicyName
            }
            
            # Exclusions: INVERSE action
            foreach ($urlListId in $categoryInfo.ExclusionUrlListIds) {
                $urlList = $urlListsHashtable[$urlListId]
                if ($null -eq $urlList) {
                    Write-LogMessage "URL List ID $urlListId not found" -Level "WARN"
                    continue
                }
                
                $urlListPolicyName = if ($policy.action -like "Block*") {
                    "$($urlList.name)-Allow"  # INVERSE
                } elseif ($policy.action -eq "Allow") {
                    "$($urlList.name)-Block"  # INVERSE
                } elseif ($policy.action -like "Alert*" -or $policy.action -like "User Alert*") {
                    $needsReview = $true
                    $reviewReasons += "Action '$($policy.action)' requires review"
                    "$($urlList.name)-Allow"  # INVERSE (treat Alert as Block)
                } else {
                    "$($urlList.name)-Block"  # INVERSE default
                }
                
                $policyLinks += $urlListPolicyName
            }
            
            # Link to predefined category policy if it exists
            if ($categoryInfo.HasPredefinedCategories) {
                $webCategoryPolicyName = if ($policy.action -like "Block*") {
                    "$appEntry-WebCategories-Block"
                } elseif ($policy.action -eq "Allow") {
                    "$appEntry-WebCategories-Allow"
                } elseif ($policy.action -like "Alert*" -or $policy.action -like "User Alert*") {
                    $needsReview = $true
                    $reviewReasons += "Action '$($policy.action)' requires review"
                    "$appEntry-WebCategories-Block"
                } else {
                    "$appEntry-WebCategories-Allow"
                }
                
                $policyLinks += $webCategoryPolicyName
            }
            
            continue
        }
        
        # 2. Check if it's a predefined category
        if ($categoryMappingsHashtable.ContainsKey($appEntry)) {
            $mapping = $categoryMappingsHashtable[$appEntry]
            
            # Determine action
            $policyAction = if ($policy.action -like "Alert*" -or $policy.action -like "User Alert*") {
                $needsReview = $true
                $reviewReasons += "Action '$($policy.action)' requires review"
                "Block"
            } elseif ($policy.action -like "Block*") {
                "Block"
            } else {
                "Allow"
            }
            
            $policyName = "$($policy.ruleName)-WebCategories-$policyAction"
            
            # Check if mapped
            if ([string]::IsNullOrWhiteSpace($mapping.GSACategory) -or $mapping.GSACategory -eq "Unmapped") {
                $gsaCategory = "UNMAPPED:$appEntry"
                $needsReview = $true
                $reviewReasons += "Predefined category '$appEntry' not mapped"
            } else {
                $gsaCategory = $mapping.GSACategory
            }
            
            # Create policy entry
            $policyEntry = [PSCustomObject]@{
                PolicyName = $policyName
                PolicyType = "WebContentFiltering"
                PolicyAction = $policyAction
                Description = "Predefined category: $appEntry"
                RuleType = "webCategory"
                RuleDestinations = $gsaCategory
                RuleName = "WebCategories"
                ReviewNeeded = if ($needsReview) { "Yes" } else { "No" }
                ReviewDetails = ($reviewReasons -join '; ')
                Provision = if ($needsReview) { "No" } else { "Yes" }
            }
            [void]$policies.Add($policyEntry)
            $policyLinks += $policyName
            
            continue
        }
        
        # 3. Treat as application object (flag for review)
        $policyAction = if ($policy.action -like "Alert*" -or $policy.action -like "User Alert*") {
            "Block"
        } elseif ($policy.action -like "Block*") {
            "Block"
        } else {
            "Allow"
        }
        
        $policyName = "$($policy.ruleName)-Application-$policyAction"
        
        $policyEntry = [PSCustomObject]@{
            PolicyName = $policyName
            PolicyType = "WebContentFiltering"
            PolicyAction = $policyAction
            Description = "Application object: $appEntry"
            RuleType = "FQDN"
            RuleDestinations = "PLACEHOLDER_APPLICATION_$appEntry"
            RuleName = "Application"
            ReviewNeeded = "Yes"
            ReviewDetails = "Application object '$appEntry' requires manual mapping to destinations"
            Provision = "No"
        }
        [void]$policies.Add($policyEntry)
        $policyLinks += $policyName
        
        $needsReview = $true
        $reviewReasons += "Application object '$appEntry' requires manual mapping"
    }
    
    # Store policy info for aggregation
    $policyInfo = [PSCustomObject]@{
        RuleName = $policy.ruleName
        Emails = $emails
        Groups = $groups
        PolicyLinks = $policyLinks
        Priority = [int]$policy.groupOrder * 10
        NeedsReview = $needsReview
        ReviewReasons = $reviewReasons
    }
    
    # Add to collection for aggregation
    $policiesForAggregation += $policyInfo
}
```

#### 3.3 Aggregate Policies by User/Group Assignment

```powershell
# Group policies by user/group assignment
$allUsersPolicies = @()
$userGroupPolicies = @{}

foreach ($policyInfo in $policiesForAggregation) {
    # Check if assigned to "All"
    if ($policyInfo.Groups -contains "Replace_with_All_IA_Users_Group") {
        $allUsersPolicies += $policyInfo
        continue
    }
    
    # Create key from sorted users and groups
    $userKey = ($policyInfo.Emails | Sort-Object) -join ','
    $groupKey = ($policyInfo.Groups | Sort-Object) -join ','
    $combinedKey = "$userKey|$groupKey"
    
    if (-not $userGroupPolicies.ContainsKey($combinedKey)) {
        $userGroupPolicies[$combinedKey] = @()
    }
    
    $userGroupPolicies[$combinedKey] += $policyInfo
}

# Create security profile for "All" users
if ($allUsersPolicies.Count -gt 0) {
    $allPolicyLinks = @()
    $allRuleNames = @()
    $lowestPriority = 999999
    $needsReview = $false
    $allReviewReasons = @()
    
    foreach ($policyInfo in $allUsersPolicies) {
        $allPolicyLinks += $policyInfo.PolicyLinks
        $allRuleNames += $policyInfo.RuleName
        if ($policyInfo.Priority -lt $lowestPriority) {
            $lowestPriority = $policyInfo.Priority
        }
        if ($policyInfo.NeedsReview) {
            $needsReview = $true
            $allReviewReasons += $policyInfo.ReviewReasons
        }
    }
    
    # Deduplicate policy links
    $uniquePolicyLinks = $allPolicyLinks | Select-Object -Unique
    
    # Order policy links: Allow policies first (alphabetically), then Block policies (alphabetically)
    $allowPolicies = @($uniquePolicyLinks | Where-Object { $_ -like "*-Allow" } | Sort-Object)
    $blockPolicies = @($uniquePolicyLinks | Where-Object { $_ -like "*-Block" } | Sort-Object)
    $orderedPolicyLinks = $allowPolicies + $blockPolicies
    
    $securityProfile = [PSCustomObject]@{
        SecurityProfileName = "SecurityProfile-All-Users"
        SecurityProfilePriority = $lowestPriority
        EntraGroups = "Replace_with_All_IA_Users_Group"
        EntraUsers = ""
        PolicyLinks = ($orderedPolicyLinks -join ';')
        Description = "Aggregated from $($allUsersPolicies.Count) real-time protection policies"
        Provision = "Yes"
        Notes = ($allRuleNames -join ', ')
    }
    [void]$securityProfiles.Add($securityProfile)
}

# Create security profiles for specific user/group assignments
$profileIndex = 1
foreach ($key in $userGroupPolicies.Keys) {
    $policies = $userGroupPolicies[$key]
    
    $policyLinks = @()
    $ruleNames = @()
    $lowestPriority = 999999
    $needsReview = $false
    $reviewReasons = @()
    
    # Get users and groups from first policy (all in group have same assignment)
    $emails = $policies[0].Emails
    $groups = $policies[0].Groups
    
    foreach ($policyInfo in $policies) {
        $policyLinks += $policyInfo.PolicyLinks
        $ruleNames += $policyInfo.RuleName
        if ($policyInfo.Priority -lt $lowestPriority) {
            $lowestPriority = $policyInfo.Priority
        }
        if ($policyInfo.NeedsReview) {
            $needsReview = $true
            $reviewReasons += $policyInfo.ReviewReasons
        }
    }
    
    # Deduplicate policy links
    $uniquePolicyLinks = $policyLinks | Select-Object -Unique
    
    # Order policy links: Allow policies first (alphabetically), then Block policies (alphabetically)
    $allowPolicies = @($uniquePolicyLinks | Where-Object { $_ -like "*-Allow" } | Sort-Object)
    $blockPolicies = @($uniquePolicyLinks | Where-Object { $_ -like "*-Block" } | Sort-Object)
    $orderedPolicyLinks = $allowPolicies + $blockPolicies
    
    $securityProfile = [PSCustomObject]@{
        SecurityProfileName = "SecurityProfile-{0:D3}" -f $profileIndex
        SecurityProfilePriority = $lowestPriority
        EntraGroups = ($groups -join ';')
        EntraUsers = ($emails -join ';')
        PolicyLinks = ($orderedPolicyLinks -join ';')
        Description = "Aggregated from $($policies.Count) real-time protection policies"
        Provision = "Yes"
        Notes = ($ruleNames -join ', ')
    }
    [void]$securityProfiles.Add($securityProfile)
    
    $profileIndex++
}
```

#### 3.4 Priority Conflict Resolution

```powershell
$priorityTracker = @{}

foreach ($secProfile in $securityProfiles) {
    $originalPriority = $secProfile.SecurityProfilePriority
    $finalPriority = $originalPriority
    
    while ($priorityTracker.ContainsKey($finalPriority)) {
        Write-LogMessage "Priority conflict: $finalPriority already used by $($priorityTracker[$finalPriority])" -Level "INFO"
        $finalPriority++
    }
    
    $secProfile.SecurityProfilePriority = $finalPriority
    $priorityTracker[$finalPriority] = $secProfile.SecurityProfileName
}
```

#### 3.5 Cleanup Unreferenced Policies

```powershell
# Collect all policy names referenced in security profiles
$referencedPolicies = @{}
foreach ($secProfile in $securityProfiles) {
    $policyNames = $secProfile.PolicyLinks -split ';'
    foreach ($policyName in $policyNames) {
        $referencedPolicies[$policyName] = $true
    }
}

# Remove unreferenced policies (URL list policies, custom category policies, etc.)
$originalPolicyCount = $policies.Count

# Group policies by PolicyName to get unique policy names
$policyGroups = $policies | Group-Object -Property PolicyName

# Filter to keep only policies that are referenced
$referencedPolicyNames = @{}
foreach ($policyGroup in $policyGroups) {
    if ($referencedPolicies.ContainsKey($policyGroup.Name)) {
        $referencedPolicyNames[$policyGroup.Name] = $true
    }
}

# Keep only policies that are referenced
$policies = [System.Collections.ArrayList]@($policies | Where-Object {
    $referencedPolicyNames.ContainsKey($_.PolicyName)
})

$removedPolicies = $originalPolicyCount - $policies.Count
if ($removedPolicies -gt 0) {
    Write-LogMessage "Removed $removedPolicies unreferenced policy rules (from $(($policyGroups.Count - $referencedPolicyNames.Count)) policies)" -Level "INFO"
    
    # Log which policies were removed
    $removedPolicyNames = $policyGroups | Where-Object { -not $referencedPolicyNames.ContainsKey($_.Name) } | Select-Object -ExpandProperty Name
    foreach ($removedPolicyName in $removedPolicyNames) {
        Write-LogMessage "Removed unreferenced policy: $removedPolicyName" -Level "DEBUG"
    }
}
```

### Phase 4: Export and Summary

#### 4.1 Export Policies CSV
```powershell
$policiesCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_Policies.csv"
$policies | Export-Csv -Path $policiesCsvPath -NoTypeInformation -Encoding utf8BOM
Write-LogMessage "Exported $($policies.Count) policies to: $policiesCsvPath" -Level "INFO"
```

#### 4.2 Export Security Profiles CSV with Priority Suffixes
```powershell
$spCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_SecurityProfiles.csv"

# Add priority suffixes to policy links during export
$securityProfilesForExport = $securityProfiles | ForEach-Object {
    $profile = $_.PSObject.Copy()
    $policyLinks = $_.PolicyLinks -split ';'
    $formattedLinks = @()
    $linkPriority = 100
    foreach ($link in $policyLinks) {
        $formattedLinks += "${link}:${linkPriority}"
        $linkPriority += 100
    }
    $profile.PolicyLinks = $formattedLinks -join ';'
    $profile
}

$securityProfilesForExport | Export-Csv -Path $spCsvPath -NoTypeInformation -Encoding utf8BOM
Write-LogMessage "Exported $($securityProfiles.Count) security profiles to: $spCsvPath" -Level "INFO"
```

#### 4.3 Generate Summary Statistics

Log the following at INFO level:

```
=== CONVERSION SUMMARY ===
Total real-time protection policies loaded: X
Web policies processed (enabled, non-NPA): Y
Policies skipped (disabled): Z
Policies skipped (NPA): A

Custom categories processed: B
URL lists processed: C
  - Exact type: C1
  - Regex type (flagged): C2

Predefined categories referenced: D
Unmapped predefined categories: E
Application objects found: F

Policies created: G
  - Custom category policies: G1
  - Predefined category policies: G2
  - Application policies: G3
Security profiles created: H
  - All users: H1
  - Specific assignments: H2

URLs classified: U
FQDNs classified: N
IP addresses classified: I

Priority conflicts resolved: P

Output files:
  - Policies: [path]
  - Security Profiles: [path]
  - Log File: [path]
```

---

## Function Parameters

### Required Parameters

| Parameter | Type | Description | Validation |
|-----------|------|-------------|------------|
| RealTimeProtectionPoliciesPath | string | Path to policies file | ValidateScript - file must exist |
| UrlListsPath | string | Path to URL lists file | ValidateScript - file must exist |
| CustomCategoriesPath | string | Path to custom categories file | ValidateScript - file must exist |
| CategoryMappingsPath | string | Path to mappings CSV file | ValidateScript - file must exist |

### Optional Parameters

| Parameter | Type | Default | Description | Validation |
|-----------|------|---------|-------------|------------|
| OutputBasePath | string | `$PWD` | Output directory for CSV and log files | ValidateScript - directory must exist |
| EnableDebugLogging | switch | `false` | Enable DEBUG level logging | None |

### Parameter Definitions

```powershell
[CmdletBinding(SupportsShouldProcess = $false)]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to Netskope Real-time Protection Policies JSON export")]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$RealTimeProtectionPoliciesPath,
    
    [Parameter(Mandatory = $true, HelpMessage = "Path to Netskope URL Lists JSON export")]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$UrlListsPath,
    
    [Parameter(Mandatory = $true, HelpMessage = "Path to Netskope Custom Categories JSON export")]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$CustomCategoriesPath,
    
    [Parameter(Mandatory = $true, HelpMessage = "Path to NSWG to EIA category mappings CSV file")]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$CategoryMappingsPath,
    
    [Parameter(HelpMessage = "Base directory for output files")]
    [ValidateScript({
        if (Test-Path $_ -PathType Container) { return $true }
        else { throw "Directory not found: $_" }
    })]
    [string]$OutputBasePath = $PWD,
    
    [Parameter(HelpMessage = "Enable verbose debug logging")]
    [switch]$EnableDebugLogging
)
```

---

## Internal Helper Functions

### Module Structure

This function uses shared internal functions from `internal/functions/`:
- **Existing shared functions** are used directly (e.g., `Write-LogMessage`)
- **New shared destination processing functions** should be created as individual files in `internal/functions/` for reuse across multiple conversion scripts
- **Conversion-specific helper functions** are defined within `Convert-NSWG2EIA.ps1`

### Shared Internal Functions (Use Directly)

**Existing Functions:**
- `Write-LogMessage` - For all logging operations (already exists)

**New Shared Functions to Create (Individual Files in `internal/functions/`):**

These destination processing functions should be extracted from `Convert-ZIA2EIA.ps1` and placed in separate files for reuse by both ZIA2EIA and NSWG2EIA conversions:

1. **`Get-DestinationType.ps1`** - Classify destination as URL, FQDN, IPv4, or IPv6
2. **`Get-BaseDomain.ps1`** - Extract base domain for grouping
3. **`Test-ValidIPv4Address.ps1`** - Validate IPv4 address format
4. **`Split-ByCharacterLimit.ps1`** - Split destination arrays by 300-char limit
5. **`ConvertTo-CleanDestination.ps1`** - Clean and normalize destinations

After creating these shared functions:
- Update `Convert-ZIA2EIA.ps1` to use the shared functions instead of local copies
- Implement `Convert-NSWG2EIA.ps1` to use these shared functions directly
- Both conversion scripts will reference the same single source of truth for destination processing

### Functions to Create (New)

#### 1. Get-GroupNameFromX500
**Purpose:** Extract group name from X500 path (reuse from Convert-NPA2EPA)

**Parameters:**
- `X500Path` (string): X500 AD-style path

**Returns:**
- String: Group name (last segment)
- `$null` if parsing fails

**Example:**
```powershell
Get-GroupNameFromX500 -X500Path "contoso.com.au/Groups/Finance/APP Finance Users"
# Returns: "APP Finance Users"
```

#### 2. ConvertTo-UserGroupKey
**Purpose:** Create unique key from user/group arrays for aggregation

**Parameters:**
- `Emails` (array): Email addresses
- `Groups` (array): Group names

**Returns:**
- String: Unique key in format "emails|groups"

**Example:**
```powershell
ConvertTo-UserGroupKey -Emails @("user1@domain.com", "user2@domain.com") -Groups @("Group1", "Group2")
# Returns: "user1@domain.com,user2@domain.com|Group1,Group2"
```

#### 3. Resolve-NSWGApplication
**Purpose:** Determine if application string is custom category, predefined category, or application object

**Parameters:**
- `ApplicationName` (string): Name from application field
- `CustomCategoriesHashtable` (hashtable): Lookup for custom categories
- `CategoryMappingsHashtable` (hashtable): Lookup for predefined categories

**Returns:**
- PSCustomObject with properties:
  - `Type`: "CustomCategory", "PredefinedCategory", or "Application"
  - `IsCustomCategory`: Boolean
  - `IsPredefinedCategory`: Boolean
$stats = @{
    TotalRTPoliciesLoaded = 0
    WebPoliciesProcessed = 0
    PoliciesSkippedDisabled = 0
    PoliciesSkippedNPA = 0
    PoliciesSkippedAppTags = 0
    CustomCategoriesProcessed = 0 -ApplicationName "Whitelist URLs" -CustomCategoriesHashtable $customCats -CategoryMappingsHashtable $catMappings
# Returns: Type = "CustomCategory", IsCustomCategory = $true
```

---

## Statistics Tracking

Initialize statistics hashtable at start of function:

```powershell
$stats = @{
    TotalRTPoliciesLoaded = 0
    WebPoliciesProcessed = 0
    PoliciesSkippedDisabled = 0
    PoliciesSkippedNPA = 0
    CustomCategoriesProcessed = 0
    UrlListsProcessed = 0
    UrlListsExact = 0
    UrlListsRegex = 0
    PredefinedCategoriesReferenced = 0
    UnmappedCategories = 0
    ApplicationObjectsFound = 0
    URLsClassified = 0
    FQDNsClassified = 0
    IPsClassified = 0
    EntriesSkipped = 0
    PoliciesCreated = 0
    CustomCategoryPolicies = 0
    PredefinedCategoryPolicies = 0
    ApplicationPolicies = 0
    SecurityProfilesCreated = 0
    SecurityProfilesAllUsers = 0
    SecurityProfilesSpecific = 0
    PriorityConflictsResolved = 0
    UnreferencedPoliciesRemoved = 0
}
```

Update statistics throughout processing and display in Phase 4 summary.

---

## Error Handling

### Fatal Errors (throw and exit)
- Missing input files
- Invalid JSON in input files
- Unable to create output directory
- Unable to write output files

### Non-Fatal Errors (log and continue)
- URL list reference not found
- Invalid destination format
- IPv4 addresses (not yet supported - flag for review)
- IPv6 addresses (not supported - skip)
- Regex URL lists (flag for review)
- Unmapped predefined categories (flag for review)
- Application objects (flag for review)

### Warnings
- Custom categories with no destinations
- Disabled policies
- NPA policies (filtered out)
- Duplicate policy names (resolved with suffix)
- Priority conflicts (auto-resolved)

---

## Known Limitations

1. **Regex URL Lists:** Not supported in EIA - policies created but flagged for manual review with PolicyAction=Block
2. **IP Addresses (IPv4):** Not yet supported in EIA - policies created but flagged for manual review with ReviewNeeded=Yes, Provision=No
3. **IPv6 Addresses:** Not supported - logged and skipped
4. **Application Objects:** No automatic mapping to web categories - requires manual review
5. **Application Tag Filtering:** Not supported - policies with app_tags other than "Any" are skipped
6. **DLP Profiles:** Not converted (profile field ignored)
7. **Activity Constraints:** Not converted (activity field logged but not processed)
8. **Source Criteria:** Not converted (sourceIP, srcCountry, etc. ignored)
9. **300-Character Limit:** Applies to FQDN, URL, and ipAddress rule destinations (not webCategory)
10. **Duplicate URL Lists:** URL lists appearing in both inclusion and exclusion arrays of same custom category require manual review
11. **Unreferenced Policies:** URL list and custom category policies not linked by any RT policy are automatically removed

---

## Examples

### Example 1: Basic Conversion
```powershell
Convert-NSWG2EIA -RealTimeProtectionPoliciesPath "real_time_protection_policies.json" `
                 -UrlListsPath "url_lists.json" `
                 -CustomCategoriesPath "custom_categories.json" `
                 -CategoryMappingsPath "NSWG2EIA-CategoryMappings.csv"
```

Converts Netskope configuration using files in current directory with default output path.

### Example 2: Custom Paths
```powershell
Convert-NSWG2EIA -RealTimeProtectionPoliciesPath "C:\Netskope\policies.json" `
                 -UrlListsPath "C:\Netskope\url_lists.json" `
                 -CustomCategoriesPath "C:\Netskope\custom_categories.json" `
                 -CategoryMappingsPath "C:\Mappings\NSWG2EIA-CategoryMappings.csv" `
                 -OutputBasePath "C:\Output"
```

Converts using specified paths for all files.

### Example 3: Debug Logging
```powershell
Convert-NSWG2EIA -RealTimeProtectionPoliciesPath "real_time_protection_policies.json" `
                 -UrlListsPath "url_lists.json" `
                 -CustomCategoriesPath "custom_categories.json" `
                 -CategoryMappingsPath "NSWG2EIA-CategoryMappings.csv" `
                 -EnableDebugLogging
```

Converts with detailed debug logging enabled.

---

## Testing Scenarios

### Scenario 1: URL List with FQDNs and URLs
**Input:**
- URL list "Whitelist URLs" (ID: 2) with type "exact"
- Contains FQDNs: *.zoom.us, *.zoom.com, play.google.com
- Contains URLs: *.htmlmail.contoso.com.au/harbourside

**Expected Output:**
- Policy 1: "Whitelist URLs-Allow" with multiple rules:
  - FQDN rule for zoom.us destinations
  - FQDN rule for google.com destinations
  - URL rule for htmlmail.contoso.com.au
- Policy 2: "Whitelist URLs-Block" (same rules structure)
- Unreferenced policy (Allow or Block) cleaned up if not linked by any RT policy

### Scenario 2: Custom Category with Predefined Categories and URL List Exclusion
**Input:**
- Custom category "Potentially malicious sites" with:
  - `categories` array: 4 predefined categories (Miscellaneous, Newly Observed Domain, Newly Registered Domain, Parked Domains)
  - `exclusion` array: URL list "Whitelist URLs" (ID: 2)
  - No `inclusion` array

**Expected Output:**
- Predefined category policies created:
  - Policy 1: "Potentially malicious sites-WebCategories-Allow" (single webCategory rule with 4 mapped GSA categories)
  - Policy 2: "Potentially malicious sites-WebCategories-Block" (single webCategory rule with 4 mapped GSA categories)
- URL list policies created separately (from Phase 2.1):
  - "Whitelist URLs-Allow"
  - "Whitelist URLs-Block"
- RT policy with "Block" action links to:
  - "Potentially malicious sites-WebCategories-Block" (blocks the predefined categories)
  - "Whitelist URLs-Allow" (allows the exclusion - INVERSE action)
- RT policy with "Allow" action links to:
  - "Potentially malicious sites-WebCategories-Allow" (allows the predefined categories)
  - "Whitelist URLs-Block" (blocks the exclusion - INVERSE action)

### Scenario 3: URL List with Regex Type
**Input:**
- URL list "Regex Patterns" with type "regex"

**Expected Output:**
- Policy 1: "Regex Patterns-Allow" created but flagged: ReviewNeeded=Yes, Provision=No, PolicyAction=Block
- Policy 2: "Regex Patterns-Block" created but flagged: ReviewNeeded=Yes, Provision=No, PolicyAction=Block
- ReviewDetails: "URL List contains regex patterns"
- Destinations not processed (rules may be empty or contain placeholder)
- Both policies likely cleaned up unless explicitly linked by RT policy

### Scenario 4: RT Policy Referencing Custom Category with URL Lists
**Input:**
- RT policy with action "Block" referencing custom category "Potentially malicious sites"
- Custom category has:
  - Predefined categories (4 categories)
  - Exclusion: URL list "Whitelist URLs" (ID: 2)

**Expected Output:**
- Security profile links to:
  - "Potentially malicious sites-WebCategories-Block" (blocks the predefined categories)
  - "Whitelist URLs-Allow" (allows the exclusion URLs - INVERSE action)

### Scenario 5: RT Policy with Multiple Applications
**Input:**
- RT policy with action "Block" and application field: "Potentially malicious sites, Online Ads, GitHub Copilot"
- "Potentially malicious sites" = custom category with:
  - Predefined categories (4 categories)
  - Exclusion: URL list "Whitelist URLs"
- "Online Ads" = predefined category (mapped to GSA "Advertising")
- "GitHub Copilot" = application object

**Expected Output:**
- Security profile with policy links (ordered: Allow first alphabetically, then Block alphabetically) with priority suffixes:
  1. "Whitelist URLs-Allow:100" (from custom category exclusion - INVERSE)
  2. "Block Multiple Applications-WebCategories-Block:200" (for Online Ads predefined category - using RT policy's ruleName "Block Multiple Applications")
  3. "GitHub Copilot-Application-Block:300" (flagged for review)
  4. "Potentially malicious sites-WebCategories-Block:400" (custom category predefined categories)
- Note: Block policies are sorted alphabetically: "Block Multiple Applications..." comes before "GitHub Copilot..." and "Potentially malicious sites..."

### Scenario 6: Policy Aggregation - All Users
**Input:**
- 5 policies all assigned to "All"

**Expected Output:**
- 1 security profile: "SecurityProfile-All-Users"
- EntraGroups: "Replace_with_All_IA_Users_Group"
- Notes: Lists all 5 rule names
- PolicyLinks: All unique policy references, deduplicated and ordered (Allow policies first alphabetically, then Block policies alphabetically)

### Scenario 7: Policy Aggregation - Same User Set with Duplicate References
**Input:**
- 3 policies assigned to "user1@domain.com, user2@domain.com"
- 2 of these policies both reference "Online Ads" predefined category with Block action

**Expected Output:**
- SecurityProfile-001: Aggregates 3 policies for user1+user2
- PolicyLinks: Deduplicated list ("Online Ads-WebCategories-Block" appears only once)
- PolicyLinks ordered: Allow policies first (alphabetically), then Block policies (alphabetically)
- Notes field lists all 3 aggregated rule names

### Scenario 8: X500 Group Path Parsing
**Input:**
- User field: "contoso.com.au/Groups/Application Security Groups/Finance/APP Finance Users"

**Expected Output:**
- EntraGroups: "APP Finance Users"

### Scenario 9: Mixed User Assignment
**Input:**
- User field: "user1@domain.com, contoso.com.au/Groups/IT/APP IT Users, user2@domain.com"

**Expected Output:**
- EntraUsers: "user1@domain.com;user2@domain.com"
- EntraGroups: "APP IT Users"

### Scenario 11: Custom Category with Duplicate URL List References
**Input:**
- Custom category "Test Category" with:
  - `inclusion` array: URL list "Shared URLs" (ID: 10)
  - `exclusion` array: URL list "Shared URLs" (ID: 10)
- RT policy with action "Block" references this custom category

**Expected Output:**
- WARNING logged: "Custom category 'Test Category' has URL lists in both inclusion and exclusion arrays: Shared URLs"
- Security profile created with:
  - "Shared URLs-Block" linked (from inclusion with Block action)
  - "Shared URLs-Allow" linked (from exclusion with Block action - INVERSE)
- Security profile flagged: ReviewNeeded with note about duplicate URL list
- User must manually review and resolve the conflict

### Scenario 12: Unreferenced Policy Cleanup
**Input:**
- URL list "Unused List" creates two policies: "Unused List-Allow" and "Unused List-Block"
- Custom category "Test Category" references URL list "Active List"
- RT policy with Block action references "Test Category" (links to "Active List-Block")
- No RT policy references "Unused List"

**Expected Output:**
- Phase 2 creates policies for both "Unused List" and "Active List"
- Phase 3.5 cleanup removes:
  - "Unused List-Allow" (not referenced)
  - "Unused List-Block" (not referenced)
  - "Active List-Allow" (not referenced, only Block variant used)
- Final output only contains "Active List-Block"
**Input:**
- 3 policies with groupOrder = 2 (all become priority 20)

**Expected Output:**
- Priorities assigned: 20, 21, 22
- Logged at INFO level

---

## Sample Files

Create sample input files in `Samples/NSWG2EIA/` directory:

1. **sample_real_time_protection_policies.rename_to_json** - Representative RT policies showing:
   - Policies with custom category references
   - Policies with predefined category references
   - Policies with application objects
   - Policies with "All" user assignment
   - Policies with specific user/group assignments
   - Policies with Alert/User Alert actions
   - Disabled policies
   - NPA policies (accessMethod = "Client")

2. **sample_url_lists.rename_to_json** - Representative URL lists showing:
   - Exact type URL lists with FQDNs
   - Exact type URL lists with URLs (with paths)
   - Exact type URL lists with IP addresses
   - Regex type URL lists

3. **sample_custom_categories.rename_to_json** - Representative custom categories showing:
   - Category with predefined categories only
   - Category with URL list inclusions only
   - Category with URL list exclusions only
   - Category with both predefined categories and URL lists
   - Category with URL lists in both inclusion and exclusion arrays (duplicate)

4. **sample_NSWG2EIA-CategoryMappings.rename_to_csv** - Sample mapping file with:
   - Common mapped predefined categories
   - Unmapped categories (blank or "Unmapped" GSACategory)

5. **README.md** - Documentation explaining:
   - How to use the sample files
   - File naming conventions (rename_to_json/csv)
   - Expected conversion results

Note: Do not create sample output files - these will be generated by running the conversion.

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-12 | Andres Canello | Initial specification |

---

## References

- Convert-ZIA2EIA.ps1 Specification (20251013-Convert-ZIA2EIA.md)
- Convert-NPA2EPA.ps1 Implementation
- Netskope Inline Policies Documentation: https://docs.netskope.com/en/inline-policies
- Microsoft Entra Internet Access Documentation

---

## Appendix A: Sample NSWG2EIA-CategoryMappings.csv

```csv
NSWGCategory,GSACategory
Social,SocialNetworking
Cloud Storage,CloudStorage
Streaming Media,StreamingMedia
Business and Economy,Business
News and Media,News
Advertisements,Advertising
Online Ads,Advertising
Gambling,Gambling
Adult Content,AdultContent
Adult Content - Pornography,AdultContent
Malware,Malware
Phishing and Deception,Phishing
Security Risk,Malicious
Potentially Unwanted Software,PotentiallyUnwantedSoftware
Miscellaneous,Unmapped
Newly Observed Domain,NewlyObservedDomain
Newly Registered Domain,Unmapped
Parked Domains,ParkedDomains
Generative AI,ArtificialIntelligence
```

---

## Appendix B: Sample Processing Output

### Sample Policies CSV Output

```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,ReviewNeeded,ReviewDetails,Provision
Whitelist URLs-Allow,WebContentFiltering,Allow,URL List: Whitelist URLs,FQDN,*.zoom.us;*.zoom.com;*.chime.aws,zoom.us,No,,Yes
Whitelist URLs-Allow,WebContentFiltering,Allow,URL List: Whitelist URLs,FQDN,play.google.com;*.google-analytics.com,google.com,No,,Yes
Whitelist URLs-Allow,WebContentFiltering,Allow,URL List: Whitelist URLs,URL,*.htmlmail.contoso.com.au/harbourside,htmlmail.contoso.com.au,No,,Yes
Potentially malicious sites-WebCategories-Block,WebContentFiltering,Block,Potentially malicious sites - Predefined categories,webCategory,Miscellaneous;NewlyObservedDomain;NewlyRegisteredDomain;ParkedDomains,WebCategories,No,,Yes
Online Ads-WebCategories-Block,WebContentFiltering,Block,Predefined category: Online Ads,webCategory,Advertising,WebCategories,No,,Yes
GitHub Copilot-Application-Allow,WebContentFiltering,Allow,Application object: GitHub Copilot,FQDN,PLACEHOLDER_APPLICATION_GitHub Copilot,Application,Yes,Application object 'GitHub Copilot' requires manual mapping to destinations,No
```

### Sample Security Profiles CSV Output

```csv
SecurityProfileName,SecurityProfilePriority,EntraGroups,EntraUsers,PolicyLinks,Description,Provision,Notes
SecurityProfile-All-Users,20,Replace_with_All_IA_Users_Group,,Whitelist URLs-Allow;Online Ads-WebCategories-Block;Potentially malicious sites-WebCategories-Block,Aggregated from 15 real-time protection policies,Yes,"Block Advertisements, Whitelist URLs, Block Malware Download and Upload, Block Access To ITAR Restricted Countries, Allow Sanctioned Web Apps, Block Risky Website, Block Unsanctioned Web Apps, Blacklist Category, Block Unsanctioned Cloud Storage Software, Allow URL for Malware Detection, Block Unsanctioned Remote Access Software, Concur Malicious Domains, Blacklist Compromised Websites, Blacklist URLs"
SecurityProfile-001,30,APP Finance Users,user1@contoso.com;user2@contoso.com,Trello URLs-Allow;Trello-WebCategories-Block,Aggregated from 2 real-time protection policies,Yes,"Whitelist Trello App, Block Trello Usage"
```

---

## Appendix C: Common Issues and Solutions

### Issue 1: Custom Category Not Found in Policies
**Symptom:** Real-time policy references custom category by name, but lookup fails

**Solution:** Ensure custom category `name` field matches exactly (case-sensitive). Check for trailing spaces or special characters.

### Issue 2: X500 Group Path Parsing Failure
**Symptom:** Group names not extracted correctly from user field

**Solution:** Verify X500 path format. Should contain "/" separators. Last segment is used as group name.

### Issue 3: Priority Conflicts Not Resolving
**Symptom:** Multiple security profiles have same priority

**Solution:** Verify priority conflict resolution logic runs in Phase 3. Check that `SecurityProfilePriority` is modified in-place.

### Issue 4: Unreferenced Policies Not Removed
**Symptom:** Output contains policies not linked to any security profile

**Solution:** Ensure Phase 3 cleanup step collects all policy links from security profiles and filters policy collection.

### Issue 5: Regex URL Lists Processed Instead of Flagged
**Symptom:** Regex patterns appear in RuleDestinations field

**Solution:** Verify type checking logic in Phase 2. Should skip processing and flag when `data.type == "regex"`.

---
