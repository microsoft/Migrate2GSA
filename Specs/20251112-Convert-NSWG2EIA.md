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
- Can have `inclusion` arrays (allowed/processed destinations)
- Can have `exclusion` arrays (blocked/excluded destinations)
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
- Netskope custom categories convert to EIA web content filtering policies
- Each policy has ONE action (Allow or Block) at the policy level
- Policies contain multiple rules grouped by destination type

**Custom Category Conversion:**
- Custom category with `inclusion` → "CategoryName-Allow" policy
- Custom category with `exclusion` → "CategoryName-Block" policy (additional)
- Destinations from URL lists are classified and grouped by type
- Predefined categories become webCategory rules

**Real-time Protection Policy Conversion:**
- Policies referencing predefined categories → "RuleName-WebCategories-[Action]" policy
- Policies referencing applications → flagged for review (no direct mapping)
- Multiple policies assigned to same users/groups → aggregated into single security profile

**Policy Naming:**
- Custom category policies: `[CategoryName]-Allow` or `[CategoryName]-Block`
- Predefined category policies: `[RuleName]-WebCategories-[Action]`
- Application policies: `[RuleName]-Application-[Action]` (with ReviewNeeded=Yes)

**Rule Naming:**
- FQDN rules: Base domain name (e.g., `example.com`, `example.com-2`)
- URL rules: Base domain name (e.g., `contoso.com`, `contoso.com-2`)
- IP address rules: `IPs`, `IPs-2`, `IPs-3`
- Web category rules: `WebCategories` (no splitting)

**Security Profile Naming:**
- All users: `SecurityProfile-All-Users`
- Specific user/group sets: `SecurityProfile-001`, `SecurityProfile-002`, etc.

### Mapping Summary

| Netskope Element | Converts To | EIA Element | Notes |
|------------------|-------------|-------------|-------|
| Custom Category (inclusion) | → | Web Content Filtering Policy | PolicyName: "CategoryName-Allow" |
| Custom Category (exclusion) | → | Web Content Filtering Policy | PolicyName: "CategoryName-Block" |
| URL List (type: exact) | → | Policy Rules (FQDN/URL/ipAddress) | Grouped by type and base domain |
| URL List (type: regex) | → | Flagged for Review | Log pattern, skip processing |
| Predefined Category in Custom Category | → | Policy Rule (webCategory type) | Mapped via NSWG2EIA-CategoryMappings.json |
| Predefined Category in Policy | → | Web Content Filtering Policy | PolicyName: "RuleName-WebCategories-[Action]" |
| Application Object | → | Web Content Filtering Policy | Flagged for review (ReviewNeeded=Yes) |
| Real-time Protection Policies (same users) | → | Single Security Profile | Aggregated with all policy links |

---

## Input Files

### 1. real_time_protection_policies.json
**Source:** Netskope API/Export  
**Required:** Yes  
**Default Path:** `real_time_protection_policies.json` (in script root directory)

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

3. **User Field Parsing:**
   - Split by comma and trim whitespace
   - Identify emails (contains @ but not /)
   - Identify X500 group paths (contains /)
   - Extract group name from X500 path (last segment after /)
   - Handle "All" → use placeholder "Replace_with_All_IA_Users_Group"

4. **Application Field Parsing:**
   - Split by comma and trim whitespace
   - For each entry, perform lookup:
     1. Check if it's a custom category name
     2. Check if it's a predefined category (in mapping file)
     3. Otherwise, treat as application object

5. **Action Mapping:**
   - "Allow" → PolicyAction "Allow"
   - "Block*" (any block variant) → PolicyAction "Block"
   - "Alert" → PolicyAction "Block" + ReviewNeeded = Yes
   - "User Alert*" → PolicyAction "Block" + ReviewNeeded = Yes

### 2. url_lists.json
**Source:** Netskope API/Export  
**Required:** Yes  
**Default Path:** `url_lists.json` (in script root directory)

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
**Default Path:** `custom_categories.json` (in script root directory)

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
| `data.categories` | array | Predefined category references | Map using NSWG2EIA-CategoryMappings.json |

#### Processing Rules

1. **Inclusion Processing:**
   - Resolve each URL list reference by ID
   - Combine all destinations from all referenced URL lists
   - If any URL list has type "regex", flag entire custom category for review
   - Create "-Allow" policy with these destinations

2. **Exclusion Processing:**
   - Resolve each URL list reference by ID
   - Combine all exclusion destinations
   - Create "-Block" policy with these destinations (only if exclusions exist)

3. **Predefined Categories:**
   - Map each category using mapping file
   - Add as webCategory rules to the appropriate policy (inclusion → Allow, exclusion → Block)

### 4. NSWG2EIA-CategoryMappings.json
**Source:** Manual configuration file (maintained by user)  
**Required:** Yes  
**Default Path:** `NSWG2EIA-CategoryMappings.json` (in script root directory)

#### Description
Provides mapping between Netskope predefined web categories and Microsoft GSA (Global Secure Access) web categories.

#### Schema

```json
{
  "LastUpdated": "2025-11-12",
  "MappingData": [
    {
      "NSWGCategory": "Social",
      "NSWGDescription": "Social networking sites",
      "ExampleSites": "facebook.com, twitter.com",
      "GSACategory": "SocialNetworking",
      "MappingNotes": "Direct mapping to GSA SocialNetworking category"
    },
    {
      "NSWGCategory": "Cloud Storage",
      "GSACategory": "CloudStorage",
      "MappingNotes": "Maps to GSA CloudStorage category"
    }
  ]
}
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `NSWGCategory` | string | Yes | Netskope category name (matches `application` or `categories[].name`) |
| `NSWGDescription` | string | No | Category description for reference |
| `ExampleSites` | string | No | Sample sites for documentation |
| `GSACategory` | string | Yes | Target GSA category name |
| `MappingNotes` | string | No | Mapping rationale |

#### Processing Rules

1. **Lookup:** For each predefined category reference, find matching `NSWGCategory`
2. **Unmapped Categories:**
   - If `GSACategory` is null, blank, or "Unmapped": use placeholder format
   - Placeholder: `"UNMAPPED:[NSWGCategory]"`
   - Set `ReviewNeeded` = "Yes" in output
3. **Mapped Categories:**
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
- Inclusion policy: `[CategoryName]-Allow`
- Exclusion policy: `[CategoryName]-Block` (only if exclusions exist)

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
- `ipAddress` - IP addresses (no CIDR, no ports)

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
- Includes custom category policies (with -Allow or -Block based on rule action)
- Includes predefined category policies (RuleName-WebCategories-[Action])
- Includes application policies (RuleName-Application-[Action])
- Example: `Whitelist URLs-Allow;Online Ads-Block;GitHub Copilot-Application-Allow`

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
4. Load `NSWG2EIA-CategoryMappings.json`
   - Validate JSON structure
   - Fatal error if file missing or invalid

#### 1.3 Build Lookup Tables

```powershell
# Category mappings for predefined categories
$categoryMappingsHashtable = @{}
foreach ($mapping in $categoryMappings.MappingData) {
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

### Phase 2: Custom Category Processing

#### 2.1 Filter and Process Custom Categories

```powershell
foreach ($category in $customCategories) {
    Write-LogMessage "Processing custom category: $($category.name)" -Level "DEBUG"
    
    # Initialize tracking
    $allInclusionDestinations = @()
    $allExclusionDestinations = @()
    $inclusionCategories = @()
    $exclusionCategories = @()
    $hasRegexUrlList = $false
    $regexUrlListNames = @()
    
    # Process inclusion URL lists
    if ($category.data.inclusion) {
        foreach ($urlListRef in $category.data.inclusion) {
            $urlList = $urlListsHashtable[$urlListRef.id]
            if ($null -eq $urlList) {
                Write-LogMessage "URL List ID $($urlListRef.id) not found for category $($category.name)" -Level "WARN"
                continue
            }
            
            # Check for regex type
            if ($urlList.data.type -eq "regex") {
                $hasRegexUrlList = $true
                $regexUrlListNames += $urlList.name
                Write-LogMessage "URL List '$($urlList.name)' is regex type - will flag for review" -Level "WARN"
                continue  # Skip processing regex lists
            }
            
            # Collect destinations
            $allInclusionDestinations += $urlList.data.urls
        }
    }
    
    # Process exclusion URL lists
    if ($category.data.exclusion) {
        foreach ($urlListRef in $category.data.exclusion) {
            $urlList = $urlListsHashtable[$urlListRef.id]
            if ($null -eq $urlList) {
                Write-LogMessage "URL List ID $($urlListRef.id) not found for category $($category.name)" -Level "WARN"
                continue
            }
            
            # Check for regex type
            if ($urlList.data.type -eq "regex") {
                $hasRegexUrlList = $true
                $regexUrlListNames += $urlList.name
                Write-LogMessage "URL List '$($urlList.name)' is regex type - will flag for review" -Level "WARN"
                continue
            }
            
            # Collect destinations
            $allExclusionDestinations += $urlList.data.urls
        }
    }
    
    # Process predefined categories (inclusion)
    if ($category.data.categories) {
        foreach ($catRef in $category.data.categories) {
            $mapping = $categoryMappingsHashtable[$catRef.name]
            if ($null -ne $mapping -and -not [string]::IsNullOrWhiteSpace($mapping.GSACategory)) {
                $inclusionCategories += $mapping.GSACategory
            } else {
                $inclusionCategories += "UNMAPPED:$($catRef.name)"
                $hasRegexUrlList = $true  # Flag for review
            }
        }
    }
    
    # Deduplicate and clean inclusion destinations
    $uniqueInclusionDestinations = @($allInclusionDestinations | Group-Object -Property { $_.ToLower() } | ForEach-Object { $_.Group[0] })
    $cleanedInclusionDestinations = @()
    foreach ($dest in $uniqueInclusionDestinations) {
        $cleaned = ConvertTo-CleanDestination -Destination $dest
        if ($null -ne $cleaned) {
            $cleanedInclusionDestinations += $cleaned
        }
    }
    
    # Classify inclusion destinations
    $inclusionClassified = @{
        'FQDN' = @()
        'URL' = @()
        'ipAddress' = @()
    }
    
    foreach ($dest in $cleanedInclusionDestinations) {
        $destType = Get-DestinationType -Destination $dest
        if ($destType -eq 'ipv4') {
            $inclusionClassified['ipAddress'] += $dest
        } elseif ($destType -eq 'ipv6') {
            Write-LogMessage "IPv6 address not supported: $dest" -Level "WARN"
        } elseif ($destType -eq 'URL') {
            $inclusionClassified['URL'] += $dest
        } else {
            $inclusionClassified['FQDN'] += $dest
        }
    }
    
    # Create -Allow policy for inclusions
    if ($cleanedInclusionDestinations.Count -gt 0 -or $inclusionCategories.Count -gt 0) {
        $allowPolicyName = "$($category.name)-Allow"
        
        # Create rules for FQDNs, URLs, IPs (same logic as ZIA)
        # ... (group by base domain, split by character limit, create policy entries)
        
        # Create rule for web categories
        if ($inclusionCategories.Count -gt 0) {
            $policyEntry = [PSCustomObject]@{
                PolicyName = $allowPolicyName
                PolicyType = "WebContentFiltering"
                PolicyAction = "Allow"
                Description = $category.name
                RuleType = "webCategory"
                RuleDestinations = ($inclusionCategories -join ';')
                RuleName = "WebCategories"
                ReviewNeeded = if ($hasRegexUrlList) { "Yes" } else { "No" }
                ReviewDetails = if ($hasRegexUrlList) { "Regex URL lists: $($regexUrlListNames -join ', ')" } else { "" }
                Provision = if ($hasRegexUrlList) { "No" } else { "Yes" }
            }
            [void]$policies.Add($policyEntry)
        }
    }
    
    # Process exclusions (create -Block policy) - similar logic
    if ($allExclusionDestinations.Count -gt 0) {
        # ... similar processing for exclusions with -Block suffix
    }
    
    # Track policies for Phase 3 lookup
    $customCategoryPoliciesHashtable[$category.name] = @{
        AllowPolicyName = "$($category.name)-Allow"
        BlockPolicyName = if ($allExclusionDestinations.Count -gt 0) { "$($category.name)-Block" } else { $null }
        HasRegex = $hasRegexUrlList
    }
}
```

### Phase 3: Real-time Protection Policy Processing

#### 3.1 Filter Policies

```powershell
# Filter out disabled and NPA policies
$webPolicies = $realTimePolicies | Where-Object {
    $_.status -eq "Enabled " -and $_.accessMethod -ne "Client"
}

Write-LogMessage "Filtered $($webPolicies.Count) enabled web policies from $($realTimePolicies.Count) total policies" -Level "INFO"
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
            
            # Select policy based on action
            if ($policy.action -like "Block*") {
                # Use Block policy if it exists, otherwise use Allow policy
                $policyName = if ($categoryInfo.BlockPolicyName) { $categoryInfo.BlockPolicyName } else { $categoryInfo.AllowPolicyName }
            } elseif ($policy.action -eq "Allow") {
                $policyName = $categoryInfo.AllowPolicyName
            } elseif ($policy.action -like "Alert*" -or $policy.action -like "User Alert*") {
                $policyName = if ($categoryInfo.BlockPolicyName) { $categoryInfo.BlockPolicyName } else { $categoryInfo.AllowPolicyName }
                $needsReview = $true
                $reviewReasons += "Action '$($policy.action)' requires review"
            }
            
            $policyLinks += $policyName
            
            if ($categoryInfo.HasRegex) {
                $needsReview = $true
                $reviewReasons += "Custom category '$appEntry' contains regex URL lists"
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
    
    $securityProfile = [PSCustomObject]@{
        SecurityProfileName = "SecurityProfile-All-Users"
        SecurityProfilePriority = $lowestPriority
        EntraGroups = "Replace_with_All_IA_Users_Group"
        EntraUsers = ""
        PolicyLinks = (($allPolicyLinks | Select-Object -Unique) -join ';')
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
    
    $securityProfile = [PSCustomObject]@{
        SecurityProfileName = "SecurityProfile-{0:D3}" -f $profileIndex
        SecurityProfilePriority = $lowestPriority
        EntraGroups = ($groups -join ';')
        EntraUsers = ($emails -join ';')
        PolicyLinks = (($policyLinks | Select-Object -Unique) -join ';')
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

# Remove unreferenced custom category policies
$originalPolicyCount = $policies.Count
$policies = [System.Collections.ArrayList]@($policies | Where-Object {
    $referencedPolicies.ContainsKey($_.PolicyName)
})

$removedPolicies = $originalPolicyCount - $policies.Count
if ($removedPolicies -gt 0) {
    Write-LogMessage "Removed $removedPolicies unreferenced policies" -Level "INFO"
}
```

### Phase 4: Export and Summary

#### 4.1 Export Policies CSV
```powershell
$policiesCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_Policies.csv"
$policies | Export-Csv -Path $policiesCsvPath -NoTypeInformation -Encoding utf8BOM
Write-LogMessage "Exported $($policies.Count) policies to: $policiesCsvPath" -Level "INFO"
```

#### 4.2 Export Security Profiles CSV
```powershell
$spCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_SecurityProfiles.csv"
$securityProfiles | Export-Csv -Path $spCsvPath -NoTypeInformation -Encoding utf8BOM
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
None (all have defaults)

### Optional Parameters

| Parameter | Type | Default | Description | Validation |
|-----------|------|---------|-------------|------------|
| RealTimeProtectionPoliciesPath | string | `real_time_protection_policies.json` | Path to policies file | ValidateScript - file must exist |
| UrlListsPath | string | `url_lists.json` | Path to URL lists file | ValidateScript - file must exist |
| CustomCategoriesPath | string | `custom_categories.json` | Path to custom categories file | ValidateScript - file must exist |
| CategoryMappingsPath | string | `NSWG2EIA-CategoryMappings.json` | Path to mappings file | ValidateScript - file must exist |
| OutputBasePath | string | `$PWD` | Output directory for CSV and log files | ValidateScript - directory must exist |
| EnableDebugLogging | switch | `false` | Enable DEBUG level logging | None |

### Parameter Definitions

```powershell
[CmdletBinding(SupportsShouldProcess = $false)]
param(
    [Parameter(HelpMessage = "Path to Netskope Real-time Protection Policies JSON export")]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$RealTimeProtectionPoliciesPath = (Join-Path $PWD "real_time_protection_policies.json"),
    
    [Parameter(HelpMessage = "Path to Netskope URL Lists JSON export")]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$UrlListsPath = (Join-Path $PWD "url_lists.json"),
    
    [Parameter(HelpMessage = "Path to Netskope Custom Categories JSON export")]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$CustomCategoriesPath = (Join-Path $PWD "custom_categories.json"),
    
    [Parameter(HelpMessage = "Path to NSWG to EIA category mappings JSON file")]
    [ValidateScript({
        if (Test-Path $_ -PathType Leaf) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$CategoryMappingsPath = (Join-Path $PWD "NSWG2EIA-CategoryMappings.json"),
    
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

### Functions to Reuse from Convert-ZIA2EIA

The following helper functions can be reused directly from `Convert-ZIA2EIA.ps1`:

1. **Get-DestinationType** - Classify destination as URL, FQDN, IPv4, or IPv6
2. **Get-BaseDomain** - Extract base domain for grouping
3. **Test-ValidIPv4Address** - Validate IPv4 address format
4. **Split-ByCharacterLimit** - Split destination arrays by 300-char limit
5. **ConvertTo-CleanDestination** - Clean and normalize destinations

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
  - `IsApplication`: Boolean
  - `MappingInfo`: Hashtable with relevant mapping data

**Example:**
```powershell
$result = Resolve-NSWGApplication -ApplicationName "Whitelist URLs" -CustomCategoriesHashtable $customCats -CategoryMappingsHashtable $catMappings
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
- IPv6 addresses (not supported)
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

1. **Regex URL Lists:** Not supported in EIA - flagged for manual review
2. **IPv6 Addresses:** Not supported - logged and skipped
3. **CIDR Ranges:** Not supported for IP addresses
4. **Port Numbers:** Not supported in destinations
5. **Application Objects:** No automatic mapping to web categories - requires manual review
6. **DLP Profiles:** Not converted (profile field ignored)
7. **Activity Constraints:** Not converted (activity field logged but not processed)
8. **Source Criteria:** Not converted (sourceIP, srcCountry, etc. ignored)
9. **300-Character Limit:** Applies to FQDN, URL, and ipAddress rule destinations (not webCategory)

---

## Examples

### Example 1: Basic Conversion
```powershell
Convert-NSWG2EIA
```

Converts Netskope configuration using default file paths in current directory.

### Example 2: Custom Paths
```powershell
Convert-NSWG2EIA -RealTimeProtectionPoliciesPath "C:\Netskope\policies.json" `
                 -UrlListsPath "C:\Netskope\url_lists.json" `
                 -CustomCategoriesPath "C:\Netskope\custom_categories.json" `
                 -CategoryMappingsPath "C:\Mappings\NSWG2EIA-CategoryMappings.json" `
                 -OutputBasePath "C:\Output"
```

Converts using specified paths for all files.

### Example 3: Debug Logging
```powershell
Convert-NSWG2EIA -EnableDebugLogging
```

Converts with detailed debug logging enabled.

---

## Testing Scenarios

### Scenario 1: Custom Category with Inclusions Only
**Input:**
- Custom category "Whitelist URLs" with inclusion referencing URL list ID 2
- URL list 2 has type "exact" with FQDNs and URLs

**Expected Output:**
- Policy: "Whitelist URLs-Allow"
- Multiple rules: FQDN, URL types
- No -Block policy created

### Scenario 2: Custom Category with Inclusions and Exclusions
**Input:**
- Custom category with inclusion (URL list 2) and exclusion (URL list 5)

**Expected Output:**
- Policy 1: "CategoryName-Allow" (inclusions)
- Policy 2: "CategoryName-Block" (exclusions)

### Scenario 3: Custom Category with Regex URL List
**Input:**
- Custom category referencing URL list with type "regex"

**Expected Output:**
- Policy created but flagged: ReviewNeeded=Yes, Provision=No
- ReviewDetails contains regex URL list name
- Destinations not processed

### Scenario 4: Real-time Policy Referencing Custom Category
**Input:**
- Policy with action "Block" referencing custom category "Whitelist URLs"

**Expected Output:**
- Security profile links to "Whitelist URLs-Block" (or -Allow if -Block doesn't exist)

### Scenario 5: Real-time Policy with Multiple Applications
**Input:**
- Policy with application field: "Whitelist URLs, Online Ads, GitHub Copilot"
- "Whitelist URLs" = custom category
- "Online Ads" = predefined category (mapped)
- "GitHub Copilot" = application object

**Expected Output:**
- Security profile with 3 policy links:
  1. "Whitelist URLs-Allow" (custom category)
  2. "RuleName-WebCategories-Block" (predefined)
  3. "RuleName-Application-Block" (flagged for review)

### Scenario 6: Policy Aggregation - All Users
**Input:**
- 5 policies all assigned to "All"

**Expected Output:**
- 1 security profile: "SecurityProfile-All-Users"
- EntraGroups: "Replace_with_All_IA_Users_Group"
- Notes: Lists all 5 rule names
- PolicyLinks: All unique policy references

### Scenario 7: Policy Aggregation - Same User Set
**Input:**
- 3 policies assigned to "user1@domain.com, user2@domain.com"
- 2 policies assigned to different users

**Expected Output:**
- SecurityProfile-001: Aggregates 3 policies for user1+user2
- SecurityProfile-002: For other user set
- Notes field lists aggregated rule names

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

### Scenario 10: Priority Conflict Resolution
**Input:**
- 3 policies with groupOrder = 2 (all become priority 20)

**Expected Output:**
- Priorities assigned: 20, 21, 22
- Logged at INFO level

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

## Appendix A: Sample NSWG2EIA-CategoryMappings.json

```json
{
  "LastUpdated": "2025-11-12",
  "Version": "1.0",
  "Description": "Mapping between Netskope predefined categories and Microsoft Global Secure Access web categories",
  "MappingData": [
    {
      "NSWGCategory": "Social",
      "NSWGDescription": "Social networking sites",
      "ExampleSites": "facebook.com, twitter.com, linkedin.com",
      "GSACategory": "SocialNetworking",
      "MappingNotes": "Direct mapping to GSA SocialNetworking category"
    },
    {
      "NSWGCategory": "Cloud Storage",
      "NSWGDescription": "Cloud storage and file sharing",
      "ExampleSites": "dropbox.com, box.com",
      "GSACategory": "CloudStorage",
      "MappingNotes": "Direct mapping to GSA CloudStorage category"
    },
    {
      "NSWGCategory": "Online Ads",
      "NSWGDescription": "Online advertising and tracking",
      "GSACategory": "Advertising",
      "MappingNotes": "Maps to GSA Advertising category"
    },
    {
      "NSWGCategory": "Generative AI",
      "NSWGDescription": "Generative AI applications",
      "ExampleSites": "openai.com, anthropic.com",
      "GSACategory": "ArtificialIntelligence",
      "MappingNotes": "Maps to GSA AI category"
    },
    {
      "NSWGCategory": "Security Risk",
      "NSWGDescription": "Security threats and malicious sites",
      "GSACategory": "Malicious",
      "MappingNotes": "Maps to GSA Malicious category"
    },
    {
      "NSWGCategory": "Gambling",
      "NSWGDescription": "Gambling and betting sites",
      "GSACategory": "Gambling",
      "MappingNotes": "Direct mapping"
    },
    {
      "NSWGCategory": "Adult Content - Pornography",
      "NSWGDescription": "Adult and pornographic content",
      "GSACategory": "AdultContent",
      "MappingNotes": "Maps to GSA AdultContent category"
    },
    {
      "NSWGCategory": "Newly Registered Domain",
      "NSWGDescription": "Recently registered domains",
      "GSACategory": "Unmapped",
      "MappingNotes": "No direct GSA equivalent - requires manual review"
    }
  ]
}
```

---

## Appendix B: Sample Processing Output

### Sample Policies CSV Output

```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,ReviewNeeded,ReviewDetails,Provision
Whitelist URLs-Allow,WebContentFiltering,Allow,Whitelist URLs,FQDN,*.zoom.us;*.zoom.com;*.chime.aws,zoom.us,No,,Yes
Whitelist URLs-Allow,WebContentFiltering,Allow,Whitelist URLs,FQDN,play.google.com;*.google-analytics.com,google.com,No,,Yes
Whitelist URLs-Allow,WebContentFiltering,Allow,Whitelist URLs,URL,*.htmlmail.contoso.com.au/harbourside,htmlmail.contoso.com.au,No,,Yes
Online Ads-WebCategories-Block,WebContentFiltering,Block,Predefined category: Online Ads,webCategory,Advertising,WebCategories,No,,Yes
GitHub Copilot-Application-Allow,WebContentFiltering,Allow,Application object: GitHub Copilot,FQDN,PLACEHOLDER_APPLICATION_GitHub Copilot,Application,Yes,Application object 'GitHub Copilot' requires manual mapping to destinations,No
```

### Sample Security Profiles CSV Output

```csv
SecurityProfileName,SecurityProfilePriority,EntraGroups,EntraUsers,PolicyLinks,Description,Provision,Notes
SecurityProfile-All-Users,20,Replace_with_All_IA_Users_Group,,Whitelist URLs-Allow;Online Ads-WebCategories-Block;Block Malware Download and Upload-WebCategories-Block,Aggregated from 15 real-time protection policies,Yes,"Block Advertisements, Whitelist URLs, Block Malware Download and Upload, Block Access To ITAR Restricted Countries, Allow Sanctioned Web Apps, Block Risky Website, Block Unsanctioned Web Apps, Blacklist Category, Block Unsanctioned Cloud Storage Software, Allow URL for Malware Detection, Block Unsanctioned Remote Access Software, Concur Malicious Domains, Blacklist Compromised Websites, Blacklist URLs"
SecurityProfile-001,30,APP Finance Users,user1@contoso.com;user2@contoso.com,Trello URLs-Allow;Block Trello Usage-WebCategories-Block,Aggregated from 2 real-time protection policies,Yes,"Whitelist Trello App, Block Trello Usage"
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
