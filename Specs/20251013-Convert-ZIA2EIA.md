# Convert-ZIA2EIA.ps1 Specification

## Document Information
- **Specification Version:** 1.0
- **Date:** 2025-10-13
- **Status:** Final
- **Target Module:** Migrate2GSA
- **Function Name:** Convert-ZIA2EIA

---

## Overview

This PowerShell function converts ZScaler Internet Access (ZIA) URL filtering configuration to Microsoft Entra Internet Access (EIA) format. The function processes URL filtering policies, custom URL categories, and predefined category mappings to generate CSV files ready for import into EIA.

### Purpose
- Transform ZIA URL filtering rules to EIA security profiles
- Convert ZIA URL categories (custom and predefined) to EIA web content filtering policies
- Provide mapping between ZIA and GSA (Global Secure Access) web categories
- Generate import-ready CSV files for EIA configuration

### Design Alignment
This function follows the same architectural patterns as `Convert-ZPA2EPA.ps1`:
- Single function with internal helper functions
- Phased processing approach (Load → Process → Export)
- Comprehensive logging using `Write-LogMessage`
- Region-based code organization
- CSV export using shared utilities

---

## Policy and Rule Naming Conventions

This section describes the structure and naming conventions used when converting ZIA configurations to EIA policies and rules.

### ZIA Structure

**ZIA URL Filtering Policy:**
- A ZIA URL filtering policy is a collection of URL filtering rules
- Each rule is defined in the `url_filtering_policy.json` file

**ZIA URL Filtering Rules:**
- Each ZIA filtering rule can target ZIA custom or predefined web categories
- Rules reference categories through the `urlCategories` array field
- Rules specify actions (ALLOW, BLOCK, CAUTION) and target users/groups

**ZIA Custom Categories:**
- Custom categories can contain destinations of type: IP address, FQDN, or URL
- ZIA refers to all these destination entries as "urls" regardless of type
- Destinations are stored in the `urls` and `dbCategorizedUrls` arrays

**ZIA Predefined Categories:**
- ZIA provides a set of predefined web categories (e.g., "OTHER_ADULT_MATERIAL")
- These categories are referenced by ID in filtering rules
- Predefined categories do not contain individual destination lists

### EIA Structure

**EIA Web Content Filtering Policies:**
- ZIA custom categories are converted to EIA web content filtering policies
- Each EIA web content filtering policy contains one or more rules
- Each rule has a destination type: `FQDN`, `URL`, `ipAddress`, or `webCategory`

**Custom Category Conversion:**
- Each ZIA custom category becomes one EIA web content filtering policy
- Within that policy, destinations are grouped by type (FQDN, URL, IP address)
- URLs are further grouped by base domain to optimize rule count
- If destinations exceed the 300-character limit, they are split into multiple rules with numeric suffixes

**Predefined Category Conversion:**
- When a ZIA filtering rule references predefined web categories, we create a single EIA web content filtering policy
- This policy contains a single rule of type `webCategory`
- All predefined categories that have a direct mapping to EIA categories (based on the mapping table provided as script input) are included in this single rule
- Categories are semicolon-separated in the `RuleDestinations` field
- Web category rules have no character limit and are never split

**Policy Naming:**
- Custom category policies: `[CategoryName]-Block` or `[CategoryName]-Allow`
- Predefined category policies: `[RuleName]-WebCategories-[Action]`

**Rule Naming:**
- FQDN rules: Base domain name (e.g., `example.com`, `example.com-2`, `example.com-3`)
- URL rules: Base domain name (e.g., `contoso.com`, `contoso.com-2`)
- IP address rules: `IPs`, `IPs-2`, `IPs-3` (not grouped by domain)
- Web category rules: `WebCategories` (no numeric suffix, never split)

### Mapping Summary

| ZIA Element | Converts To | EIA Element | Notes |
|-------------|-------------|-------------|-------|
| Custom Category | → | Web Content Filtering Policy | One policy per custom category |
| Custom Category Destinations | → | Policy Rules (FQDN/URL/ipAddress) | Grouped by type and base domain |
| Predefined Categories in Rule | → | Web Content Filtering Policy | One policy per filtering rule |
| Predefined Category References | → | Single Rule (webCategory type) | All categories in one rule, semicolon-separated |
| URL Filtering Rule | → | Security Profile | References all related policies |

---

## Input Files

### 1. url_filtering_policy.json
**Source:** ZIA API endpoint `/urlFilteringRules`  
**Required:** Yes  
**Default Path:** `url_filtering_policy.json` (in script root directory)

#### Description
Contains all URL filtering rules configured in ZScaler Internet Access, including rule order, actions, target users/groups, and associated URL categories.

#### Key Fields to Process

| Field | Type | Description | Processing Notes |
|-------|------|-------------|------------------|
| `id` | integer | Unique identifier for the rule | Log for reference |
| `name` | string | Rule name | Maps to SecurityProfileName in output |
| `order` | integer | Rule priority (lower = higher) | Maps to SecurityProfilePriority (order × 10) |
| `groups` | array | Group objects with `name` attribute | Extract `name` field |
| `users` | array | User objects | Parse email from `name` field |
| `users[].name` | string | Format: "Display Name (email@domain.com)" | Extract email portion |
| `users[].deleted` | boolean | User deletion flag | Skip if `true` |
| `urlCategories` | array | Category IDs (strings) | Both custom and predefined IDs |
| `state` | string | Rule state | Only process "ENABLED" |
| `description` | string | Rule description | Maps to Security Profile Description in output |
| `action` | string | Rule action | Values: "ALLOW", "BLOCK", "CAUTION" |

#### Processing Rules
1. **State Filtering:** Only process rules where `state` = "ENABLED"
   - Log count of disabled rules at INFO level
   - Log names of disabled rules at DEBUG level

2. **User Processing:**
   - Parse email from format: "Display Name (email@domain.com)"
   - Skip users where `deleted: true` (log at DEBUG level)
   - If no valid users remain, proceed with groups only

3. **Group Processing:**
   - Extract `name` attribute from each group object
   - Preserve group names as-is

4. **Default Assignment:**
   - If no users AND no groups: use placeholder "Replace_with_All_IA_Users_Group"

### 2. url_categories.json
**Source:** ZIA API endpoint `/urlCategories`  
**Required:** Yes  
**Default Path:** `url_categories.json` (in script root directory)

#### Description
Contains all URL categories including both ZScaler predefined categories and customer-defined custom categories with their URL/FQDN/IP lists.

#### Key Fields to Process

| Field | Type | Description | Processing Notes |
|-------|------|-------------|------------------|
| `id` | string | Category identifier | e.g., "CUSTOM_01", "OTHER_ADULT_MATERIAL" |
| `configuredName` | string | Custom category display name | Use for PolicyName if present |
| `customCategory` | boolean | True if custom category | Determines processing path |
| `type` | string | Category type | Must be "URL_CATEGORY" |
| `urls` | array | Array of URLs/FQDNs/IP Addresses | Combine with dbCategorizedUrls |
| `dbCategorizedUrls` | array | Array of URLs/FQDNs/IP Addresses | Combine with urls |
| `description` | string | Category description | Maps to Web Content Filtering Description in output |

#### Processing Rules
1. **Type Filtering:** Only process entries where `type` = "URL_CATEGORY"
   - Log and skip other types at WARN level

2. **Custom Categories (`customCategory: true`):**
   - Combine and deduplicate `urls` and `dbCategorizedUrls` arrays
   - Classify each entry as URL, FQDN, or IP address
   - Group entries by type and base domain
   - Apply character limits and split as needed

3. **Predefined Categories (`customCategory: false`):**
   - Map using ZIA2EIA-CategoryMappings.json
   - No URL list processing required
   - Reference by category ID in rules

4. **Empty Categories:**
   - Log and skip custom categories with no URLs at WARN level

### 3. ZIA2EIA-CategoryMappings.json
**Source:** Manual configuration file (maintained by user)  
**Required:** Yes  
**Default Path:** `ZIA2EIA-CategoryMappings.json` (in script root directory)

#### Description
Provides mapping between ZScaler predefined web categories and Microsoft GSA (Global Secure Access) web categories.

#### Schema

```json
{
  "LastUpdated": "2025-10-09",
  "MappingData": [
    {
      "ZIACategory": "OTHER_ADULT_MATERIAL",
      "ZIADescription": "Sites that contain adult-oriented content",
      "ExampleURLs": "www.example.com, www.example.org",
      "GSACategory": "AdultContent",
      "MappingNotes": "Mapped based on semantic similarity"
    }
  ]
}
```

#### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ZIACategory` | string | Yes | ZIA category ID (matches `urlCategories` entries) |
| `ZIADescription` | string | No | Category description for reference |
| `ExampleURLs` | string | No | Sample URLs for documentation |
| `GSACategory` | string | Yes | Target GSA category name |
| `MappingNotes` | string | No | Mapping rationale |

#### Processing Rules
1. **Lookup:** For each predefined category ID, find matching `ZIACategory`
2. **Unmapped Categories:**
   - If `GSACategory` is null, blank, or "Unmapped": use placeholder format
   - Placeholder format: `[ZIACategoryID]_Unmapped`
   - Example: `OTHER_RELIGION` → `OTHER_RELIGION_Unmapped`
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
Contains all policies including web content filtering policies for custom URL categories and predefined category references.

#### Fields

| Field | Description | Example | Notes |
|-------|-------------|---------|-------|
| PolicyName | Policy name | "Custom_Web_Cat_01-Block" | Unique identifier |
| PolicyType | Type of policy | "WebContentFiltering" | Currently only "WebContentFiltering" supported |
| PolicyAction | Allow or Block | "Block", "Allow" | From rules or default |
| Description | Policy description | "Custom category for dev tools" | From category or generated |
| RuleType | Type of destination | "FQDN", "URL", "webCategory", "ipAddress" | One type per row |
| RuleDestinations | Semicolon-separated list | "*.example.com;site.com;other.com" | Max 300 chars |
| RuleName | Sub-rule identifier | "FQDNs1", "URLs2", "WebCategories1" | For grouping/splitting |
| ReviewNeeded | Manual review flag | "Yes", "No" | "Yes" if unmapped categories or CAUTION action |
| ReviewDetails | Reason for review | "Unmapped categories found; Rule action CAUTION converted to Block" | Semicolon-separated list of reasons |

#### PolicyName Format
- **Custom Categories:** 
  - Default: `[configuredName]-Block` or `[id]-Block`
  - If duplicated for Allow: `[configuredName]-Allow`
- **Predefined Categories (from rules):**
  - Format: `[RuleName]-WebCategories-[Action]`
  - Example: `urlRule1-WebCategories-Block`

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

### 2. Security Profiles CSV
**Filename:** `[yyyyMMdd_HHmmss]_EIA_SecurityProfiles.csv`

#### Description
Contains security profile definitions that reference web content filtering policies and assign them to users/groups.

#### Fields

| Field | Description | Example | Notes |
|-------|-------------|---------|-------|
| SecurityProfileName | Security profile name | "urlRule1" | From rule `name` |
| SecurityProfilePriority | Rule priority | "140" | `order` × 10 |
| EntraGroups | Semicolon-separated groups | "Group1;Group2;Group3" | From `groups[].name` |
| EntraUsers | Semicolon-separated emails | "user1@domain.com;user2@domain.com" | Parsed from users |
| PolicyLinks | Semicolon-separated policy names | "Custom_01-Block;urlRule1-WebCategories-Block" | References to policies |
| Description | Profile description | "Block adult content" | From rule `description` |

#### SecurityProfilePriority Calculation and Conflict Resolution
1. Calculate: `SecurityProfilePriority = order × 10`
2. Validate uniqueness across all rules
3. If conflict detected:
   - Add 1 to subsequent occurrence: `SecurityProfilePriority + 1`
   - Continue checking and incrementing until unique
   - Log conflict resolution at INFO level

#### EntraUsers Field
- Parse email from format: "Display Name (email@domain.com)"
- Extract text between parentheses
- Join multiple users with semicolon separator
- Empty if no valid users

#### EntraGroups Field
- Extract `name` attribute from each group
- Join multiple groups with semicolon separator
- If no users and no groups: "Replace_with_All_IA_Users_Group"

#### PolicyLinks Field
- Semicolon-separated list of PolicyName values
- Includes custom category policies
- Includes predefined category policy (one entry for all)
- Example: 3 links for rule with 2 custom + predefined categories

### 3. Log File
**Filename:** `[yyyyMMdd_HHmmss]_Convert-ZIA2EIA.log`  
**Location:** Same directory as output CSV files (`$OutputBasePath`)

#### Description
Comprehensive log file created by `Write-LogMessage` internal function with all processing details, warnings, and statistics.

---

## Processing Logic

### Phase 1: Data Loading and Validation

#### 1.1 Initialize Logging
```powershell
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath = Join-Path $OutputBasePath "${timestamp}_Convert-ZIA2EIA.log"
```

#### 1.2 Load Input Files
1. Load `url_filtering_policy.json`
   - Validate JSON structure
   - Fatal error if file missing or invalid
2. Load `url_categories.json`
   - Validate JSON structure
   - Fatal error if file missing or invalid
3. Load `ZIA2EIA-CategoryMappings.json`
   - Validate JSON structure
   - Fatal error if file missing or invalid

#### 1.3 Build Lookup Tables
- Create hashtable for category mappings (ZIACategory → GSACategory)
- Create hashtable for custom categories (id → category object)
- Create hashtable for custom category policies (id → policy info with BlockPolicyName/AllowPolicyName)
- Initialize collections for policies and security profiles

```powershell
# Category mappings for predefined categories
$categoryMappingsHashtable = @{}
foreach ($mapping in $categoryMappings.MappingData) {
    $categoryMappingsHashtable[$mapping.ZIACategory] = $mapping
}

# Custom categories for quick lookup
$customCategoriesHashtable = @{}
foreach ($category in $urlCategories | Where-Object { $_.customCategory -eq $true }) {
    $customCategoriesHashtable[$category.id] = $category
}

# Custom category policies tracking (populated in Phase 2)
$customCategoryPoliciesHashtable = @{}

# Collections for output
$policies = @()
$securityProfiles = @()
```

### Phase 2: Custom Category Processing

#### 2.1 Filter Custom Categories
```
For each category in url_categories:
    If type != "URL_CATEGORY":
        Log at WARN level
        Skip
    If customCategory != true:
        Skip (handle in Phase 3)
    If urls array empty AND dbCategorizedUrls array empty:
        Log at WARN level
        Skip
    Process custom category
```

#### 2.2 Deduplication and Cleaning
- Combine `urls` and `dbCategorizedUrls` arrays
- Remove duplicate entries (case-insensitive comparison)
- Log count of duplicates removed at DEBUG level
- Call `ConvertTo-CleanDestination` on each unique entry
- Remove entries where cleaning returns `$null`

**Rationale:** Deduplication is performed before cleaning and classification for performance efficiency. Processing fewer entries reduces execution time.

#### 2.3 URL/FQDN/IP Classification Algorithm

**Prerequisites:**
- Entries must be deduplicated
- Entries must be cleaned using `ConvertTo-CleanDestination`
- Null entries from cleaning are already skipped

**Classification Order (sequential checks):**

1. **Check for Empty String**
   - If empty or whitespace only: skip and continue (should not occur after cleaning)

2. **Check for IP Address**
   - Use `Get-DestinationType` to classify as `ipv4` or `ipv6`
   - If `ipv4`: Use `Test-ValidIPv4Address` to validate
     - If invalid: WARN and skip
     - If valid: classify as `ipAddress` for output
   - If `ipv6`: WARN and skip (not supported in current version)

3. **Check for Path Component**
   - If contains "/" character: classify as `URL`
   - Extract authority and path only (no schema, port, query, fragment)

4. **Check for Wildcard Position**
   - If starts with "*.": classify as `FQDN`
   - Example: `*.contoso.com` → FQDN
   - Note: `*.contoso.com` does NOT include `contoso.com`
   - If wildcard anywhere else: classify as `URL`
   - Example: `contoso*.com` → URL

5. **Clean Invalid Components**
   - Call `ConvertTo-CleanDestination` BEFORE classification
   - Function handles: schema, ports, query strings, fragments
   - If function returns `$null`: skip entry
   - If entry is cleaned: continue with classification

6. **Default Classification**
   - No path, no wildcard (or wildcard at start): `FQDN`
   - Example: `contoso.com` → FQDN

#### 2.4 Grouping by Base Domain

**Purpose:** Optimize number of rules by grouping related FQDNs/URLs together while respecting character limits.

**Base Domain Extraction:**
- Use last 2 segments of domain
- Example: `api.internal.company.com` → base domain: `company.com`
- Example: `www.site.com` → base domain: `site.com`
- **Note:** IP addresses do not have base domains and are not grouped by domain

**Grouping Logic:**

```powershell
# For FQDNs: Group by base domain
$fqdnsByBaseDomain = @{}
foreach ($fqdn in $classifiedDestinations['FQDN']) {
    $baseDomain = Get-BaseDomain -Domain $fqdn
    if (-not $fqdnsByBaseDomain.ContainsKey($baseDomain)) {
        $fqdnsByBaseDomain[$baseDomain] = @()
    }
    $fqdnsByBaseDomain[$baseDomain] += $fqdn
}

# For URLs: Group by base domain
$urlsByBaseDomain = @{}
foreach ($url in $classifiedDestinations['URL']) {
    $baseDomain = Get-BaseDomain -Domain $url
    if (-not $urlsByBaseDomain.ContainsKey($baseDomain)) {
        $urlsByBaseDomain[$baseDomain] = @()
    }
    $urlsByBaseDomain[$baseDomain] += $url
}

# For IP addresses: Keep as single collection (no domain grouping)
$ipAddresses = $classifiedDestinations['ipAddress']
```

**Splitting by Character Limit:**

```
For each base domain group (FQDNs or URLs):
    Calculate combined length (with semicolons)
    If > 300 characters:
        Split into multiple sub-groups using Split-ByCharacterLimit
        Respect individual entry boundaries (no truncation)
    Create policy entry for each sub-group
    RuleName: first = baseDomain, subsequent = baseDomain-2, baseDomain-3, etc.

For ipAddress collection:
    Calculate combined length (with semicolons)
    If > 300 characters:
        Split into multiple sub-groups using Split-ByCharacterLimit
        Respect individual entry boundaries (no truncation)
    Create policy entry for each sub-group
    RuleName: first = "IPs", subsequent = "IPs-2", "IPs-3", etc.
```

**Note:** Web categories (`webCategory` type) are never grouped or split by character limit. All web categories for a rule are placed in a single policy entry regardless of length.

#### 2.5 Character Limit Splitting

**Limit:** 300 characters (excluding field quotes, including semicolons)
**Applies to:** FQDN, URL, and ipAddress types only (NOT webCategory)

**Splitting Algorithm:**
```
currentLength = 0
currentGroup = []
groupNumber = 1

For each entry in group:
    entryLength = entry.Length
    If currentLength + entryLength + 1 > 300:  // +1 for semicolon
        Create policy entry with currentGroup
        RuleName = "{baseDomain}" (first) or "{baseDomain}-{groupNumber}" (subsequent)
        groupNumber++
        currentGroup = [entry]
        currentLength = entryLength
    Else:
        currentGroup.Add(entry)
        currentLength += entryLength + 1  // +1 for semicolon

Create policy entry with remaining currentGroup
```

**RuleName Format:**
- **For FQDNs and URLs (grouped by base domain):**
  - First group: Base domain name (e.g., `example.com`, `contoso.com`)
  - Subsequent groups: Base domain with suffix (e.g., `example.com-2`, `example.com-3`)
- **For IP addresses:**
  - First group: `IPs`
  - Subsequent groups: `IPs-2`, `IPs-3`, etc.
- **For Web Categories:**
  - Always: `WebCategories` (no splitting, no numeric suffix)

#### 2.6 Policy Entry Creation (Custom Categories)

For each custom category and destination type:

```powershell
# Determine policy name
$basePolicyName = if ($category.configuredName) { $category.configuredName } else { $category.id }
$policyName = "$basePolicyName-Block"

# Process FQDNs grouped by base domain
if ($classifiedDestinations['FQDN'].Count -gt 0) {
    # Group FQDNs by base domain
    $fqdnsByBaseDomain = @{}
    foreach ($fqdn in $classifiedDestinations['FQDN']) {
        $baseDomain = Get-BaseDomain -Domain $fqdn
        if (-not $fqdnsByBaseDomain.ContainsKey($baseDomain)) {
            $fqdnsByBaseDomain[$baseDomain] = @()
        }
        $fqdnsByBaseDomain[$baseDomain] += $fqdn
    }
    
    # Create policy entries for each base domain group
    foreach ($baseDomain in $fqdnsByBaseDomain.Keys) {
        $groups = Split-ByCharacterLimit -Entries $fqdnsByBaseDomain[$baseDomain] -MaxLength 300
        
        for ($i = 0; $i -lt $groups.Count; $i++) {
            $ruleName = if ($i -eq 0) { $baseDomain } else { "$baseDomain-$($i + 1)" }
            
            $policyEntry = @{
                PolicyName = $policyName
                PolicyType = "WebContentFiltering"
                PolicyAction = "Block"
                Description = $category.description
                RuleType = "FQDN"
                RuleDestinations = $groups[$i] -join ";"
                RuleName = $ruleName
                ReviewNeeded = "No"
                ReviewDetails = ""
            }
            
            $policies += $policyEntry
        }
    }
}

# Process URLs grouped by base domain
if ($classifiedDestinations['URL'].Count -gt 0) {
    # Group URLs by base domain
    $urlsByBaseDomain = @{}
    foreach ($url in $classifiedDestinations['URL']) {
        $baseDomain = Get-BaseDomain -Domain $url
        if (-not $urlsByBaseDomain.ContainsKey($baseDomain)) {
            $urlsByBaseDomain[$baseDomain] = @()
        }
        $urlsByBaseDomain[$baseDomain] += $url
    }
    
    # Create policy entries for each base domain group
    foreach ($baseDomain in $urlsByBaseDomain.Keys) {
        $groups = Split-ByCharacterLimit -Entries $urlsByBaseDomain[$baseDomain] -MaxLength 300
        
        for ($i = 0; $i -lt $groups.Count; $i++) {
            $ruleName = if ($i -eq 0) { $baseDomain } else { "$baseDomain-$($i + 1)" }
            
            $policyEntry = @{
                PolicyName = $policyName
                PolicyType = "WebContentFiltering"
                PolicyAction = "Block"
                Description = $category.description
                RuleType = "URL"
                RuleDestinations = $groups[$i] -join ";"
                RuleName = $ruleName
                ReviewNeeded = "No"
                ReviewDetails = ""
            }
            
            $policies += $policyEntry
        }
    }
}

# Process IP addresses (not grouped by domain)
if ($classifiedDestinations['ipAddress'].Count -gt 0) {
    $groups = Split-ByCharacterLimit -Entries $classifiedDestinations['ipAddress'] -MaxLength 300
    
    for ($i = 0; $i -lt $groups.Count; $i++) {
        $ruleName = if ($i -eq 0) { "IPs" } else { "IPs-$($i + 1)" }
        
        $policyEntry = @{
            PolicyName = $policyName
            PolicyType = "WebContentFiltering"
            PolicyAction = "Block"
            Description = $category.description
            RuleType = "ipAddress"
            RuleDestinations = $groups[$i] -join ";"
            RuleName = $ruleName
            ReviewNeeded = "No"
            ReviewDetails = ""
        }
        
        $policies += $policyEntry
    }
}

# Track this custom category policy for Phase 3 lookup
$customCategoryPoliciesHashtable[$category.id] = @{
    BlockPolicyName = $policyName
    AllowPolicyName = $null  # Will be populated in Phase 3 if needed
    BaseName = $basePolicyName
}
```

**Important:** Each policy entry is added to `$policies` collection, and the policy name is tracked in `$customCategoryPoliciesHashtable` for efficient lookup during Phase 3 rule processing.

### Phase 3: URL Filtering Rule Processing

#### 3.1 Filter Rules
```
For each rule in url_filtering_policy:
    If state != "ENABLED":
        Increment disabledCount
        Log name at DEBUG level
        Skip
    Process rule
```

#### 3.2 Extract Users and Groups

**Users:**
```powershell
$validUsers = @()
foreach ($user in $rule.users) {
    if ($user.deleted -eq $true) {
        Write-LogMessage "Skipping deleted user: $($user.name)" -Level "DEBUG"
        continue
    }
    
    # Parse email from "Display Name (email@domain.com)"
    if ($user.name -match '\(([^)]+)\)') {
        $email = $Matches[1]
        $validUsers += $email
    }
    else {
        Write-LogMessage "Could not parse email from: $($user.name)" -Level "WARN"
    }
}
```

**Groups:**
```powershell
$groups = $rule.groups | ForEach-Object { $_.name }
```

**Default Assignment:**
```powershell
if ($validUsers.Count -eq 0 -and $groups.Count -eq 0) {
    $groups = @("Replace_with_All_IA_Users_Group")
}
```

#### 3.3 Process URL Categories

**Separate Custom from Predefined:**
```powershell
$customCategoryRefs = @()
$predefinedCategoryRefs = @()

foreach ($categoryId in $rule.urlCategories) {
    if ($customCategoriesHashtable.ContainsKey($categoryId)) {
        $customCategoryRefs += $categoryId
    }
    else {
        $predefinedCategoryRefs += $categoryId
    }
}
```

#### 3.4 Policy Action Update (Custom Categories)

For each custom category referenced by the rule, determine the appropriate policy name based on the rule's action:

```powershell
$customCategoryPolicyNames = @()
$needsReview = $false
$reviewReasons = @()

foreach ($customCatId in $customCategoryRefs) {
    # Look up policy info from Phase 2
    $policyInfo = $customCategoryPoliciesHashtable[$customCatId]
    
    if ($null -eq $policyInfo) {
        Write-LogMessage "Custom category policy not found: $customCatId" -Level "WARN"
        continue
    }
    
    # Determine which policy to use based on action
    if ($rule.action -eq "BLOCK") {
        # Use existing Block policy
        $customCategoryPolicyNames += $policyInfo.BlockPolicyName
    }
    elseif ($rule.action -eq "CAUTION") {
        # Convert CAUTION to BLOCK and flag for review
        Write-LogMessage "Rule '$($rule.name)': Converting CAUTION action to BLOCK for category $customCatId" -Level "WARN"
        $customCategoryPolicyNames += $policyInfo.BlockPolicyName
        
        if ("Rule action CAUTION converted to Block" -notin $reviewReasons) {
            $reviewReasons += "Rule action CAUTION converted to Block"
        }
        $needsReview = $true
    }
    elseif ($rule.action -eq "ALLOW") {
        # Check if Allow version exists
        if ($null -eq $policyInfo.AllowPolicyName) {
            # Need to create Allow version by duplicating Block policies
            $allowPolicyName = "$($policyInfo.BaseName)-Allow"
            
            # Find all policy entries with the Block policy name and duplicate them
            $blockPolicies = $policies | Where-Object { $_.PolicyName -eq $policyInfo.BlockPolicyName }
            
            foreach ($blockPolicy in $blockPolicies) {
                # Manually create new hashtable with copied values
                $allowPolicy = @{
                    PolicyName = $allowPolicyName
                    PolicyType = $blockPolicy.PolicyType
                    PolicyAction = "Allow"
                    Description = $blockPolicy.Description
                    RuleType = $blockPolicy.RuleType
                    RuleDestinations = $blockPolicy.RuleDestinations
                    RuleName = $blockPolicy.RuleName
                    ReviewNeeded = $blockPolicy.ReviewNeeded
                    ReviewDetails = $blockPolicy.ReviewDetails
                }
                
                # Add to policies collection
                $policies += $allowPolicy
            }
            
            # Update tracking hashtable
            $policyInfo.AllowPolicyName = $allowPolicyName
            
            Write-LogMessage "Created Allow version of policy: $allowPolicyName" -Level "INFO"
        }
        
        # Use the Allow policy
        $customCategoryPolicyNames += $policyInfo.AllowPolicyName
    }
}
```

**Key Points:**
- Looks up policy info from `$customCategoryPoliciesHashtable` (populated in Phase 2)
- For BLOCK actions: uses existing Block policy
- For CAUTION actions: uses existing Block policy, logs WARN message, and tracks review reason
- For ALLOW actions: creates Allow version if it doesn't exist by duplicating all Block policy entries (preserves ReviewNeeded/ReviewDetails)
- Updates tracking hashtable so subsequent rules can reuse the Allow policy
- Stores policy names in `$customCategoryPolicyNames` array for use in security profile
- Accumulates review reasons in `$reviewReasons` array for later use

**Example:**
- Custom category: "CUSTOM_01" has 3 policy entries (FQDNs, URLs, IPs)
- Initial policies: all named "CUSTOM_01-Block" with PolicyAction "Block"
- Rule1 (Block) references CUSTOM_01 → uses "CUSTOM_01-Block"
- Rule2 (Allow) references CUSTOM_01 → creates 3 new policies named "CUSTOM_01-Allow" with PolicyAction "Allow"
- Rule3 (Allow) references CUSTOM_01 → reuses "CUSTOM_01-Allow" (already exists)

#### 3.5 Policy Creation (Predefined Categories)

If rule references predefined categories:

```powershell
$predefinedPolicyName = $null

if ($predefinedCategoryRefs.Count -gt 0) {
    $mappedCategories = @()
    $hasUnmapped = $false

    foreach ($categoryId in $predefinedCategoryRefs) {
        $mapping = $categoryMappingsHashtable[$categoryId]
        
        if ($null -eq $mapping -or 
            [string]::IsNullOrWhiteSpace($mapping.GSACategory) -or
            $mapping.GSACategory -eq 'Unmapped') {
            
            $mappedCategories += "${categoryId}_Unmapped"
            $hasUnmapped = $true
            Write-LogMessage "Unmapped category: $categoryId" -Level "INFO"
        }
        else {
            $mappedCategories += $mapping.GSACategory
        }
    }
    
    # Handle CAUTION action conversion
    $finalAction = $rule.action
    if ($rule.action -eq "CAUTION") {
        Write-LogMessage "Rule '$($rule.name)': Converting CAUTION action to BLOCK for predefined categories" -Level "WARN"
        $finalAction = "BLOCK"
        if ("Rule action CAUTION converted to Block" -notin $reviewReasons) {
            $reviewReasons += "Rule action CAUTION converted to Block"
        }
        $needsReview = $true
    }
    
    # Build review reasons
    $policyReviewReasons = @()
    if ($hasUnmapped) {
        $policyReviewReasons += "Unmapped categories found"
        $needsReview = $true
    }
    if ($finalAction -ne $rule.action) {
        $policyReviewReasons += "Rule action CAUTION converted to Block"
    }

    $policyEntry = @{
        PolicyName = "$($rule.name)-WebCategories-$($finalAction.Substring(0,1) + $finalAction.Substring(1).ToLower())"
        PolicyType = "WebContentFiltering"
        PolicyAction = if ($finalAction -eq "ALLOW") { "Allow" } else { "Block" }
        Description = "Converted from $($rule.name) categories"
        RuleType = "webCategory"
        RuleDestinations = $mappedCategories -join ";"  # No character limit for web categories
        RuleName = "WebCategories"  # Never split, no numeric suffix
        ReviewNeeded = if ($needsReview) { "Yes" } else { "No" }
        ReviewDetails = $policyReviewReasons -join "; "
    }
    
    # Add to policies collection
    $policies += $policyEntry
    
    # Store the created policy name for reference in security profile
    $predefinedPolicyName = $policyEntry.PolicyName
}
```

**PolicyName Examples:**
- Rule "urlRule1" with action "BLOCK" → "urlRule1-WebCategories-Block"
- Rule "urlRule2" with action "ALLOW" → "urlRule2-WebCategories-Allow"

**Important:** The policy is added to the `$policies` collection and the policy name is stored in `$predefinedPolicyName` variable for use in security profile creation (Section 3.6).

**Note on Custom Category Policy Updates:**
After processing custom categories for this rule, if `$needsReview` is true and custom category policies were used, update those policies with review information:

```powershell
# Update custom category policies with review information if needed
if ($needsReview -and $customCategoryPolicyNames.Count -gt 0 -and $reviewReasons.Count -gt 0) {
    foreach ($policyName in $customCategoryPolicyNames) {
        # Find all policy entries with this policy name and update them
        for ($i = 0; $i -lt $policies.Count; $i++) {
            if ($policies[$i].PolicyName -eq $policyName) {
                $policies[$i].ReviewNeeded = "Yes"
                
                # Merge review reasons (avoid duplicates)
                $existingReasons = if ($policies[$i].ReviewDetails) { 
                    $policies[$i].ReviewDetails -split "; " 
                } else { 
                    @() 
                }
                
                foreach ($reason in $reviewReasons) {
                    if ($reason -notin $existingReasons) {
                        $existingReasons += $reason
                    }
                }
                
                $policies[$i].ReviewDetails = $existingReasons -join "; "
            }
        }
    }
}
```

#### 3.6 Security Profile Creation

```powershell
$policyLinks = @()

# Add custom category policy references (from Section 3.4)
if ($customCategoryPolicyNames.Count -gt 0) {
    $policyLinks += $customCategoryPolicyNames
}

# Add predefined category policy reference (from Section 3.5)
if ($null -ne $predefinedPolicyName) {
    $policyLinks += $predefinedPolicyName
}

$securityProfile = @{
    SecurityProfileName = $rule.name
    SecurityProfilePriority = $rule.order * 10
    EntraGroups = $groups -join ";"
    EntraUsers = $validUsers -join ";"
    PolicyLinks = $policyLinks -join ";"
    Description = $rule.description
}

# Add to security profiles collection
$securityProfiles += $securityProfile
```

**Key Points:**
- Uses `$customCategoryPolicyNames` array populated in Section 3.4 (not reconstructing names)
- Uses `$predefinedPolicyName` variable set in Section 3.5 (if predefined categories exist)
- **Adds the security profile to `$securityProfiles` collection**
- All policy names are guaranteed to match actually created policies
- Clear data flow: policy creation → store name → reference in security profile
- **Important:** PolicyLinks contains policy names (e.g., "CUSTOM_01-Block"), not individual rule names within those policies. A custom category with 3 destination types (FQDN, URL, ipAddress) creates 3 CSV rows sharing the same PolicyName, but only ONE policy name goes into PolicyLinks.

#### 3.7 Priority Conflict Resolution

```powershell
$priorityTracker = @{}

foreach ($profile in $securityProfiles) {
    $originalPriority = $profile.SecurityProfilePriority
    
    while ($priorityTracker.ContainsKey($profile.SecurityProfilePriority)) {
        Write-LogMessage "Priority conflict at $($profile.SecurityProfilePriority), incrementing" -Level "INFO"
        $profile.SecurityProfilePriority++
    }
    
    $priorityTracker[$profile.SecurityProfilePriority] = $profile.SecurityProfileName
}
```

#### 3.8 Cleanup Unreferenced Policies

After all security profiles are created, remove custom category policies that are not referenced by any security profile:

```powershell
# Collect all policy names referenced in security profiles
$referencedPolicies = @{}
foreach ($profile in $securityProfiles) {
    $policyNames = $profile.PolicyLinks -split ';'
    foreach ($policyName in $policyNames) {
        $referencedPolicies[$policyName] = $true
    }
}

# Remove unreferenced custom category policies
$policies = $policies | Where-Object {
    # Keep predefined category policies (they're created per-rule)
    if ($_.RuleType -eq 'webCategory') {
        return $true
    }
    
    # Keep custom category policies that are referenced
    if ($referencedPolicies.ContainsKey($_.PolicyName)) {
        return $true
    }
    
    # Remove unreferenced custom category policy (silently)
    return $false
}
```

**Purpose:** Avoid creating unused "-Block" policies when the first filtering rule referencing a custom category has action "ALLOW". Phase 2 creates all custom categories with "-Block" suffix by default, but if no rule actually uses the Block version, it should be removed.

**Example:**
- Custom category "CUSTOM_01" processed in Phase 2 → creates "CUSTOM_01-Block"
- Only rule referencing CUSTOM_01 has action "ALLOW" → creates "CUSTOM_01-Allow" in Phase 3
- Cleanup removes "CUSTOM_01-Block" since no security profile references it

### Phase 4: Export and Summary

#### 4.1 Export Policies CSV
```powershell
$policies | Export-Csv -Path $policiesCsvPath -NoTypeInformation
Write-LogMessage "Exported $($policies.Count) policies to: $policiesCsvPath" -Level "INFO"
```

#### 4.2 Export Security Profiles CSV
```powershell
$securityProfiles | Export-Csv -Path $spCsvPath -NoTypeInformation
Write-LogMessage "Exported $($securityProfiles.Count) security profiles to: $spCsvPath" -Level "INFO"
```

#### 4.3 Generate Summary Statistics

Log the following at INFO level:

```
=== CONVERSION SUMMARY ===
Total rules loaded: X
Rules processed (enabled): Y
Rules skipped (disabled): Z

Custom categories processed: A
Custom categories skipped (empty): B
Predefined categories referenced: C
Unmapped predefined categories: D

Policies created: E
  - Custom category policies: E1
  - Predefined category policies: E2
Security profiles created: F

URLs classified: U
FQDNs classified: N
IP addresses classified: I

Groups created from splitting: G
Priority conflicts resolved: P

Output files:
  - Policies: [path]
  - Security Profiles: [path]
  - Log File: [path]
```

#### 4.4 Memory Cleanup
PowerShell automatically handles memory cleanup when variables go out of scope. For explicit cleanup:
```powershell
# Variables are cleaned up automatically when function exits
# No special cleanup needed in PowerShell
```

---

## Function Parameters

### Required Parameters
None (all have defaults)

### Optional Parameters

| Parameter | Type | Default | Description | Validation |
|-----------|------|---------|-------------|------------|
| UrlFilteringPolicyPath | string | `url_filtering_policy.json` | Path to policy file | ValidateScript - file must exist |
| UrlCategoriesPath | string | `url_categories.json` | Path to categories file | ValidateScript - file must exist |
| CategoryMappingsPath | string | `ZIA2EIA-CategoryMappings.json` | Path to mappings file | ValidateScript - file must exist |
| OutputBasePath | string | `$PWD` | Output directory for CSV and log files | ValidateScript - directory must exist |
| EnableDebugLogging | switch | `false` | Enable DEBUG level logging | None |

### Parameter Definitions

```powershell
[CmdletBinding(SupportsShouldProcess = $false)]
param(
    [Parameter(HelpMessage = "Path to ZIA URL Filtering Policy JSON export")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$UrlFilteringPolicyPath = (Join-Path $PWD "url_filtering_policy.json"),
    
    [Parameter(HelpMessage = "Path to ZIA URL Categories JSON export")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$UrlCategoriesPath = (Join-Path $PWD "url_categories.json"),
    
    [Parameter(HelpMessage = "Path to ZIA to EIA category mappings JSON file")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$CategoryMappingsPath = (Join-Path $PWD "ZIA2EIA-CategoryMappings.json"),
    
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

### Parameters NOT Included
- No filtering parameters (no TargetAppSegmentName equivalent)
- No PassThru parameter
- No batch size or processing limit parameters

### Parameter Validation Notes
- **File paths:** All input file parameters use `[ValidateScript()]` to ensure files exist before processing begins
- **OutputBasePath:** Validates that the directory exists using `-PathType Container`
- **Default paths:** Use `Join-Path $PWD` to construct default paths relative to current directory (matching Convert-ZPA2EPA pattern)
- **Error messages:** Validation throws descriptive errors if files/directories are missing

---

## Internal Helper Functions

### Functions to Create (New)

#### 1. Get-DestinationType
**Purpose:** Classify destination entry as URL, FQDN, IPv4, or IPv6 address

**Returns:** `'FQDN'`, `'URL'`, `'ipv4'`, `'ipv6'`, or `$null` (for empty/invalid entries)

**Logic:**
```powershell
function Get-DestinationType {
    param([string]$Destination)
    
    # Empty check
    if ([string]::IsNullOrWhiteSpace($Destination)) { return $null }
    
    # IPv4 check (basic validation)
    if ($Destination -match '^(\d{1,3}\.){3}\d{1,3}$') { return 'ipv4' }
    
    # IPv6 detection (contains multiple colons)
    if ($Destination -match ':.*:') { return 'ipv6' }
    
    # Path check - URLs contain forward slash
    if ($Destination -like '*/*') { return 'URL' }
    
    # Wildcard position check
    if ($Destination -like '*.*') {
        if ($Destination.StartsWith('*.')) { return 'FQDN' }
        else { return 'URL' }  # Wildcard elsewhere makes it URL pattern
    }
    
    # Default to FQDN
    return 'FQDN'
}
```

**Notes:**
- Function performs basic type detection without validation
- Calling code is responsible for skipping unsupported types (ipv6)
- Use `ConvertTo-CleanDestination` before calling for best results
- Use `Test-ValidIPv4Address` to validate IPv4 addresses before use

#### 2. Get-BaseDomain
**Purpose:** Extract base domain (last 2 segments) for grouping

**Logic:**
```powershell
function Get-BaseDomain {
    param([string]$Domain)
    
    # Remove leading wildcard if present
    $cleanDomain = $Domain -replace '^\*\.', ''
    
    # Extract path-free domain for URLs
    if ($cleanDomain -like '*/*') {
        $cleanDomain = $cleanDomain.Split('/')[0]
    }
    
    # Get last 2 segments
    $segments = $cleanDomain.Split('.')
    if ($segments.Count -ge 2) {
        return "$($segments[-2]).$($segments[-1])"
    }
    
    return $cleanDomain
}
```

#### 3. Test-ValidIPv4Address
**Purpose:** Validate IPv4 address format (used by calling code to decide if address should be skipped)

**Returns:** `$true` if valid IPv4 address, `$false` otherwise

**Logic:**
```powershell
function Test-ValidIPv4Address {
    param([string]$IpAddress)
    
    # Must match IPv4 pattern
    if ($IpAddress -notmatch '^(\d{1,3}\.){3}\d{1,3}$') { return $false }
    
    # Validate each octet is 0-255
    $octets = $IpAddress.Split('.')
    foreach ($octet in $octets) {
        $num = [int]$octet
        if ($num -lt 0 -or $num -gt 255) { return $false }
    }
    
    return $true
}
```

**Notes:**
- Use after `ConvertTo-CleanDestination` has been called
- Does not accept CIDR notation, ports, or paths
- Calling code should log and skip invalid IPv4 addresses

#### 4. Split-UserEmail
**Purpose:** Extract email from "Display Name (email@domain.com)" format

**Logic:**
```powershell
function Split-UserEmail {
    param([string]$UserName)
    
    if ($UserName -match '\(([^)]+)\)') {
        return $Matches[1]
    }
    
    Write-LogMessage "Could not parse email from: $UserName" -Level "WARN"
    return $null
}
```

#### 5. Split-ByCharacterLimit
**Purpose:** Split destination arrays by character limit without truncating entries (for FQDN, URL, ipAddress only - NOT for webCategory)

**Logic:**
```powershell
function Split-ByCharacterLimit {
    param(
        [array]$Entries,
        [int]$MaxLength = 300
    )
    
    $groups = @()
    $currentGroup = @()
    $currentLength = 0
    
    foreach ($entry in $Entries) {
        $entryLength = $entry.Length
        $separator = if ($currentGroup.Count -gt 0) { 1 } else { 0 }  # semicolon
        
        if (($currentLength + $entryLength + $separator) -gt $MaxLength -and $currentGroup.Count -gt 0) {
            # Current group is full, start new group
            $groups += ,@($currentGroup)
            $currentGroup = @($entry)
            $currentLength = $entryLength
        }
        else {
            $currentGroup += $entry
            $currentLength += $entryLength + $separator
        }
    }
    
    # Add remaining group
    if ($currentGroup.Count -gt 0) {
        $groups += ,@($currentGroup)
    }
    
    return $groups
}
```

#### 6. Get-CustomCategoryPolicyName
**Purpose:** Look up custom category policy name based on category ID and action, handling Block/Allow duplication

**Returns:** Policy name string, or `$null` if policy not found

**Logic:**
```powershell
function Get-CustomCategoryPolicyName {
    param(
        [string]$CategoryId,
        [string]$Action,
        [hashtable]$CustomCategoryPoliciesHashtable
    )
    
    # Get base policy info from hashtable (created in Phase 2)
    $basePolicyInfo = $CustomCategoryPoliciesHashtable[$CategoryId]
    
    if ($null -eq $basePolicyInfo) {
        Write-LogMessage "Custom category not found: $CategoryId" -Level "WARN"
        return $null
    }
    
    # If action is BLOCK or CAUTION, use the base policy (created with -Block suffix in Phase 2)
    if ($Action -eq "BLOCK" -or $Action -eq "CAUTION") {
        return $basePolicyInfo.BlockPolicyName
    }
    
    # If action is ALLOW, check if Allow version exists, if not return null (will be created)
    if ($Action -eq "ALLOW") {
        if ($null -ne $basePolicyInfo.AllowPolicyName) {
            return $basePolicyInfo.AllowPolicyName
        }
        return $null  # Signal that Allow policy needs to be created
    }
    
    # Default to Block policy for unknown actions
    return $basePolicyInfo.BlockPolicyName
}
```

**Notes:**
- Uses `$CustomCategoryPoliciesHashtable` created in Phase 2 for fast lookup
- Returns `$null` for ALLOW action if Allow policy doesn't exist yet (caller creates it)
- Returns Block policy for CAUTION action (caller is responsible for logging and setting review flags)

#### 7. ConvertTo-CleanDestination
**Purpose:** Clean and normalize destination entries by removing unsupported components (schema, port, query, fragment)

**Returns:** Cleaned destination string, or `$null` if entry should be skipped

**Logic:**
```powershell
function ConvertTo-CleanDestination {
    param(
        [string]$Destination,
        [string]$LogPath,
        [bool]$EnableDebugLogging
    )
    
    if ([string]::IsNullOrWhiteSpace($Destination)) { return $null }
    
    $cleaned = $Destination.Trim()
    $modified = $false
    
    # Remove schema (http:// or https://)
    if ($cleaned -match '^https?://') {
        Write-LogMessage "Removing schema from: $Destination" -Level "WARN" `
            -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging $EnableDebugLogging
        $cleaned = $cleaned -replace '^https?://', ''
        $modified = $true
    }
    
    # Check for IPv4 with port/path (should be skipped)
    if ($cleaned -match '^(\d{1,3}\.){3}\d{1,3}[:/]') {
        Write-LogMessage "Skipping IPv4 with port/path: $Destination" -Level "WARN" `
            -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging $EnableDebugLogging
        return $null
    }
    
    # Remove port (for non-IP entries)
    if ($cleaned -match ':\d+' -and $cleaned -notmatch '^(\d{1,3}\.){3}\d{1,3}$') {
        Write-LogMessage "Removing port from: $Destination" -Level "WARN" `
            -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging $EnableDebugLogging
        $cleaned = $cleaned -replace ':\d+', ''
        $modified = $true
    }
    
    # Remove query string
    if ($cleaned -like '*?*') {
        Write-LogMessage "Removing query string from: $Destination" -Level "WARN" `
            -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging $EnableDebugLogging
        $cleaned = $cleaned.Split('?')[0]
        $modified = $true
    }
    
    # Remove fragment
    if ($cleaned -like '*#*') {
        Write-LogMessage "Removing fragment from: $Destination" -Level "WARN" `
            -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging $EnableDebugLogging
        $cleaned = $cleaned.Split('#')[0]
        $modified = $true
    }
    
    # Return null if cleaning resulted in empty string
    if ([string]::IsNullOrWhiteSpace($cleaned)) {
        Write-LogMessage "Destination became empty after cleaning: $Destination" -Level "WARN" `
            -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging $EnableDebugLogging
        return $null
    }
    
    return $cleaned
}
```

**Notes:**
- Call this function BEFORE `Get-DestinationType` for best results
- Returns `$null` for entries that should be skipped (e.g., IPv4 with port/path)
- Logs all modifications at WARN level
- Generic function suitable for reuse in other conversion functions

### Functions to Reuse from Convert-ZPA2EPA

#### 1. Write-LogMessage
**Location:** `Migrate2GSA\internal\functions\Write-LogMessage.ps1`  
**Purpose:** Write structured log messages to console and file with levels (INFO, WARN, ERROR, DEBUG)

**Usage:**
```powershell
Write-LogMessage "Processing custom category: $categoryName" -Level "INFO" `
    -Component "Convert-ZIA2EIA" -LogPath $logPath -EnableDebugLogging $EnableDebugLogging
```

#### 2. Export-DataToFile
**Source:** Convert-ZPA2EPA.ps1  
**Purpose:** Export PowerShell objects to CSV with consistent formatting

**Should Extract:** Yes, to shared internal functions module for reuse

**Usage:**
```powershell
Export-DataToFile -Data $policies -FilePath $policiesCsvPath -FileType "CSV"
```

#### 3. Test-WildcardMatch
**Source:** Convert-ZPA2EPA.ps1  
**Purpose:** Test if a string matches a wildcard pattern (* and ?)

**Should Extract:** Yes, to shared internal functions module for reuse (if filtering added later)

**Usage:**
```powershell
if (Test-WildcardMatch -String $categoryName -Pattern "Custom*") { ... }
```

#### 4. Clear-Domain
**Source:** Convert-ZPA2EPA.ps1  
**Purpose:** Clean domain names by removing wildcards and paths

**Should Extract:** Yes, could be adapted for URL cleaning

**Usage:**
```powershell
$cleanDomain = Clear-Domain -Domain "*.example.com"
```

---

## Logging Specifications

### Log Levels and Usage

| Level | Usage | Examples |
|-------|-------|----------|
| INFO | Major milestones, counts, file operations | "Loaded 42 rules", "Exported policies" |
| WARN | Skipped items, unmapped categories, data issues | "Skipping IP with port", "Unmapped category" |
| ERROR | Fatal errors, missing files, invalid JSON | "File not found", "Invalid JSON format" |
| DEBUG | Individual item processing, detailed flow | "Processing rule: urlRule1", "Skipped deleted user" |

### Progress Reporting

**Not included in initial implementation.** The script is expected to process data quickly for typical ZIA configurations. Progress reporting can be added in future enhancements if needed for larger datasets.

### Statistics to Track and Log

Track these counters throughout processing:

```powershell
$stats = @{
    # Rules
    TotalRulesLoaded = 0
    RulesProcessed = 0
    RulesSkippedDisabled = 0
    
    # Categories
    CustomCategoriesProcessed = 0
    CustomCategoriesSkipped = 0
    PredefinedCategoriesReferenced = 0
    UnmappedCategories = 0
    
    # Classifications
    URLsClassified = 0
    FQDNsClassified = 0
    IPsClassified = 0
    EntriesSkipped = 0
    
    # Users/Groups
    UsersProcessed = 0
    UsersSkippedDeleted = 0
    GroupsProcessed = 0
    
    # Outputs
    PoliciesCreated = 0
    SecurityProfilesCreated = 0
    GroupsSplitForCharLimit = 0
    PriorityConflictsResolved = 0
}
```

---

## Error Handling

### Fatal Errors (Stop Processing)

| Error | Condition | Action |
|-------|-----------|--------|
| Missing input file | File not found | Throw error, exit |
| Invalid JSON | JSON parse error | Throw error, exit |
| No enabled rules | All rules disabled | Throw error, exit |
| Invalid output path | Directory doesn't exist | Throw error, exit |

```powershell
if (-not (Test-Path $UrlFilteringPolicyPath)) {
    throw "URL filtering policy file not found: $UrlFilteringPolicyPath"
}
```

### Non-Fatal Errors (Log and Continue)

| Error | Condition | Action |
|-------|-----------|--------|
| Malformed URL | Invalid format | WARN, skip entry |
| IP with port/path | Contains ":/" | WARN, skip entry |
| IPv6 address | Multiple colons | WARN, skip entry |
| Deleted user | deleted = true | DEBUG, skip user |
| Empty category | No URLs | WARN, skip category |
| Unmapped category | No GSA mapping | INFO, use placeholder |
| Email parse fail | Invalid format | WARN, skip user |

```powershell
try {
    # Process entry
}
catch {
    Write-LogMessage "Error processing entry: $_" -Level "WARN"
    continue
}
```

---

## Sample Files

### Location
All sample files should be created in: `c:\Git\Migrate2GSAPublic\Samples\ZIA2EIA\`

### Required Samples

#### 1. sample_url_filtering_policy.json
**Content:** 3-4 rules demonstrating:
- Rule with users and groups
- Rule with no users/groups (→ "Replace_with_All_IA_Users_Group")
- Rule with custom categories
- Rule with predefined categories
- Rule with both custom and predefined
- Mix of ALLOW and BLOCK actions
- Rules with different order values

#### 2. sample_url_categories.json
**Content:** 4-5 categories demonstrating:
- Custom category with URLs
- Custom category with FQDNs
- Custom category with mix of URLs, FQDNs, IPs
- Custom category with wildcards
- Predefined category references

#### 3. sample_ZIA2EIA-CategoryMappings.json
**Content:** 10-15 mappings demonstrating:
- Mapped categories (with GSACategory)
- Unmapped categories (GSACategory = "Unmapped")
- Various category types

#### 4. sample_output_Policies.csv
**Content:** Expected output showing:
- Custom category policies
- Predefined category policies
- PolicyType field with "WebContentFiltering" value
- PolicyAction field with "Block" or "Allow" values
- RuleType field with different destination types (FQDN, URL, webCategory, ipAddress)
- Split rules (character limit)
- ReviewNeeded flag examples

#### 5. sample_output_SecurityProfiles.csv
**Content:** Expected output showing:
- Security profiles with users and groups
- PolicyLinks with multiple references
- SecurityProfilePriority values
- Default user group placeholder

### Test Scenarios to Cover
1. ✅ Rules with no users/groups
2. ✅ Categories with mixed URL types
3. ✅ Action conflicts requiring duplication
4. ❌ Character limit exceeded (NOT in samples - too complex)
5. ✅ Wildcard domains and URLs
6. ❌ Deleted users (NOT in samples - covered in unit tests)
7. ✅ Unmapped predefined categories
8. ✅ Empty custom categories (logged and skipped)
9. ✅ Priority conflicts
10. ✅ Malformed URLs with ports/query strings
11. ✅ Rules with timeWindows (processed normally)

---

## Code Organization

### Region Structure
Following Convert-ZPA2EPA.ps1 pattern:

```powershell
function Convert-ZIA2EIA {
    <# .SYNOPSIS, .DESCRIPTION, .PARAMETER, .EXAMPLE, .NOTES #>
    
    [CmdletBinding()]
    param(...)
    
    Set-StrictMode -Version Latest
    
    #region Helper Functions
    # Internal function definitions
    #endregion
    
    #region Initialization
    # Logging setup
    # Variable initialization
    #endregion
    
    #region Phase 1: Data Loading
    # Load JSON files
    # Build lookup tables
    #endregion
    
    #region Phase 2: Custom Category Processing
    # Process custom categories
    # Deduplicate URLs/FQDNs/IPs
    # Classify URLs/FQDNs/IPs
    # Group and split
    # Create policy entries
    #endregion
    
    #region Phase 3: URL Filtering Rule Processing
    # Filter enabled rules
    # Extract users/groups
    # Process category references
    # Create security profiles
    # Resolve priority conflicts
    #endregion
    
    #region Phase 4: Export and Summary
    # Export CSVs
    # Generate statistics
    # Display summary
    #endregion
}
```

---

## Implementation Checklist

### Phase 1: Foundation
- [ ] Create function skeleton with parameters
- [ ] Implement logging initialization
- [ ] Create data loading logic
- [ ] Add JSON validation
- [ ] Build lookup tables

### Phase 2: Helper Functions
- [ ] Implement Get-DestinationType
- [ ] Implement Get-BaseDomain
- [ ] Implement Test-ValidIPv4Address
- [ ] Implement Split-UserEmail
- [ ] Implement Split-ByCharacterLimit
- [ ] Implement ConvertTo-CleanDestination

### Phase 3: Custom Categories
- [ ] Implement category filtering
- [ ] Implement deduplication
- [ ] Implement URL/FQDN/IP classification
- [ ] Implement grouping by base domain
- [ ] Implement character limit splitting
- [ ] Create policy entries

### Phase 4: Rules Processing
- [ ] Implement rule filtering
- [ ] Implement user/group extraction
- [ ] Implement category separation (custom vs predefined)
- [ ] Implement policy action updates
- [ ] Implement predefined category policy creation
- [ ] Implement security profile creation
- [ ] Implement priority conflict resolution

### Phase 5: Export
- [ ] Implement Policies CSV export
- [ ] Implement Security Profile CSV export
- [ ] Implement summary statistics

### Phase 6: Testing
- [ ] Create sample input files
- [ ] Create expected output files
- [ ] Test with real-world data
- [ ] Validate all edge cases
- [ ] Performance testing

### Phase 7: Documentation
- [ ] Complete inline comments
- [ ] Create user guide
- [ ] Document limitations
- [ ] Add troubleshooting guide

---

## Known Limitations

1. **Character Limits:** 300-character limit per Destinations field is hard-coded
2. **Base Domain:** Simple last-2-segments approach may not handle all TLDs correctly (e.g., .co.uk)
3. **IPv6:** Not supported, will be skipped with warning
4. **CIDR Ranges:** Not supported for IP addresses
5. **Port Numbers:** Not supported, will be skipped with warning
6. **Memory:** All data held in memory (acceptable for expected data sizes)
7. **No Filtering:** Cannot filter specific rules or categories (unlike Convert-ZPA2EPA)

---

## Future Enhancements

1. Add filtering parameters (TargetRuleName, RuleNamePattern, etc.)
2. Add PassThru parameter for pipeline support
3. Improve base domain extraction for complex TLDs
4. Add validation mode (dry-run)
5. Add support for incremental updates
6. Add WhatIf support for testing
7. Extract common functions to shared module
8. Add parallel processing for large datasets

---

## References

### ZScaler API Documentation
- URL Filtering Rules: https://help.zscaler.com/zia/url-filtering-policy#/urlFilteringRules-get
- URL Categories: https://help.zscaler.com/zia/url-categories#/urlCategories-get

### Related Functions
- Convert-ZPA2EPA.ps1: Template for design patterns
- Write-LogMessage.ps1: Shared logging function

### Microsoft Documentation
- Entra Internet Access: [Add documentation link]
- Web Content Filtering: [Add documentation link]

---

**End of Specification**
