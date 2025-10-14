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
| ReviewNeeded | Manual review flag | "Yes", "No" | "Yes" if unmapped categories |

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
- Character limit: 300 characters (not including quotes)
- Commas within limit count toward total
- If exceeded, split into multiple rules with "-2", "-3" suffix

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
- Initialize collections for policies and security profiles

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

#### 2.2 Deduplication
- Combine `urls` and `dbCategorizedUrls` arrays
- Remove duplicate entries (case-insensitive comparison)
- Log count of duplicates removed at DEBUG level

**Rationale:** Deduplication is performed before classification for performance efficiency. Classifying fewer entries reduces processing time, and deduplicating raw strings is simpler than deduplicating classified objects.

#### 2.3 URL/FQDN/IP Classification Algorithm

**Classification Order (sequential checks):**

1. **Check for Empty String**
   - If empty or whitespace only: skip and continue

2. **Check for IP Address**
   - Use regex: `^(\d{1,3}\.){3}\d{1,3}$`
   - If matches: classify as `ipAddress`
   - If contains port (":"), path ("/"), or query ("?"): WARN and skip
   - If IPv6 format: WARN and skip

3. **Check for Path Component**
   - If contains "/" character: classify as `URL`
   - Extract authority and path only (no schema, port, query, fragment)

4. **Check for Wildcard Position**
   - If starts with "*.": classify as `FQDN`
   - Example: `*.contoso.com` → FQDN
   - Note: `*.contoso.com` does NOT include `contoso.com`
   - If wildcard anywhere else: classify as `URL`
   - Example: `contoso*.com` → URL

5. **Check for Invalid Components**
   - If contains "http://" or "https://": WARN, strip schema, continue
   - If contains ":" (port): WARN and skip
   - If contains "?" (query): WARN, strip query/fragment, continue
   - If contains "#" (fragment): WARN, strip fragment, continue

6. **Default Classification**
   - No path, no wildcard (or wildcard at start): `FQDN`
   - Example: `contoso.com` → FQDN

#### 2.4 Grouping by Base Domain

**Purpose:** Optimize number of rules by grouping related FQDNs/URLs together while respecting character limits.

**Base Domain Extraction:**
- Use last 2 segments of domain
- Example: `api.internal.company.com` → base domain: `company.com`
- Example: `www.site.com` → base domain: `site.com`

**Grouping Logic:**

```
For each destination type (FQDN, URL, ipAddress):
    Group entries by base domain
    For each group:
        Calculate combined length (with semicolons)
        If > 300 characters:
            Split into multiple sub-groups
            Respect individual entry boundaries (no truncation)
        Create policy entry for each sub-group
```

#### 2.5 Character Limit Splitting

**Limit:** 300 characters (excluding field quotes, including semicolons)

**Splitting Algorithm:**
```
currentLength = 0
currentGroup = []
groupNumber = 1

For each entry in group:
    entryLength = entry.Length
    If currentLength + entryLength + 1 > 300:  // +1 for semicolon
        Create policy entry with currentGroup
        RuleName = "{base}-{type}{groupNumber}"
        groupNumber++
        currentGroup = [entry]
        currentLength = entryLength
    Else:
        currentGroup.Add(entry)
        currentLength += entryLength + 1  // +1 for semicolon

Create policy entry with remaining currentGroup
```

**RuleName Format:**
- First group: `FQDNs1`, `URLs1`, `IPs1`, `WebCategories1`
- Subsequent: `FQDNs1-2`, `FQDNs1-3`, etc.

#### 2.6 Policy Entry Creation (Custom Categories)

For each custom category and destination type:

```powershell
$policyEntry = @{
    PolicyName = "$configuredName-Block"  # or "$id-Block" if no configuredName
    PolicyType = "WebContentFiltering"
    PolicyAction = "Block"                    # Default action
    Description = $category.description
    RuleType = "FQDN" | "URL" | "ipAddress"
    RuleDestinations = "entry1;entry2;entry3"  # semicolon-separated
    RuleName = "FQDNs1" | "URLs1" | "IPs1"
    ReviewNeeded = "No"
}
```

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

For each custom category referenced by the rule:

```
Lookup existing policy entry for custom category

If rule.action == "BLOCK":
    Use existing policy (already set to Block)
    
If rule.action == "ALLOW":
    Check if policy with "-Allow" suffix exists
    If not exists:
        Duplicate the policy entry
        Change PolicyName to append "-Allow"
        Change PolicyAction to "Allow"
        Add to policy collection
    Use the "-Allow" version
```

**Example:**
- Custom category: "CUSTOM_01"
- Initial policy: "CUSTOM_01-Block" (PolicyAction: Block)
- Rule1 (Block) references CUSTOM_01 → uses "CUSTOM_01-Block"
- Rule2 (Allow) references CUSTOM_01 → creates "CUSTOM_01-Allow", uses it

#### 3.5 Policy Creation (Predefined Categories)

If rule references predefined categories:

```powershell
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

$policyEntry = @{
    PolicyName = "$($rule.name)-WebCategories-$($rule.action.Substring(0,1) + $rule.action.Substring(1).ToLower())"
    PolicyType = "WebContentFiltering"
    PolicyAction = if ($rule.action -eq "ALLOW") { "Allow" } else { "Block" }
    Description = "Converted from $($rule.name) categories"
    RuleType = "webCategory"
    RuleDestinations = $mappedCategories -join ";"
    RuleName = "WebCategories1"
    ReviewNeeded = if ($hasUnmapped) { "Yes" } else { "No" }
}
```

**PolicyName Examples:**
- Rule "urlRule1" with action "BLOCK" → "urlRule1-WebCategories-Block"
- Rule "urlRule2" with action "ALLOW" → "urlRule2-WebCategories-Allow"

#### 3.6 Security Profile Creation

```powershell
$policyLinks = @()

# Add custom category policy references
foreach ($customCatId in $customCategoryRefs) {
    $policyName = Get-CustomCategoryPolicyName $customCatId $rule.action
    $policyLinks += $policyName
}

# Add predefined category policy reference (if any)
if ($predefinedCategoryRefs.Count -gt 0) {
    $policyName = "$($rule.name)-WebCategories-$($rule.action)"
    $policyLinks += $policyName
}

$securityProfile = @{
    SecurityProfileName = $rule.name
    SecurityProfilePriority = $rule.order * 10
    EntraGroups = $groups -join ";"
    EntraUsers = $validUsers -join ";"
    PolicyLinks = $policyLinks -join ";"
    Description = $rule.description
}
```

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

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| UrlFilteringPolicyPath | string | `url_filtering_policy.json` | Path to policy file |
| UrlCategoriesPath | string | `url_categories.json` | Path to categories file |
| CategoryMappingsPath | string | `ZIA2EIA-CategoryMappings.json` | Path to mappings file |
| OutputBasePath | string | `$PWD` | Output directory for CSV and log files |
| DestinationsMaxLength | int | `300` | Max characters per RuleDestinations field |
| EnableDebugLogging | switch | `false` | Enable DEBUG level logging |

### Parameters NOT Included
- No filtering parameters (no TargetAppSegmentName equivalent)
- No PassThru parameter
- No batch size or processing limit parameters

### Parameter Validation
- File paths: Validate existence for input files
- OutputBasePath: Validate directory exists
- DestinationsMaxLength: Validate > 0

---

## Internal Helper Functions

### Functions to Create (New)

#### 1. Get-UrlType
**Purpose:** Classify entry as URL, FQDN, or IP address

**Logic:**
```powershell
function Get-UrlType {
    param([string]$Entry)
    
    # Empty check
    if ([string]::IsNullOrWhiteSpace($Entry)) { return $null }
    
    # IP check (IPv4 only, no CIDR/port/path)
    if ($Entry -match '^(\d{1,3}\.){3}\d{1,3}$') { return 'ipAddress' }
    if ($Entry -match '^(\d{1,3}\.){3}\d{1,3}[:/]') {
        Write-LogMessage "Skipping IP with port/path: $Entry" -Level "WARN"
        return $null
    }
    if ($Entry -match ':.*:') {  # IPv6 detection
        Write-LogMessage "Skipping IPv6 address: $Entry" -Level "WARN"
        return $null
    }
    
    # Path check
    if ($Entry -contains '/') { return 'URL' }
    
    # Wildcard position check
    if ($Entry -like '*.*') {
        if ($Entry.StartsWith('*.')) { return 'FQDN' }
        else { return 'URL' }
    }
    
    # Default
    return 'FQDN'
}
```

#### 2. Get-BaseDomain
**Purpose:** Extract base domain (last 2 segments) for grouping

**Logic:**
```powershell
function Get-BaseDomain {
    param([string]$Domain)
    
    # Remove leading wildcard if present
    $cleanDomain = $Domain -replace '^\*\.', ''
    
    # Extract path-free domain for URLs
    if ($cleanDomain -contains '/') {
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

#### 3. Test-ValidIpAddress
**Purpose:** Validate IP address without CIDR, port, or path

**Logic:**
```powershell
function Test-ValidIpAddress {
    param([string]$IpAddress)
    
    if ($IpAddress -notmatch '^(\d{1,3}\.){3}\d{1,3}$') { return $false }
    if ($IpAddress -contains ':') { return $false }  # Port
    if ($IpAddress -contains '/') { return $false }  # Path
    if ($IpAddress -match ':.*:') { return $false }  # IPv6
    
    return $true
}
```

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
**Purpose:** Split destination arrays by character limit without truncating entries

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

#### 6. Remove-InvalidUrlComponents
**Purpose:** Strip schema, port, query, and fragment from URLs

**Logic:**
```powershell
function Remove-InvalidUrlComponents {
    param([string]$Url)
    
    $cleaned = $Url
    
    # Remove schema
    if ($cleaned -match '^https?://') {
        Write-LogMessage "Removing schema from: $Url" -Level "WARN"
        $cleaned = $cleaned -replace '^https?://', ''
    }
    
    # Remove port
    if ($cleaned -match ':\d+') {
        Write-LogMessage "Removing port from: $Url" -Level "WARN"
        $cleaned = $cleaned -replace ':\d+', ''
    }
    
    # Remove query and fragment
    if ($cleaned -contains '?') {
        Write-LogMessage "Removing query from: $Url" -Level "WARN"
        $cleaned = $cleaned.Split('?')[0]
    }
    if ($cleaned -contains '#') {
        Write-LogMessage "Removing fragment from: $Url" -Level "WARN"
        $cleaned = $cleaned.Split('#')[0]
    }
    
    return $cleaned
}
```

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

Use `Write-Progress` for long-running operations:

```powershell
$totalRules = $rules.Count
$currentRule = 0

foreach ($rule in $rules) {
    $currentRule++
    Write-Progress -Activity "Processing URL Filtering Rules" `
        -Status "Processing rule $currentRule of $totalRules: $($rule.name)" `
        -PercentComplete (($currentRule / $totalRules) * 100)
    
    # Process rule...
}

Write-Progress -Activity "Processing URL Filtering Rules" -Completed
```

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
- [ ] Implement Get-UrlType
- [ ] Implement Get-BaseDomain
- [ ] Implement Test-ValidIpAddress
- [ ] Implement Split-UserEmail
- [ ] Implement Split-ByCharacterLimit
- [ ] Implement Remove-InvalidUrlComponents

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
- [ ] Add progress reporting

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
