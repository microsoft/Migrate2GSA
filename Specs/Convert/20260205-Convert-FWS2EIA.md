# Convert-ForcepointWS2EIA.ps1 Specification

## Document Information
- **Specification Version:** 1.0
- **Date:** 2026-02-05
- **Status:** Draft
- **Target Module:** Migrate2GSA
- **Function Name:** Convert-ForcepointWS2EIA
- **Author:** Andres Canello

---

## Overview

This PowerShell function converts Forcepoint Web Security (FWS) policy configuration to Microsoft Entra Internet Access (EIA) format. The function processes a matrix-style CSV file where rows represent web categories (predefined or user-defined FQDNs) and columns represent security groups, with cell values indicating the policy action (Block, Allow, Continue, Do not block).

### Purpose
- Transform Forcepoint category-based policies to EIA web content filtering policies
- Convert Forcepoint security group assignments to EIA security profiles
- Map Forcepoint predefined categories to GSA (Global Secure Access) web categories
- Generate import-ready CSV files for EIA configuration
- Deduplicate identical policies across security groups

### Design Alignment
This function follows the same architectural patterns as `Convert-ZIA2EIA.ps1`:
- Single function with internal helper functions
- Phased processing approach (Load → Process → Export)
- Comprehensive logging using `Write-LogMessage`
- Region-based code organization
- CSV export using UTF8 with BOM for Excel compatibility

---

## Input File Structure

### Forcepoint Policies CSV
**Source:** Forcepoint Web Security export  
**Required:** Yes  
**Default Path:** `ForcepointPolicies.csv` (in script root directory)

#### Description
Matrix-style CSV where:
- **Rows:** Represent web categories or FQDNs
- **Columns:** Represent security groups and their disposition settings
- **Cells:** Contain policy actions (Block, Allow, Continue, Do not block)

#### CSV Structure

| Parent Category Name | Child Category Name | DEFAULT Disposition | Group1 Disposition | Group2 Disposition | ... |
|---------------------|---------------------|---------------------|-------------------|-------------------|-----|
| Abortion | Abortion | Do not block | Block | Block | ... |
| Abortion | Pro-Choice | Do not block | Block | Do not block | ... |
| Adult Material | Adult Content | Block | Block | Block | ... |
| User-Defined | example.com | Block | Allow | Block | ... |
| User-Defined | internal.company.com | Do not block | Do not block | Do not block | ... |

#### Column Structure

1. **Parent Category Name** (Column 1)
   - Predefined category group name
   - Special value: "User-Defined" indicates custom FQDN entries

2. **Child Category Name** (Column 2)
   - Predefined: Specific category name (used for mapping lookup)
   - User-Defined: The actual FQDN to filter

3. **DEFAULT Disposition** (Column 3)
   - Default policy action applied to all users
   - Values: "Block", "Allow", "Continue", "Do not block"

4. **Security Group Columns** (Column 4+)
   - Column header format: `[GroupName] Disposition`
   - Example: "ESS DA Disposition", "Capita India DA Disposition"
   - Column headers ending with "_NOTUSED" or "NOTUSED" are processed (user's requirement)

#### Action Values

| Forcepoint Action | Meaning | Maps to EIA |
|-------------------|---------|-------------|
| Block | Explicitly block access | block |
| Continue | Warn user, allow continuation | block (with warning logged) |
| Allow | Explicitly allow access | allow |
| Do not block | Do not restrict access | allow |

---

## Category Mapping File

### Forcepoint-to-GSA-CategoryMapping.csv
**Source:** Manual configuration file (maintained by user)  
**Required:** Yes  
**Default Path:** `Forcepoint-to-GSA-CategoryMapping.csv` (in script root directory)

#### Description
Provides mapping between Forcepoint predefined web categories and Microsoft GSA (Global Secure Access) web categories.

#### Schema

| Column | Type | Required | Description |
|--------|------|----------|-------------|
| ForcepointCategory | string | Yes | Child Category Name from Forcepoint CSV |
| ForcepointDescription | string | No | Category description for reference |
| ExampleURLs | string | No | Sample URLs for documentation |
| GSACategory | string | Yes | Target GSA category name |
| MappingNotes | string | No | Mapping rationale |

#### Processing Rules
1. **Lookup:** Use Child Category Name (not Parent) to find matching `ForcepointCategory`
2. **Unmapped Categories:**
   - If `GSACategory` is null, blank, or "Unmapped": use placeholder format
   - Placeholder format: `[ForcepointCategory]_Unmapped`
   - Example: `Adult_Content` → `Adult_Content_Unmapped`
   - Mark for review in output
3. **Mapped Categories:**
   - Use the `GSACategory` value directly
   - Mark as ready for provisioning

#### Example Mapping File

```csv
ForcepointCategory,ForcepointDescription,ExampleURLs,GSACategory,MappingNotes
Abortion,Abortion-related content,example.com,Uncategorized,No direct GSA category match
Adult Content,Adult-oriented material,adult.com,AdultContent,Direct mapping
Drugs,Drug-related content,drugs.com,IllegalDrugs,Semantic match
```

---

## Output Files

All output files are created in `$OutputBasePath` with consistent timestamp prefix.

### 1. Policies CSV
**Filename:** `[yyyyMMdd_HHmmss]_EIA_Policies.csv`

#### Description
Contains all web content filtering policies with rules for blocked/allowed categories and FQDNs.

#### Fields

| Field | Description | Example | Notes |
|-------|-------------|---------|-------|
| PolicyName | Sequential policy name | "Web Content Filtering 1" | Unique identifier |
| PolicyType | Type of policy | "WebContentFiltering" | Always "WebContentFiltering" |
| PolicyAction | Allow or Block | "Block", "Allow" | From disposition |
| Description | Policy description | "Converted from Forcepoint" | Auto-generated |
| RuleType | Type of destination | "FQDN", "webCategory" | Rule destination type |
| RuleDestinations | Semicolon-separated list | "Abortion;Drugs;Adult Content" | Categories or FQDNs |
| RuleName | Sub-rule identifier | "Blocked_Categories", "example.com-Block" | Descriptive name |
| ReviewNeeded | Manual review flag | "Yes", "No" | "Yes" if unmapped or Continue action |
| ReviewDetails | Reason for review | "Unmapped categories found" | Semicolon-separated reasons |
| Provision | Provisioning flag | "Yes", "No" | "Yes" unless ReviewNeeded |

#### PolicyName Format
- Sequential numbering: "Web Content Filtering 1", "Web Content Filtering 2", etc.
- Each unique policy content gets one policy name
- Duplicate policies reuse the same policy name

#### RuleName Format
- **Web Categories:** "Blocked_Categories" or "Allowed_Categories"
- **FQDNs:** "[fqdn]-Block" or "[fqdn]-Allow"
  - Example: "example.com-Block", "internal.company.com-Allow"

#### Policy Structure Example

A security group with blocked categories and allowed FQDNs creates one policy:

```csv
PolicyName,PolicyType,PolicyAction,RuleType,RuleDestinations,RuleName
Web Content Filtering 1,WebContentFiltering,Block,webCategory,Abortion;AdultContent;Drugs,Blocked_Categories
Web Content Filtering 1,WebContentFiltering,Allow,FQDN,example.com;test.com,example.com-Allow
```

### 2. Security Profiles CSV
**Filename:** `[yyyyMMdd_HHmmss]_EIA_SecurityProfiles.csv`

#### Description
Contains security profile definitions that link policies to security groups.

#### Fields

| Field | Description | Example | Notes |
|-------|-------------|---------|-------|
| SecurityProfileName | Sequential profile name | "Security_Profile_1" | Unique identifier |
| Priority | Profile priority | 500, 600, 60000 | Lower = higher priority |
| SecurityProfileLinks | Policy references with priorities | "Web Content Filtering 1:100;Web Content Filtering 2:200" | Semicolon-separated |
| CADisplayName | Conditional Access display name | "CA_Security_Profile_1" | Auto-generated |
| EntraUsers | Semicolon-separated user emails | "_Replace_Me" | Placeholder |
| EntraGroups | Semicolon-separated group names | "ESS_DA;Capita_India_DA" | From CSV columns |
| Description | Profile description | "Converted from Forcepoint" | Auto-generated |
| Provision | Provisioning flag | "Yes" | Always "Yes" |

#### SecurityProfileLinks Format
- Format: `[PolicyName]:[InternalPriority]`
- Internal priorities: 100, 200, 300, etc. (within security profile)
- Multiple policies semicolon-separated
- Example: `Web Content Filtering 1:100;Web Content Filtering 2:200`

#### Priority Assignment
- **DEFAULT disposition:** Priority 60000 (low priority, catch-all)
- **Security groups:** Priority 500, 600, 700, etc. (increment 100)
- Order determined by processing sequence
- Duplicated groups share same priority (same security profile)

### 3. Log File
**Filename:** `[yyyyMMdd_HHmmss]_Convert-ForcepointWS2EIA.log`  
**Location:** Same directory as output CSV files (`$OutputBasePath`)

---

## Processing Logic

### Phase 1: Data Loading and Validation

#### 1.1 Initialize Logging
```powershell
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath = Join-Path $OutputBasePath "${timestamp}_Convert-ForcepointWS2EIA.log"
```

#### 1.2 Load Input Files
1. Load Forcepoint Policies CSV
   - Use `Import-Csv` with UTF8 encoding
   - Validate CSV structure (minimum 3 columns)
   - Fatal error if file missing or invalid
2. Load Category Mappings CSV
   - Validate required columns present
   - Fatal error if file missing or invalid

#### 1.3 Identify Security Group Columns
```powershell
# Get all column headers
$allColumns = $policiesCsv[0].PSObject.Properties.Name

# Filter for disposition columns (exclude first 3 fixed columns)
$groupColumns = $allColumns | Where-Object {
    $_ -notmatch '^(Parent Category Name|Child Category Name|DEFAULT)' -and
    $_ -match 'Disposition$'
}

# Extract group names (remove " Disposition" suffix)
$securityGroups = $groupColumns | ForEach-Object {
    $_ -replace ' Disposition$', ''
}
```

#### 1.4 Build Category Mapping Hashtable
```powershell
$categoryMappingsHashtable = @{}
foreach ($mapping in $categoryMappings) {
    $categoryMappingsHashtable[$mapping.ForcepointCategory] = $mapping
}
```

#### 1.5 Initialize Collections
```powershell
# Track unique policy definitions for deduplication
$policyDefinitionsHashtable = @{}  # Hash → PolicyDefinitionObject

# Track security group to policy definition mapping
$groupToPolicyDefHashtable = @{}   # GroupName → PolicyDefinitionHash

# Sequential counters
$policyCounter = 1
$securityProfileCounter = 1

# Collections for output
$policies = [System.Collections.ArrayList]::new()
$securityProfiles = [System.Collections.ArrayList]::new()
```

### Phase 2: Parse Forcepoint Policies by Security Group

#### 2.1 Process Each Security Group (Including DEFAULT)

For each security group (including "DEFAULT"):

1. **Collect Dispositions:**
   - Iterate through all CSV rows
   - Skip rows where disposition is empty/null
   - Separate by action type (Block vs Allow)

2. **Categorize Rows:**
   - **Predefined Categories:** Parent ≠ "User-Defined"
   - **User-Defined FQDNs:** Parent = "User-Defined"

3. **Build Policy Definition:**
   ```powershell
   $policyDefinition = @{
       BlockedCategories = @()      # Predefined categories to block
       AllowedCategories = @()      # Predefined categories to allow
       BlockedFQDNs = @()          # User-defined FQDNs to block
       AllowedFQDNs = @()          # User-defined FQDNs to allow
       HasContinueAction = $false   # Flag for warning
       UnmappedCategories = @()     # Categories not in mapping file
   }
   ```

#### 2.2 Process Each Row

For each row in Forcepoint CSV:

```powershell
$parentCategory = $row.'Parent Category Name'
$childCategory = $row.'Child Category Name'
$disposition = $row."$groupName Disposition"

# Skip if no disposition or empty
if ([string]::IsNullOrWhiteSpace($disposition)) { continue }

# Map action
$action = switch ($disposition) {
    'Block' { 'Block' }
    'Continue' { 
        $policyDefinition.HasContinueAction = $true
        'Block' 
    }
    'Allow' { 'Allow' }
    'Do not block' { 'Allow' }
    default { 
        Write-LogMessage "Unknown disposition '$disposition' for $childCategory" -Level "WARN"
        $null 
    }
}

if ($null -eq $action) { continue }

# Categorize and add to appropriate collection
if ($parentCategory -eq 'User-Defined') {
    # FQDN entry
    if ($action -eq 'Block') {
        $policyDefinition.BlockedFQDNs += $childCategory
    }
    else {
        $policyDefinition.AllowedFQDNs += $childCategory
    }
}
else {
    # Predefined category - lookup in mapping
    $mapping = $categoryMappingsHashtable[$childCategory]
    
    if ($null -eq $mapping -or 
        [string]::IsNullOrWhiteSpace($mapping.GSACategory) -or 
        $mapping.GSACategory -eq 'Unmapped') {
        
        # Unmapped category
        $gsaCategory = "${childCategory}_Unmapped"
        $policyDefinition.UnmappedCategories += $childCategory
    }
    else {
        $gsaCategory = $mapping.GSACategory
    }
    
    # Add to appropriate list
    if ($action -eq 'Block') {
        $policyDefinition.BlockedCategories += $gsaCategory
    }
    else {
        $policyDefinition.AllowedCategories += $gsaCategory
    }
}
```

#### 2.3 Deduplicate and Sort

After collecting all dispositions for a group:

```powershell
# Deduplicate (case-insensitive)
$policyDefinition.BlockedCategories = @($policyDefinition.BlockedCategories | 
    Select-Object -Unique | Sort-Object)
$policyDefinition.AllowedCategories = @($policyDefinition.AllowedCategories | 
    Select-Object -Unique | Sort-Object)
$policyDefinition.BlockedFQDNs = @($policyDefinition.BlockedFQDNs | 
    Select-Object -Unique | Sort-Object)
$policyDefinition.AllowedFQDNs = @($policyDefinition.AllowedFQDNs | 
    Select-Object -Unique | Sort-Object)
$policyDefinition.UnmappedCategories = @($policyDefinition.UnmappedCategories | 
    Select-Object -Unique | Sort-Object)
```

#### 2.4 Skip Empty Policy Definitions

```powershell
$totalItems = $policyDefinition.BlockedCategories.Count + 
              $policyDefinition.AllowedCategories.Count + 
              $policyDefinition.BlockedFQDNs.Count + 
              $policyDefinition.AllowedFQDNs.Count

if ($totalItems -eq 0) {
    Write-LogMessage "Security group '$groupName' has no dispositions defined, skipping" -Level "INFO"
    continue
}
```

### Phase 3: Policy Deduplication and Creation

#### 3.1 Generate Policy Definition Hash

```powershell
# Create deterministic string representation
$hashInput = @(
    "BlockedCategories:$($policyDefinition.BlockedCategories -join ',')"
    "AllowedCategories:$($policyDefinition.AllowedCategories -join ',')"
    "BlockedFQDNs:$($policyDefinition.BlockedFQDNs -join ',')"
    "AllowedFQDNs:$($policyDefinition.AllowedFQDNs -join ',')"
) -join '|'

# Generate SHA256 hash
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($hashInput))
$hash = [BitConverter]::ToString($hashBytes) -replace '-', ''
```

#### 3.2 Check for Duplicate Policy

```powershell
if ($policyDefinitionsHashtable.ContainsKey($hash)) {
    # Policy already exists - reuse it
    $existingPolicyDef = $policyDefinitionsHashtable[$hash]
    
    # Add this group to the existing policy's group list
    $existingPolicyDef.SecurityGroups += $groupName
    
    # Store mapping for security profile creation
    $groupToPolicyDefHashtable[$groupName] = $hash
    
    Write-LogMessage "Security group '$groupName' matches existing policy definition (hash: $($hash.Substring(0,8))...)" -Level "DEBUG"
}
else {
    # New unique policy - create it
    $policyName = "Web Content Filtering $policyCounter"
    $policyCounter++
    
    # Store policy definition
    $policyDefObject = @{
        Hash = $hash
        PolicyName = $policyName
        Definition = $policyDefinition
        SecurityGroups = @($groupName)
    }
    
    $policyDefinitionsHashtable[$hash] = $policyDefObject
    $groupToPolicyDefHashtable[$groupName] = $hash
    
    # Create policy entries
    Create-PolicyEntries -PolicyDefObject $policyDefObject -Policies $policies
}
```

#### 3.3 Create Policy Entries (Helper Logic)

For each unique policy definition, create CSV rows:

```powershell
function Create-PolicyEntries {
    param($PolicyDefObject, $Policies)
    
    $policyName = $PolicyDefObject.PolicyName
    $def = $PolicyDefObject.Definition
    
    # Determine if review needed
    $reviewNeeded = $false
    $reviewReasons = @()
    
    if ($def.UnmappedCategories.Count -gt 0) {
        $reviewNeeded = $true
        $reviewReasons += "Unmapped categories: $($def.UnmappedCategories -join ', ')"
    }
    
    if ($def.HasContinueAction) {
        $reviewNeeded = $true
        $reviewReasons += "Continue action converted to Block (requires review)"
    }
    
    $provision = if ($reviewNeeded) { "No" } else { "Yes" }
    $reviewDetails = $reviewReasons -join "; "
    
    # Create Block policy with rules
    if ($def.BlockedCategories.Count -gt 0 -or $def.BlockedFQDNs.Count -gt 0) {
        $blockPolicyName = $policyName + "-Block"
        
        # Rule 1: Blocked categories
        if ($def.BlockedCategories.Count -gt 0) {
            $policies.Add([PSCustomObject]@{
                PolicyName = $blockPolicyName
                PolicyType = "WebContentFiltering"
                PolicyAction = "Block"
                Description = "Converted from Forcepoint - Block rules"
                RuleType = "webCategory"
                RuleDestinations = $def.BlockedCategories -join ";"
                RuleName = "Blocked_Categories"
                ReviewNeeded = if ($reviewNeeded) { "Yes" } else { "No" }
                ReviewDetails = $reviewDetails
                Provision = $provision
            })
        }
        
        # Rules 2+: Blocked FQDNs (one per FQDN)
        foreach ($fqdn in $def.BlockedFQDNs) {
            $policies.Add([PSCustomObject]@{
                PolicyName = $blockPolicyName
                PolicyType = "WebContentFiltering"
                PolicyAction = "Block"
                Description = "Converted from Forcepoint - Block rules"
                RuleType = "FQDN"
                RuleDestinations = $fqdn
                RuleName = "$fqdn-Block"
                ReviewNeeded = if ($reviewNeeded) { "Yes" } else { "No" }
                ReviewDetails = $reviewDetails
                Provision = $provision
            })
        }
    }
    
    # Create Allow policy with rules
    if ($def.AllowedCategories.Count -gt 0 -or $def.AllowedFQDNs.Count -gt 0) {
        $allowPolicyName = $policyName + "-Allow"
        
        # Rule 1: Allowed categories
        if ($def.AllowedCategories.Count -gt 0) {
            $policies.Add([PSCustomObject]@{
                PolicyName = $allowPolicyName
                PolicyType = "WebContentFiltering"
                PolicyAction = "Allow"
                Description = "Converted from Forcepoint - Allow rules"
                RuleType = "webCategory"
                RuleDestinations = $def.AllowedCategories -join ";"
                RuleName = "Allowed_Categories"
                ReviewNeeded = if ($reviewNeeded) { "Yes" } else { "No" }
                ReviewDetails = $reviewDetails
                Provision = $provision
            })
        }
        
        # Rules 2+: Allowed FQDNs (one per FQDN)
        foreach ($fqdn in $def.AllowedFQDNs) {
            $policies.Add([PSCustomObject]@{
                PolicyName = $allowPolicyName
                PolicyType = "WebContentFiltering"
                PolicyAction = "Allow"
                Description = "Converted from Forcepoint - Allow rules"
                RuleType = "FQDN"
                RuleDestinations = $fqdn
                RuleName = "$fqdn-Allow"
                ReviewNeeded = if ($reviewNeeded) { "Yes" } else { "No" }
                ReviewDetails = $reviewDetails
                Provision = $provision
            })
        }
    }
}
```

### Phase 4: Security Profile Creation

#### 4.1 Group Security Groups by Policy Hash

```powershell
# Invert the mapping: Hash → List of groups
$hashToGroupsHashtable = @{}

foreach ($groupName in $groupToPolicyDefHashtable.Keys) {
    $hash = $groupToPolicyDefHashtable[$groupName]
    
    if (-not $hashToGroupsHashtable.ContainsKey($hash)) {
        $hashToGroupsHashtable[$hash] = @()
    }
    
    $hashToGroupsHashtable[$hash] += $groupName
}
```

#### 4.2 Create Security Profiles

```powershell
# Track if DEFAULT has been processed
$defaultPriority = 60000
$currentPriority = 500

foreach ($hash in $hashToGroupsHashtable.Keys) {
    $policyDefObject = $policyDefinitionsHashtable[$hash]
    $groups = $hashToGroupsHashtable[$hash]
    
    # Sanitize group names for EntraGroups field
    $sanitizedGroups = $groups | ForEach-Object { 
        $_ -replace '\s', '_' -replace '[^a-zA-Z0-9_-]', ''
    }
    
    # Determine priority
    if ($groups -contains 'DEFAULT') {
        $priority = $defaultPriority
        $targetGroup = 'Replace_with_All_IA_Users_Group'
    }
    else {
        $priority = $currentPriority
        $currentPriority += 100
        $targetGroup = $sanitizedGroups -join ";"
    }
    
    # Build policy links
    $policyLinks = @()
    $linkPriority = 100
    
    $blockPolicyName = "$($policyDefObject.PolicyName)-Block"
    $allowPolicyName = "$($policyDefObject.PolicyName)-Allow"
    
    # Check if policies actually exist
    if ($policies | Where-Object { $_.PolicyName -eq $blockPolicyName }) {
        $policyLinks += "${blockPolicyName}:${linkPriority}"
        $linkPriority += 100
    }
    
    if ($policies | Where-Object { $_.PolicyName -eq $allowPolicyName }) {
        $policyLinks += "${allowPolicyName}:${linkPriority}"
        $linkPriority += 100
    }
    
    # Create security profile
    $profileName = "Security_Profile_$securityProfileCounter"
    $securityProfileCounter++
    
    $securityProfile = [PSCustomObject]@{
        SecurityProfileName = $profileName
        Priority = $priority
        SecurityProfileLinks = $policyLinks -join ";"
        CADisplayName = "CA_$profileName"
        EntraUsers = "_Replace_Me"
        EntraGroups = $targetGroup
        Description = "Converted from Forcepoint - Groups: $($groups -join ', ')"
        Provision = "Yes"
    }
    
    [void]$securityProfiles.Add($securityProfile)
}
```

#### 4.3 Sort Security Profiles by Priority

```powershell
$securityProfiles = $securityProfiles | Sort-Object -Property Priority
```

### Phase 5: Export and Summary

#### 5.1 Export Policies CSV
```powershell
$policiesCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_Policies.csv"
$policies | Export-Csv -Path $policiesCsvPath -NoTypeInformation -Encoding utf8BOM
Write-LogMessage "Exported $($policies.Count) policy entries to: $policiesCsvPath" -Level "INFO"
```

#### 5.2 Export Security Profiles CSV
```powershell
$spCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_SecurityProfiles.csv"
$securityProfiles | Export-Csv -Path $spCsvPath -NoTypeInformation -Encoding utf8BOM
Write-LogMessage "Exported $($securityProfiles.Count) security profiles to: $spCsvPath" -Level "INFO"
```

#### 5.3 Generate Summary Statistics

```powershell
=== CONVERSION SUMMARY ===
Total Forcepoint rows processed: X
Security groups found: Y
  - DEFAULT group included: Yes/No

Unique policies created: Z
  - Block policies: Z1
  - Allow policies: Z2
Policy entries (CSV rows): A
Security profiles created: B

Categories processed:
  - Predefined blocked categories: C1
  - Predefined allowed categories: C2
  - User-defined blocked FQDNs: C3
  - User-defined allowed FQDNs: C4

Unmapped categories: U
Continue actions converted to Block: V

Deduplication results:
  - Total security groups: W
  - Unique policy definitions: X
  - Groups sharing policies: Y

Output files:
  - Policies: [path]
  - Security Profiles: [path]
  - Log File: [path]
```

#### 5.4 Validate Against GSA Limits

```powershell
# Define limits
$limits = @{
    MaxPolicies = 100
    MaxRules = 1000
    MaxFQDNs = 8000
    MaxSecurityProfiles = 256
}

# Calculate counts
$uniquePolicies = ($policies | Select-Object -Property PolicyName -Unique).Count
$totalRules = $policies.Count
$totalFQDNs = ($policies | Where-Object { $_.RuleType -eq 'FQDN' }).Count

# Display warnings if limits exceeded
if ($uniquePolicies -gt $limits.MaxPolicies) {
    Write-LogMessage "WARNING: Unique policies ($uniquePolicies) exceeds limit of $($limits.MaxPolicies)" -Level "WARN"
}

if ($totalRules -gt $limits.MaxRules) {
    Write-LogMessage "WARNING: Total rules ($totalRules) exceeds limit of $($limits.MaxRules)" -Level "WARN"
}

if ($totalFQDNs -gt $limits.MaxFQDNs) {
    Write-LogMessage "WARNING: Total FQDNs ($totalFQDNs) exceeds limit of $($limits.MaxFQDNs)" -Level "WARN"
}

if ($securityProfiles.Count -gt $limits.MaxSecurityProfiles) {
    Write-LogMessage "WARNING: Security profiles ($($securityProfiles.Count)) exceeds limit of $($limits.MaxSecurityProfiles)" -Level "WARN"
}
```

---

## Function Parameters

### Optional Parameters

| Parameter | Type | Default | Description | Validation |
|-----------|------|---------|-------------|------------|
| ForcepointPoliciesPath | string | `ForcepointPolicies.csv` | Path to Forcepoint policies CSV | ValidateScript - file must exist |
| CategoryMappingsPath | string | `Forcepoint-to-GSA-CategoryMapping.csv` | Path to category mappings CSV | ValidateScript - file must exist |
| OutputBasePath | string | `$PWD` | Output directory for CSV and log files | ValidateScript - directory must exist |
| EnableDebugLogging | switch | `false` | Enable DEBUG level logging | None |

### Parameter Definitions

```powershell
[CmdletBinding(SupportsShouldProcess = $false)]
param(
    [Parameter(HelpMessage = "Path to Forcepoint Policies CSV export")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$ForcepointPoliciesPath = (Join-Path $PWD "ForcepointPolicies.csv"),
    
    [Parameter(HelpMessage = "Path to Forcepoint to GSA category mappings CSV file")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$CategoryMappingsPath = (Join-Path $PWD "Forcepoint-to-GSA-CategoryMapping.csv"),
    
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

### Functions to Reuse from Shared Module

#### 1. Write-LogMessage
**Location:** `Migrate2GSA\internal\functions\Write-LogMessage.ps1`  
**Purpose:** Write structured log messages to console and file

**Usage:**
```powershell
Write-LogMessage "Processing security group: $groupName" -Level "INFO" `
    -Component "Convert-ForcepointWS2EIA" -LogPath $logPath -EnableDebugLogging $EnableDebugLogging
```

---

## Examples

### Example 1: Basic Conversion

**Input Forcepoint CSV:**
```csv
Parent Category Name,Child Category Name,DEFAULT Disposition,Finance_Group Disposition,Marketing_Group Disposition
Abortion,Abortion,Do not block,Block,Do not block
Adult Material,Adult Content,Block,Block,Block
User-Defined,example.com,Block,Allow,Block
```

**Output - Policies CSV:**
```csv
PolicyName,PolicyType,PolicyAction,RuleType,RuleDestinations,RuleName,ReviewNeeded,ReviewDetails,Provision
Web Content Filtering 1-Block,WebContentFiltering,Block,webCategory,Abortion,Blocked_Categories,No,,Yes
Web Content Filtering 2-Block,WebContentFiltering,Block,webCategory,AdultContent,Blocked_Categories,No,,Yes
Web Content Filtering 2-Block,WebContentFiltering,Block,FQDN,example.com,example.com-Block,No,,Yes
Web Content Filtering 3-Allow,WebContentFiltering,Allow,FQDN,example.com,example.com-Allow,No,,Yes
```

**Output - Security Profiles CSV:**
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Description,Provision
Security_Profile_1,500,Web Content Filtering 1-Block:100,CA_Security_Profile_1,_Replace_Me,Finance_Group,Converted from Forcepoint - Groups: Finance_Group,Yes
Security_Profile_2,600,Web Content Filtering 2-Block:100,CA_Security_Profile_2,_Replace_Me,Marketing_Group,Converted from Forcepoint - Groups: Marketing_Group,Yes
Security_Profile_3,700,Web Content Filtering 3-Allow:100,CA_Security_Profile_3,_Replace_Me,Finance_Group,Converted from Forcepoint - Groups: Finance_Group,Yes
Security_Profile_4,60000,Web Content Filtering 2-Block:100,CA_Security_Profile_4,_Replace_Me,Replace_with_All_IA_Users_Group,Converted from Forcepoint - Groups: DEFAULT,Yes
```

### Example 2: Deduplication

**Input:**
```csv
Parent Category Name,Child Category Name,DEFAULT Disposition,Group1 Disposition,Group2 Disposition
Abortion,Abortion,Do not block,Block,Block
Adult Material,Adult Content,Block,Block,Block
```

Both Group1 and Group2 have identical dispositions (both block Abortion and Adult Content).

**Output - Policies CSV:**
```csv
PolicyName,PolicyType,PolicyAction,RuleType,RuleDestinations,RuleName,ReviewNeeded,ReviewDetails,Provision
Web Content Filtering 1-Block,WebContentFiltering,Block,webCategory,Abortion;AdultContent,Blocked_Categories,No,,Yes
Web Content Filtering 2-Block,WebContentFiltering,Block,webCategory,AdultContent,Blocked_Categories,No,,Yes
```

**Output - Security Profiles CSV:**
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Description,Provision
Security_Profile_1,500,Web Content Filtering 1-Block:100,CA_Security_Profile_1,_Replace_Me,Group1;Group2,Converted from Forcepoint - Groups: Group1; Group2,Yes
Security_Profile_2,60000,Web Content Filtering 2-Block:100,CA_Security_Profile_2,_Replace_Me,Replace_with_All_IA_Users_Group,Converted from Forcepoint - Groups: DEFAULT,Yes
```

**Note:** Group1 and Group2 share one security profile since they have identical policies.

### Example 3: Unmapped Categories and Continue Action

**Input:**
```csv
Parent Category Name,Child Category Name,DEFAULT Disposition,Test_Group Disposition
Gambling,Online Gambling,Do not block,Continue
Custom Category,Test,Do not block,Block
```

Assuming "Online Gambling" is not in the mapping file and "Custom Category" is also unmapped.

**Output - Policies CSV:**
```csv
PolicyName,PolicyType,PolicyAction,RuleType,RuleDestinations,RuleName,ReviewNeeded,ReviewDetails,Provision
Web Content Filtering 1-Block,WebContentFiltering,Block,webCategory,Online Gambling_Unmapped;Custom Category_Unmapped,Blocked_Categories,Yes,Unmapped categories: Online Gambling; Custom Category; Continue action converted to Block (requires review),No
```

**Note:** Policy marked for review due to unmapped categories and Continue action.

---

## Code Organization

### Region Structure

```powershell
function Convert-ForcepointWS2EIA {
    <# .SYNOPSIS, .DESCRIPTION, .PARAMETER, .EXAMPLE, .NOTES #>
    
    [CmdletBinding()]
    param(...)
    
    Set-StrictMode -Version Latest
    
    #region Initialization
    # Logging setup
    # Variable initialization
    # Statistics hashtable
    #endregion
    
    #region Phase 1: Data Loading
    # Load Forcepoint CSV
    # Load category mappings
    # Identify security group columns
    # Build lookup tables
    #endregion
    
    #region Phase 2: Parse Forcepoint Policies
    # For each security group (including DEFAULT)
    # Collect dispositions
    # Build policy definitions
    # Track Continue actions and unmapped categories
    #endregion
    
    #region Phase 3: Policy Deduplication and Creation
    # Generate policy definition hashes
    # Check for duplicates
    # Create unique policies
    # Generate CSV rows
    #endregion
    
    #region Phase 4: Security Profile Creation
    # Group security groups by policy hash
    # Assign priorities
    # Create security profiles
    # Link to policies
    #endregion
    
    #region Phase 5: Export and Summary
    # Export CSVs
    # Generate statistics
    # Validate against GSA limits
    # Display summary
    #endregion
}
```

---

## Statistics to Track

```powershell
$stats = @{
    # Input
    TotalRowsProcessed = 0
    SecurityGroupsFound = 0
    DefaultGroupIncluded = $false
    
    # Categories
    PredefinedBlockedCategories = 0
    PredefinedAllowedCategories = 0
    UserDefinedBlockedFQDNs = 0
    UserDefinedAllowedFQDNs = 0
    UnmappedCategories = 0
    
    # Actions
    ContinueActionsConverted = 0
    BlockActionsProcessed = 0
    AllowActionsProcessed = 0
    
    # Deduplication
    TotalSecurityGroups = 0
    UniquePolicyDefinitions = 0
    GroupsSharingPolicies = 0
    
    # Outputs
    UniquePoliciesCreated = 0
    BlockPoliciesCreated = 0
    AllowPoliciesCreated = 0
    PolicyEntriesCreated = 0
    SecurityProfilesCreated = 0
}
```

---

## Known Limitations

1. **Column Header Format:** Assumes columns end with " Disposition" suffix
2. **User-Defined Detection:** Relies on exact match of "User-Defined" as parent category
3. **No FQDN Validation:** Does not validate if User-Defined entries are valid FQDNs
4. **Sequential Naming:** Policy and profile names are sequential, not customizable
5. **No Filtering:** Cannot filter specific categories or groups (processes entire CSV)
6. **Memory:** All data held in memory (acceptable for expected data sizes)
7. **No Incremental Updates:** Always processes full file, not optimized for incremental changes

---

## Error Handling

### Fatal Errors (Stop Processing)

| Error | Condition | Action |
|-------|-----------|--------|
| Missing input file | File not found | Throw error, exit |
| Invalid CSV structure | Less than 3 columns | Throw error, exit |
| No security groups found | Only fixed columns present | Throw error, exit |
| Invalid output path | Directory doesn't exist | Throw error, exit |

### Non-Fatal Errors (Log and Continue)

| Error | Condition | Action |
|-------|-----------|--------|
| Unknown disposition | Invalid value | WARN, skip |
| Empty disposition | Null/empty cell | DEBUG, skip |
| Unmapped category | Not in mapping file | INFO, use placeholder |
| Empty policy definition | No rules for group | INFO, skip group |

---

## Future Enhancements

1. Add FQDN validation for User-Defined entries
2. Support custom policy/profile naming patterns
3. Add filtering parameters (specific groups, categories)
4. Support for additional policy types (TLS Inspection)
5. Add dry-run/validation mode
6. Support incremental updates
7. Add WhatIf support
8. Performance optimization for very large CSVs
9. Support for additional Forcepoint action types

---

## References

### Related Functions
- Convert-ZIA2EIA.ps1: Similar conversion function for ZScaler
- Write-LogMessage.ps1: Shared logging function

### Microsoft Documentation
- Entra Internet Access Concepts: https://learn.microsoft.com/en-us/entra/global-secure-access/concept-internet-access
- Web Content Filtering: https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-web-content-filtering

---

**End of Specification**
