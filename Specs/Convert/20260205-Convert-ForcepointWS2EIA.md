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

### Terminology
- **Policy**: A named collection of rules with ONE action (Block or Allow). Identified by PolicyName (e.g., "Web Content Filtering 1-Block")
- **Rule**: A single CSV row representing one destination filter (one FQDN or a semicolon-separated list of web categories)
- **Policy Definition**: The internal data structure containing all blocked/allowed categories and FQDNs before being split into separate Block and Allow policies
- **Security Profile**: Links one or more policies to one or more security groups, establishing the enforcement scope
- **Disposition**: The action value from Forcepoint (Block, Allow, Continue, Do not block) that determines how to handle traffic

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
**Default Path:** None (must be specified)

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
   - All columns ending with "Disposition" are processed ("NOTUSED" may appear as part of group names)

#### Action Values

All action values are case-insensitive (e.g., "Block", "block", "BLOCK" are equivalent).

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
**Default Path:** None (must be specified)

#### Description
Provides mapping between Forcepoint predefined web categories and Microsoft GSA (Global Secure Access) web categories.

#### Schema

| Column | Type | Required | Description |
|--------|------|----------|-------------|
| ForcepointCategory | string | Yes | Child Category Name from Forcepoint CSV |
| GSACategory | string | Yes | Target GSA category name |
| MappingNotes | string | No | Mapping rationale |

#### Processing Rules
1. **Lookup:** Use Child Category Name (not Parent) to find matching `ForcepointCategory`
2. **Category Not Found in Mapping File:**
   - If `ForcepointCategory` does not exist as a key in the mapping file: treat as unmapped
   - Use placeholder format: `[ChildCategoryName]_Unmapped`
   - Add to unmapped categories list for review
3. **Unmapped Categories:**
   - If `ForcepointCategory` exists but `GSACategory` is null, blank, or "Unmapped": use placeholder format
   - Placeholder format: `[ChildCategoryName]_Unmapped`
   - Example: `Adult_Content` → `Adult_Content_Unmapped`
   - Mark for review in output
4. **Mapped Categories:**
   - Use the `GSACategory` value directly
   - Mark as ready for provisioning

#### Example Mapping File

```csv
ForcepointCategory,GSACategory,MappingNotes
Abortion,Uncategorized,No direct GSA category match
Adult Content,AdultContent,Direct mapping
Drugs,IllegalDrugs,Semantic match
```

---

## Output Files

All output files are created in `$OutputBasePath` with consistent timestamp prefix.

### 1. Policies CSV
**Filename:** `[yyyyMMdd_HHmmss]_EIA_Policies.csv`

#### Description
Contains all web content filtering policies with rules for blocked/allowed categories and FQDNs. Each policy has ONE action (Block or Allow). A security group with both blocked and allowed items will generate TWO separate policies. Each policy can have multiple rules: web categories are combined into one rule with semicolon-separated destinations, while FQDNs are created as individual rules (one CSV row per FQDN).

#### Fields

| Field | Description | Example | Notes |
|-------|-------------|---------|-------|
| PolicyName | Sequential policy name with action suffix | "Web Content Filtering 1-Block" | Includes -Block or -Allow suffix |
| PolicyType | Type of policy | "WebContentFiltering" | Always "WebContentFiltering" |
| PolicyAction | Allow or Block | "Block", "Allow" | ONE action per policy |
| Description | Policy description | "Converted from Forcepoint" | Auto-generated |
| RuleType | Type of destination | "FQDN", "webCategory" | Rule destination type |
| RuleDestinations | Semicolon-separated list for categories, single FQDN for FQDN rules | "Abortion;Drugs;Adult Content" or "example.com" | Categories: semicolon-separated; FQDNs: one per row |
| RuleName | Sub-rule identifier | "Blocked_Categories", "example.com-Block" | Descriptive name |
| ReviewNeeded | Manual review flag (per rule) | "Yes", "No" | "Yes" if THIS rule has unmapped categories or Continue action |
| ReviewDetails | Reason for review (per rule) | "Unmapped categories found" | Semicolon-separated reasons for this specific rule |
| Provision | Provisioning flag (per rule) | "Yes", "No" | "Yes" unless THIS rule needs review |

#### PolicyName Format
- Sequential numbering across ALL policies (global counter): 1, 2, 3, 4...
- Action suffix added: "-Block" or "-Allow"
- Full policy names: "Web Content Filtering 1-Block", "Web Content Filtering 2-Allow", "Web Content Filtering 3-Block"
- Each policy has ONLY ONE action (Block or Allow)
- Policy numbers are UNIQUE across all policies (no reuse of numbers)
- A security group with both blocked and allowed items creates TWO policies with different numbers
- Duplicate policy definitions reuse the same policy name (same number)

#### RuleName Format
- **Web Categories:** "Blocked_Categories" or "Allowed_Categories"
- **FQDNs:** "[fqdn]-Block" or "[fqdn]-Allow"
  - Example: "example.com-Block", "internal.company.com-Allow"

#### Policy Structure Example

A security group with blocked categories and allowed FQDNs creates TWO policies:

**Block Policy** (one rule with multiple web categories):
```csv
PolicyName,PolicyType,PolicyAction,RuleType,RuleDestinations,RuleName
Web Content Filtering 1-Block,WebContentFiltering,Block,webCategory,Abortion;AdultContent;Drugs,Blocked_Categories
```

**Allow Policy** (one rule per FQDN):
```csv
PolicyName,PolicyType,PolicyAction,RuleType,RuleDestinations,RuleName
Web Content Filtering 1-Allow,WebContentFiltering,Allow,FQDN,example.com,example.com-Allow
Web Content Filtering 1-Allow,WebContentFiltering,Allow,FQDN,test.com,test.com-Allow
```

Both policies are linked to the same security profile.

### 2. Security Profiles CSV
**Filename:** `[yyyyMMdd_HHmmss]_EIA_SecurityProfiles.csv`

#### Description
Contains security profile definitions that link policies to security groups. A security profile can reference multiple policies (e.g., both a Block policy and an Allow policy for the same security group). The security profile is then referenced by a Conditional Access policy to enforce the web content filtering rules.

#### Fields

| Field | Description | Example | Notes |
|-------|-------------|---------|-------|
| SecurityProfileName | Sequential profile name | "Security_Profile_1" | Unique identifier |
| Priority | Profile priority | 500, 600, 60000 | Lower = higher priority |
| SecurityProfileLinks | Policy references with priorities | "Web Content Filtering 1-Block:100;Web Content Filtering 1-Allow:200" | Semicolon-separated, includes -Block/-Allow suffix |
| CADisplayName | Conditional Access display name | "CA_Security_Profile_1" | Auto-generated |
| EntraUsers | Semicolon-separated user emails | "_Replace_Me" | Placeholder |
| EntraGroups | Semicolon-separated group names | "ESS_DA;Capita_India_DA" | From CSV columns |
| Description | Profile description | "Converted from Forcepoint" | Auto-generated |
| Provision | Provisioning flag | "Yes" | Always "Yes" |

#### SecurityProfileLinks Format
- Format: `[PolicyName]:[InternalPriority]`
- Internal priorities: 100, 200, 300, etc. (within security profile)
- Multiple policies semicolon-separated
- **Ordering:** Allow policies FIRST, then Block policies
- Example: `Web Content Filtering 2-Allow:100;Web Content Filtering 1-Block:200`
- Note: PolicyName includes the -Block or -Allow suffix

#### Priority Assignment
- **DEFAULT disposition:** Priority 60000 (low priority, catch-all)
- **Security groups:** Priority 500, 600, 700, etc. (increment 100)
- Order determined by CSV column position (left to right, starting from column 4)
- Groups with identical policy definitions share the same security profile and priority

### 3. Log File
**Filename:** `[yyyyMMdd_HHmmss]_Convert-ForcepointWS2EIA.log`  
**Location:** Same directory as output CSV files (`$OutputBasePath`)

#### Output Encoding
All CSV exports use UTF-8 with BOM (Byte Order Mark) encoding:
- PowerShell parameter: `-Encoding utf8BOM`
- Ensures Excel compatibility on Windows
- Maintains international character support
- Consistent with other Convert-* functions in Migrate2GSA module

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
# Note: Column matching is case-insensitive
$groupColumns = $allColumns | Where-Object {
    $_ -notmatch '^(Parent Category Name|Child Category Name|DEFAULT Disposition)$' -and
    $_ -match 'Disposition$'
}

# Extract group names (remove " Disposition" suffix and trim whitespace)
# Preserve spaces in group names
$securityGroups = $groupColumns | ForEach-Object {
    ($_ -replace ' Disposition$', '').Trim()
}

# Store original column order for priority assignment
$groupColumnOrder = @{}
$priority = 0
foreach ($col in $groupColumns) {
    $groupName = ($col -replace ' Disposition$', '').Trim()
    $groupColumnOrder[$groupName] = $priority
    $priority++
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
if ([string]::IsNullOrWhiteSpace($disposition)) { 
    Write-LogMessage "Skipping $childCategory for $groupName - empty disposition" -Level "DEBUG"
    continue 
}

# Normalize disposition (trim whitespace, case-insensitive comparison)
$disposition = $disposition.Trim()

# Map action (case-insensitive using -Regex with case-insensitive flag)
$action = switch -Regex ($disposition) {
    '^Block$' { 'Block' }
    '^Continue$' { 
        $policyDefinition.HasContinueAction = $true
        'Block' 
    }
    '^Allow$' { 'Allow' }
    '^Do not block$' { 'Allow' }
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
# NOTE: Arrays MUST be sorted (done in Phase 2.3) to ensure identical policies 
# generate identical hashes regardless of the order items were added
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
    # New unique policy - create policies for Block and/or Allow
    # Note: PolicyCounter increments for EACH policy created (Block and Allow get separate numbers)
    
    # Store policy definition
    $policyDefObject = @{
        Hash = $hash
        Definition = $policyDefinition
        SecurityGroups = @($groupName)
        BlockPolicyName = $null
        AllowPolicyName = $null
    }
    
    $policyDefinitionsHashtable[$hash] = $policyDefObject
    $groupToPolicyDefHashtable[$groupName] = $hash
    
    # Create policy entries (assigns policy names with unique numbers)
    Create-PolicyEntries -PolicyDefObject $policyDefObject -Policies $policies -PolicyCounterRef ([ref]$policyCounter)
}
```

#### 3.3 Create Policy Entries (Helper Logic)

For each unique policy definition, create CSV rows. Each policy has ONE action (Block or Allow), so if a security group has both blocked and allowed items, TWO separate policies are created with UNIQUE numbers:
- One Block policy with blocked categories and/or blocked FQDNs
- One Allow policy with allowed categories and/or allowed FQDNs

Web categories are combined into a single rule with semicolon-separated destinations. FQDNs are created as individual rules (one per FQDN).

**ReviewNeeded and Provision are evaluated PER RULE**, not per policy.

```powershell
function Create-PolicyEntries {
    param(
        $PolicyDefObject, 
        $Policies,
        [ref]$PolicyCounterRef
    )
    
    $def = $PolicyDefObject.Definition
    
    # Create Block policy with rules (if needed)
    if ($def.BlockedCategories.Count -gt 0 -or $def.BlockedFQDNs.Count -gt 0) {
        $blockPolicyName = "Web Content Filtering $($PolicyCounterRef.Value)-Block"
        $PolicyDefObject.BlockPolicyName = $blockPolicyName
        $PolicyCounterRef.Value++
        
        # Rule 1: Blocked categories
        if ($def.BlockedCategories.Count -gt 0) {
            # Check if THIS RULE needs review
            $ruleReviewNeeded = $false
            $ruleReviewReasons = @()
            
            # Check if any blocked categories are unmapped
            $unmappedInThisRule = $def.BlockedCategories | Where-Object { $_ -like '*_Unmapped' }
            if ($unmappedInThisRule) {
                $ruleReviewNeeded = $true
                $ruleReviewReasons += "Unmapped categories: $($unmappedInThisRule -join ', ')"
            }
            
            if ($def.HasContinueAction) {
                $ruleReviewNeeded = $true
                $ruleReviewReasons += "Continue action converted to Block (requires review)"
            }
            
            $ruleProvision = if ($ruleReviewNeeded) { "No" } else { "Yes" }
            $ruleReviewDetails = $ruleReviewReasons -join "; "
            
            $policies.Add([PSCustomObject]@{
                PolicyName = $blockPolicyName
                PolicyType = "WebContentFiltering"
                PolicyAction = "Block"
                Description = "Converted from Forcepoint - Block rules"
                RuleType = "webCategory"
                RuleDestinations = $def.BlockedCategories -join ";"
                RuleName = "Blocked_Categories"
                ReviewNeeded = if ($ruleReviewNeeded) { "Yes" } else { "No" }
                ReviewDetails = $ruleReviewDetails
                Provision = $ruleProvision
            })
        }
        
        # Rules 2+: Blocked FQDNs (one per FQDN)
        # FQDNs from User-Defined don't have unmapped issues, but Continue action still applies
        foreach ($fqdn in $def.BlockedFQDNs) {
            $ruleReviewNeeded = $false
            $ruleReviewReasons = @()
            
            if ($def.HasContinueAction) {
                $ruleReviewNeeded = $true
                $ruleReviewReasons += "Continue action converted to Block (requires review)"
            }
            
            $ruleProvision = if ($ruleReviewNeeded) { "No" } else { "Yes" }
            $ruleReviewDetails = $ruleReviewReasons -join "; "
            
            $policies.Add([PSCustomObject]@{
                PolicyName = $blockPolicyName
                PolicyType = "WebContentFiltering"
                PolicyAction = "Block"
                Description = "Converted from Forcepoint - Block rules"
                RuleType = "FQDN"
                RuleDestinations = $fqdn
                RuleName = "$fqdn-Block"
                ReviewNeeded = if ($ruleReviewNeeded) { "Yes" } else { "No" }
                ReviewDetails = $ruleReviewDetails
                Provision = $ruleProvision
            })
        }
    }
    
    # Create Allow policy with rules (if needed)
    if ($def.AllowedCategories.Count -gt 0 -or $def.AllowedFQDNs.Count -gt 0) {
        $allowPolicyName = "Web Content Filtering $($PolicyCounterRef.Value)-Allow"
        $PolicyDefObject.AllowPolicyName = $allowPolicyName
        $PolicyCounterRef.Value++
        
        # Rule 1: Allowed categories
        if ($def.AllowedCategories.Count -gt 0) {
            # Check if THIS RULE needs review
            $ruleReviewNeeded = $false
            $ruleReviewReasons = @()
            
            # Check if any allowed categories are unmapped
            $unmappedInThisRule = $def.AllowedCategories | Where-Object { $_ -like '*_Unmapped' }
            if ($unmappedInThisRule) {
                $ruleReviewNeeded = $true
                $ruleReviewReasons += "Unmapped categories: $($unmappedInThisRule -join ', ')"
            }
            
            $ruleProvision = if ($ruleReviewNeeded) { "No" } else { "Yes" }
            $ruleReviewDetails = $ruleReviewReasons -join "; "
            
            $policies.Add([PSCustomObject]@{
                PolicyName = $allowPolicyName
                PolicyType = "WebContentFiltering"
                PolicyAction = "Allow"
                Description = "Converted from Forcepoint - Allow rules"
                RuleType = "webCategory"
                RuleDestinations = $def.AllowedCategories -join ";"
                RuleName = "Allowed_Categories"
                ReviewNeeded = if ($ruleReviewNeeded) { "Yes" } else { "No" }
                ReviewDetails = $ruleReviewDetails
                Provision = $ruleProvision
            })
        }
        
        # Rules 2+: Allowed FQDNs (one per FQDN)
        # FQDNs don't have mapping issues, always provision
        foreach ($fqdn in $def.AllowedFQDNs) {
            $policies.Add([PSCustomObject]@{
                PolicyName = $allowPolicyName
                PolicyType = "WebContentFiltering"
                PolicyAction = "Allow"
                Description = "Converted from Forcepoint - Allow rules"
                RuleType = "FQDN"
                RuleDestinations = $fqdn
                RuleName = "$fqdn-Allow"
                ReviewNeeded = "No"
                ReviewDetails = ""
                Provision = "Yes"
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
# Track DEFAULT processing
$defaultPriority = 60000

# Process groups in column order for consistent priority assignment
$groupsToProcess = $securityGroups | Sort-Object { $groupColumnOrder[$_] }

# Assign priorities based on column order
$groupPriorities = @{}
$currentPriority = 500
foreach ($groupName in $groupsToProcess) {
    if ($groupName -eq 'DEFAULT') {
        $groupPriorities[$groupName] = $defaultPriority
    }
    else {
        $groupPriorities[$groupName] = $currentPriority
        $currentPriority += 100
    }
}

foreach ($hash in $hashToGroupsHashtable.Keys) {
    $policyDefObject = $policyDefinitionsHashtable[$hash]
    $groups = $hashToGroupsHashtable[$hash]
    
    # Group names preserve spaces (only trim whitespace at start/end)
    $targetGroups = $groups | ForEach-Object { $_.Trim() }
    
    # Determine priority (use lowest priority of all groups sharing this policy)
    $priority = ($groups | ForEach-Object { $groupPriorities[$_] } | Measure-Object -Minimum).Minimum
    
    # Handle DEFAULT group
    if ($groups -contains 'DEFAULT') {
        $targetGroup = 'Replace_with_All_IA_Users_Group'
    }
    else {
        $targetGroup = $targetGroups -join ";"
    }
    
    # Build policy links
    # IMPORTANT: Allow policies FIRST, then Block policies
    $policyLinks = @()
    $linkPriority = 100
    
    # Add Allow policy first (if exists)
    if ($policyDefObject.AllowPolicyName) {
        $policyLinks += "$($policyDefObject.AllowPolicyName):${linkPriority}"
        $linkPriority += 100
    }
    
    # Add Block policy second (if exists)
    if ($policyDefObject.BlockPolicyName) {
        $policyLinks += "$($policyDefObject.BlockPolicyName):${linkPriority}"
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
Input Processing:
  - Total Forcepoint rows processed: {TotalRowsProcessed}
  - Security groups found: {SecurityGroupsFound}
  - DEFAULT group included: {Yes/No}

Policy Creation:
  - Unique policies created: {UniquePoliciesCreated}
    - Block policies: {BlockPoliciesCreated}
    - Allow policies: {AllowPoliciesCreated}
  - Total policy entries (CSV rows): {PolicyEntriesCreated}
  - Rules requiring review: {RulesNeedingReview}
  
Security Profiles:
  - Security profiles created: {SecurityProfilesCreated}

Actions Processed:
  - Block actions: {BlockActionsProcessed}
  - Allow actions: {AllowActionsProcessed}
  - Continue actions converted to Block: {ContinueActionsConverted}
  - Unknown actions skipped: {UnknownActionsSkipped}

Category Mapping:
  - Mapped categories: {TotalMappedCategories}
  - Unmapped categories: {TotalUnmappedCategories}
  - User-defined FQDNs: {TotalUserDefinedFQDNs}

Deduplication Results:
  - Total security groups: {TotalSecurityGroups}
  - Unique policy definitions: {UniquePolicyDefinitions}
  - Groups sharing policies: {GroupsSharingPolicies}

Output Files:
  - Policies: {policiesCsvPath}
  - Security Profiles: {spCsvPath}
  - Log File: {logPath}
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
| ForcepointPoliciesPath | string | None (required) | Path to Forcepoint policies CSV | ValidateScript - file must exist |
| CategoryMappingsPath | string | None (required) | Path to category mappings CSV | ValidateScript - file must exist |
| OutputBasePath | string | `$PWD` | Output directory for CSV and log files | ValidateScript - directory must exist |
| EnableDebugLogging | switch | `false` | Enable DEBUG level logging | None |

### Parameter Definitions

```powershell
[CmdletBinding(SupportsShouldProcess = $false)]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to Forcepoint Policies CSV export")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
        else { throw "File not found: $_" }
    })]
    [string]$ForcepointPoliciesPath,
    
    [Parameter(Mandatory = $true, HelpMessage = "Path to Forcepoint to GSA category mappings CSV file")]
    [ValidateScript({
        if (Test-Path $_) { return $true }
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

### Example 1: Basic Conversion with Multiple Policies

**Scenario:** Three groups with different dispositions demonstrate policy creation and deduplication.

**Input Forcepoint CSV:**
```csv
Parent Category Name,Child Category Name,DEFAULT Disposition,Finance Group Disposition,Marketing Group Disposition
Abortion,Abortion,Do not block,Block,Do not block
Adult Material,Adult Content,Block,Block,Block
User-Defined,example.com,Block,Allow,Block
```

**Processing Steps:**

1. **DEFAULT Group:** 
   - Blocking: Adult Content (category), example.com (FQDN)
   - Creates: "Web Content Filtering 1-Block" (policy #1)

2. **Finance Group:** 
   - Blocking: Abortion, Adult Content (categories)
   - Allowing: example.com (FQDN)
   - Creates: "Web Content Filtering 2-Block" (policy #2) and "Web Content Filtering 3-Allow" (policy #3)

3. **Marketing Group:**
   - Blocking: Adult Content (category), example.com (FQDN)
   - Matches DEFAULT → REUSES "Web Content Filtering 1-Block"

**Output - Policies CSV:**
```csv
PolicyName,PolicyType,PolicyAction,RuleType,RuleDestinations,RuleName,ReviewNeeded,ReviewDetails,Provision
Web Content Filtering 1-Block,WebContentFiltering,Block,webCategory,AdultContent,Blocked_Categories,No,,Yes
Web Content Filtering 1-Block,WebContentFiltering,Block,FQDN,example.com,example.com-Block,No,,Yes
Web Content Filtering 2-Block,WebContentFiltering,Block,webCategory,Abortion;AdultContent,Blocked_Categories,No,,Yes
Web Content Filtering 3-Allow,WebContentFiltering,Allow,FQDN,example.com,example.com-Allow,No,,Yes
```

**Output - Security Profiles CSV:**
```csv
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Description,Provision
Security_Profile_1,500,Web Content Filtering 3-Allow:100;Web Content Filtering 2-Block:200,CA_Security_Profile_1,_Replace_Me,Finance Group,Converted from Forcepoint - Groups: Finance Group,Yes
Security_Profile_2,600,Web Content Filtering 1-Block:100,CA_Security_Profile_2,_Replace_Me,Marketing Group,Converted from Forcepoint - Groups: Marketing Group,Yes
Security_Profile_3,60000,Web Content Filtering 1-Block:100,CA_Security_Profile_3,_Replace_Me,Replace_with_All_IA_Users_Group,Converted from Forcepoint - Groups: DEFAULT,Yes
```

**Key Observations:**
- Policy numbers are unique: 1, 2, 3 (no reuse of numbers)
- Finance Group has TWO policies (#2-Block and #3-Allow) linked in security profile
- In SecurityProfileLinks, Allow policy (#3) comes FIRST, then Block policy (#2)
- Marketing Group SHARES policy #1 with DEFAULT (identical rules)
- Group names preserve spaces: "Finance Group", "Marketing Group"
- Each group gets own security profile even when sharing policies
- Priority based on column order: Finance (500), Marketing (600), DEFAULT (60000)

### Example 2: Deduplication and Group Consolidation

**Scenario:** Multiple groups with identical policies are consolidated.

**Input:**
```csv
Parent Category Name,Child Category Name,DEFAULT Disposition,Group1 Disposition,Group2 Disposition
Abortion,Abortion,Do not block,Block,Block
Adult Material,Adult Content,Block,Block,Block
```

**Processing:**
- **Group1 & Group2:** Both block Abortion and Adult Content (identical)
- **DEFAULT:** Blocks only Adult Content
- Group1 and Group2 generate same policy definition hash → share policies

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

**Key Observations:**
- ONE policy created for Group1 and Group2 (policy #1)
- ONE security profile for both groups (consolidated in EntraGroups field)
- Groups separated by semicolons in EntraGroups: "Group1;Group2"
- Priority 500 assigned (based on first group's column position)
- Deduplication reduces policy count from 3 potential policies to 2 actual policies

### Example 3: Unmapped Categories and Continue Action

**Scenario:** Demonstrates handling of unmapped categories and Continue action with per-rule review flags.

**Input:**
```csv
Parent Category Name,Child Category Name,DEFAULT Disposition,Test Group Disposition
Gambling,Online Gambling,Do not block,Continue
Custom Category,Test Category,Do not block,Block
User-Defined,trusted.com,Do not block,Allow
```

**Assumptions:**
- "Online Gambling" not in mapping file → becomes "Online Gambling_Unmapped"
- "Test Category" not in mapping file → becomes "Test Category_Unmapped"
- trusted.com is a User-Defined FQDN (no mapping needed)

**Processing:**
- Test Group blocks: Online Gambling (Continue→Block, unmapped), Test Category (unmapped)
- Test Group allows: trusted.com (FQDN)
- DEFAULT has no dispositions → skipped

**Output - Policies CSV:**
```csv
PolicyName,PolicyType,PolicyAction,RuleType,RuleDestinations,RuleName,ReviewNeeded,ReviewDetails,Provision
Web Content Filtering 1-Block,WebContentFiltering,Block,webCategory,Online Gambling_Unmapped;Test Category_Unmapped,Blocked_Categories,Yes,Unmapped categories: Online Gambling_Unmapped; Test Category_Unmapped; Continue action converted to Block (requires review),No
Web Content Filtering 2-Allow,WebContentFiltering,Allow,FQDN,trusted.com,trusted.com-Allow,No,,Yes
```

**Key Observations:**
- Blocked_Categories rule: ReviewNeeded=Yes, Provision=No (unmapped + Continue action)
- FQDN rule: ReviewNeeded=No, Provision=Yes (no mapping issues)
- Review flags are per-rule, not per-policy
- Policy #1 (Block) and Policy #2 (Allow) have different review statuses
- Unmapped categories include "_Unmapped" suffix in destinations

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
    # Input (raw counts)
    TotalRowsProcessed = 0              # Total CSV rows read
    SecurityGroupsFound = 0             # Number of group columns found
    DefaultGroupIncluded = $false       # Whether DEFAULT disposition column exists
    
    # Actions (total occurrence counts)
    ContinueActionsConverted = 0        # Count of Continue actions converted to Block
    BlockActionsProcessed = 0           # Total Block + Continue actions
    AllowActionsProcessed = 0           # Total Allow + "Do not block" actions
    UnknownActionsSkipped = 0           # Actions with unrecognized values
    
    # Categories (occurrence-based counts)
    TotalUnmappedCategories = 0         # Total unmapped category occurrences
    TotalMappedCategories = 0           # Total successfully mapped categories
    TotalUserDefinedFQDNs = 0           # Total FQDN entries from User-Defined rows
    
    # Deduplication
    TotalSecurityGroups = 0             # Total groups processed
    UniquePolicyDefinitions = 0         # Unique policy definition hashes
    GroupsSharingPolicies = 0           # Count of groups sharing policies with others
    
    # Outputs
    UniquePoliciesCreated = 0           # Total unique policy names created
    BlockPoliciesCreated = 0            # Count of policies with -Block suffix
    AllowPoliciesCreated = 0            # Count of policies with -Allow suffix
    PolicyEntriesCreated = 0            # Total CSV rows in Policies output
    RulesNeedingReview = 0              # Count of rules with ReviewNeeded=Yes
    SecurityProfilesCreated = 0         # Total security profiles created
}
```

### DEFAULT Group Special Handling

The DEFAULT disposition column receives special treatment throughout the processing:

**Column Detection:**
- Column name matches "DEFAULT Disposition" (case-insensitive)
- Exact match required (e.g., "DEFAULT" column without "Disposition" suffix is not processed)

**Priority Assignment:**
- Always receives priority 60000 (lowest priority)
- Acts as catch-all for users not in specific security groups
- Priority assigned regardless of column position in CSV

**EntraGroups Mapping:**
- Always set to `Replace_with_All_IA_Users_Group` (placeholder)
- User must replace with actual Entra group name for all Internet Access users
- Never uses "DEFAULT" as the group name in output

**Policy Deduplication:**
- DEFAULT can share policy definitions with other security groups
- If DEFAULT policies match another group, they reuse the same policy names
- DEFAULT always gets its own security profile (never combined with other groups)

**Processing Behavior:**
- Processed in same manner as other groups for policy creation
- Empty DEFAULT dispositions are skipped (same as other groups)
- Can have both Block and Allow policies

**Rationale:** DEFAULT represents the baseline policy for all users not explicitly covered by other security groups.

---

## Edge Cases and Special Scenarios

### Scenario 1: Group with Only "Do not block" / "Allow" Entries
**Input:** All dispositions for a group are "Allow" or "Do not block"  
**Result:** 
- Policy definition contains only AllowedCategories and/or AllowedFQDNs
- Creates ONE Allow policy only (no Block policy)
- Security profile links to Allow policy only

### Scenario 2: All Groups Have Identical Policies
**Input:** Multiple security groups with identical disposition sets  
**Result:**
- One policy definition hash generated
- Policies created once, reused across all groups
- Each group gets its own security profile pointing to the same policies
- Different priorities assigned based on column order ensure correct evaluation

### Scenario 3: Empty Parent Category Name
**Input:** CSV row has empty/null "Parent Category Name"  
**Result:**
- Treated as non-User-Defined (predefined category)
- Uses "Child Category Name" for mapping lookup
- WARN logged about empty parent category
- Processing continues normally

### Scenario 4: No Mapping File Provided or File Not Found
**Input:** CategoryMappingsPath parameter not provided or file missing  
**Result:**
- FATAL ERROR - function exits
- All predefined categories would be unmapped
- Error message directs user to provide valid mapping file

### Scenario 5: FQDN Contains Wildcards or Special Characters
**Input:** User-Defined row has "*.example.com" or similar patterns  
**Result:**
- Passed through as-is to FQDN rule (no validation)
- RuleDestinations contains the exact value from CSV
- Note: FQDN format validation is NOT performed (see Known Limitations)
- User responsible for ensuring valid FQDN syntax

### Scenario 6: Security Group Has No Non-Empty Dispositions
**Input:** All dispositions for a group are empty, null, or whitespace  
**Result:**
- Policy definition has zero items
- Group is skipped (INFO logged)
- No policy or security profile created for this group

### Scenario 7: Only DEFAULT Disposition Exists
**Input:** CSV has only 3 columns (no security group columns)  
**Result:**
- DEFAULT is processed as the only group
- Creates policies and one security profile for DEFAULT
- Priority 60000 assigned to security profile

---

## Known Limitations

1. **Column Header Format:** Assumes columns end with " Disposition" suffix (case-insensitive)
2. **User-Defined Detection:** Relies on "User-Defined" as parent category name (case-insensitive) to identify FQDNs
3. **No FQDN Validation:** Does not validate if User-Defined entries are valid FQDNs or follow proper format
4. **Sequential Naming:** Policy and profile names are sequential integers, not customizable
5. **No Filtering:** Cannot filter specific categories or groups (processes entire CSV)
6. **Memory:** All data held in memory (acceptable for expected data sizes < 10,000 rows)
7. **No Incremental Updates:** Always processes full file, not optimized for incremental changes
8. **Group Name Preservation:** Group names with special characters are preserved; user must ensure Entra compatibility

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

## Sample Files

### Sample Input File for Testing

Create a sample Forcepoint Policies CSV file in the `Samples/ForcepointWS2EIA/` folder to demonstrate the input format and enable testing.

**Filename:** `sample_forcepoint_policies.rename_to_csv`  
**Location:** `Samples/ForcepointWS2EIA/`  
**Purpose:** Provide realistic example of Forcepoint Web Security policy export format

#### Sample File Content

The sample file should include:
- **Predefined Categories:** Mix of mapped and unmapped categories from various parent groups
- **User-Defined FQDNs:** Custom domain entries showing FQDN filtering
- **DEFAULT Disposition:** Baseline policies for all users
- **Multiple Security Groups:** 2-3 example groups with different disposition patterns
- **Various Actions:** Block, Allow, Continue, Do not block
- **Deduplication Scenario:** At least two groups with identical policies

#### Recommended Sample Structure

```csv
Parent Category Name,Child Category Name,DEFAULT Disposition,ESS DA Disposition,Capita India DA Disposition,Finance Team Disposition
Abortion,Abortion,Do not block,Block,Block,Do not block
Abortion,Pro-Choice,Do not block,Block,Do not block,Do not block
Adult Material,Adult Content,Block,Block,Block,Block
Adult Material,Nudity,Block,Block,Block,Block
Gambling,Online Gambling,Do not block,Block,Continue,Block
Gambling,Sports Betting,Do not block,Block,Block,Block
Drugs,Illegal Drugs,Block,Block,Block,Block
Social Networking,Facebook,Do not block,Block,Allow,Block
Social Networking,LinkedIn,Do not block,Allow,Allow,Allow
Social Networking,Twitter,Do not block,Block,Allow,Block
User-Defined,example.com,Block,Allow,Block,Block
User-Defined,internal.company.com,Do not block,Do not block,Do not block,Do not block
User-Defined,test-site.com,Do not block,Block,Block,Block
User-Defined,trusted-partner.com,Do not block,Allow,Allow,Allow
```

#### Key Features Demonstrated

| Feature | Demonstrated By |
|---------|----------------|
| Predefined categories | Abortion, Adult Material, Gambling, etc. |
| Category mapping | Mix of categories in mapping file (some mapped, some unmapped) |
| User-Defined FQDNs | example.com, internal.company.com, etc. |
| DEFAULT baseline | Third column with baseline policies |
| Multiple groups | Three security groups (ESS DA, Capita India DA, Finance Team) |
| Block action | Adult Content, Illegal Drugs, etc. |
| Allow action | LinkedIn, trusted-partner.com |
| Continue action | Online Gambling for "Capita India DA" |
| Do not block | Various categories and FQDNs |
| Policy deduplication | ESS DA and Finance Team both block example.com, test-site.com |
| Mixed policies | Groups with both Block and Allow rules |

#### Notes

- File uses `.rename_to_csv` extension to prevent accidental use as real data
- Users rename to `.csv` when using for testing
- Sample coordinates with existing `Forcepoint-to-GSA-CategoryMapping.rename_to_csv` file
- Should include categories that appear in the mapping file and some that don't (to demonstrate unmapped handling)

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
