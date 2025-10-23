# Provision Entra Internet Access - Technical Specifications

**Version:** 1.0  
**Date:** October 10, 2025  
**Purpose:** Define the complete provisioning process for importing GSA Internet Access configurations and Conditional Access policies from exported CSV files into a new Entra tenant.

---

## Overview

This specification defines how to provision Global Secure Access (GSA) Internet Access filtering profiles, web content filtering policies, TLS inspection policies, and associated Conditional Access policies from exported CSV files into a target Entra tenant.

**Input Sources:**
- `Policies CSV` (REQUIRED) - Web content filtering policies, TLS inspection policies, and their rules
- `Security Profiles CSV` (OPTIONAL) - Security profiles (with links to policies) and Conditional Access policies

**Input Method:** Two separate parameters pointing to individual input files:
- `-PoliciesCsvPath` (REQUIRED) - Path to the policies CSV file containing web content filtering policies, TLS inspection policies, and their rules
- `-SecurityProfilesCsvPath` (OPTIONAL) - Path to the security profiles CSV file containing security profiles and Conditional Access policies

**Target:** New or existing Entra tenant with GSA Internet Access capabilities

---


## 1. Scope and Objectives

### 1.1 What to Provision
- [x] Security Profiles (Internet Access Security profiles)
- [x] Web Content Filtering Policies
- [x] TLS Inspection Policies  
- [x] Policy Rules (webCategory, FQDN, TLS Inspection rules, etc.)
- [x] Conditional Access Policies linked to security profiles
- [x] User/Group assignments to Conditional Access policies
- [x] Unassociated policies (policies not linked to any security profile, or security profile not linked to any Conditional Access)

### 1.2 Selective Provisioning
- **Provision Field Filtering:** Skip items where `Provision = "no"`
- **Policy Name Filtering:** Filter to provision only a specific policy by exact name using `-PolicyName` parameter
- **Output CSV Re-use:** Output CSV files update the `Provision` field based on provisioning results:
  - Successfully provisioned or reused items: `Provision=no` (will be skipped on re-run)
  - Failed, filtered, or skipped items: `Provision=yes` (original value retained, will be retried on re-run)

### 1.3 Provisioning Order (Critical Dependencies)
1. **Web Content Filtering Policies** (and their rules)
2. **TLS Inspection Policies** (and their rules)  
3. **Security Profiles** (referencing the policies created in steps 1-2)
4. **Conditional Access Policies** (referencing security profiles from step 3)

### 1.4 What NOT to Provision
- Items explicitly marked with `Provision = "no"`
- Policies excluded by `-PolicyName` filter (when specified)

---

## 2. Input Validation and Prerequisites

### 2.0 Configuration File Management
- **Input Parameters:** 
  - `-PoliciesCsvPath` (REQUIRED) - Path to the policies CSV file containing web content filtering policies, TLS inspection policies, and their rules
  - `-SecurityProfilesCsvPath` (OPTIONAL) - Path to the security profiles CSV file containing security profiles (with links to policies) and Conditional Access policies
  - `-PolicyName` (OPTIONAL) - Filter to provision only the policy with this exact name
- **Flexible Input:** Users can provision from any CSV file location
- **Note:** Only the policies CSV is required; Security Profiles CSV can be omitted if not provisioning security profiles or CA policies

### 2.0.1 Parameter Validation and Mutual Exclusivity
- **Mutual Exclusivity Rule:** `-PolicyName` and `-SecurityProfilesCsvPath` cannot be used together
- **Validation Logic:**
  ```powershell
  if ($PolicyName -and $SecurityProfilesCsvPath) {
      throw "PolicyName filter cannot be used with SecurityProfilesCsvPath. Use PolicyName for policy-only provisioning."
  }
  ```
- **Rationale:** Policy filtering is for testing/incremental updates of individual policies; security profiles require complete policy context

- **SkipCAPoliciesProvisioning Parameter:**
  - Can be used with any other parameter combination
  - When enabled, skips user/group resolution (not needed without CA policies)
  - Compatible with `-SecurityProfilesCsvPath` (creates profiles without CA policies)
  - Compatible with `-PolicyName` (though CA policies wouldn't be created anyway for single policy provisioning)
  - No validation errors - it's a filtering option, not a mutual exclusivity constraint

### 2.1 Target Tenant Assumptions
- **Existing Content:** Target tenant may have existing security profiles and policies. Script need to warm user in case -Whatif was not selected and encourage user to run -Whatif as first
- **Licensing:** No automatic licensing checks (assumed to be handled externally)
- **GSA Feature Availability:** Assumed to be available and configured

### 2.2 User/Group Assignment Handling
- **Resolution Before Provisioning:** All users and groups referenced in the Security Profiles CSV are resolved and cached before any provisioning begins
  - **Exception:** If `-SkipCAPoliciesProvisioning` is specified, user/group resolution is skipped entirely (not needed without CA policies)
- **Missing Users/Groups:** If any user/group names don't exist in target tenant:
  - Log WARNING for each missing user/group with details
  - After checking all users/groups, STOP script execution if any are missing
  - Provide summary of all missing assignments in error message
  - User must fix CSV and re-run
  - **Exception:** If `-SkipCAPoliciesProvisioning` is specified, no validation is performed (CA policies won't be created)
- **Rationale:** Prevents creating incomplete CA policies; ensures all assignments are valid before provisioning

### 2.3 Policies CSV File Format

**Row Structure:**
- Every row represents a **rule** belonging to a policy
- Policy metadata (PolicyName, PolicyType, PolicyAction, Description) is repeated on every row for the same policy
- Policies are created by grouping rows with the same PolicyName
- Rules are created from each row's RuleType, RuleDestinations, and RuleName fields

**Required Columns:**
- `PolicyName` - Name of the policy (required on all rows)
- `PolicyType` - Type of policy (required on all rows)
  - Values: `WebContentFiltering`, `TLSInspection`
- `PolicyAction` - Action for the policy (required on all rows)
  - For WebContentFiltering: `Allow`, `Block` (case-insensitive, converted to lowercase for API)
  - For TLSInspection: `Inspect` (ignored - TLS inspection policies always inspect, action is specified at rule level)
- `Description` - Policy description (optional, should be consistent across all rows for same policy)
- `RuleType` - Type of rule (required on all rows)
  - For WebContentFiltering: `FQDN`, `URL`, `webCategory`
  - For TLSInspection: `bypass` (TLS rules can bypass or inspect specific destinations)
- `RuleDestinations` - Semicolon-separated list of destinations (required on all rows)
  - Will be split by semicolon, trimmed, and passed as array to internal functions
- `RuleName` - Name of the rule (required on all rows)
- `Provision` - Whether to provision this rule (required on all rows)
  - Values: `yes`, `no`
  - Rows with `Provision = no` are filtered out during CSV import

**Additional Columns:**
- Any other columns in the CSV are ignored by the provisioning script

**Data Redundancy:**
- Policy metadata is intentionally repeated on every rule row
- This is EXPECTED behavior for easier CSV creation and editing
- All rows for the same policy MUST have identical PolicyName, PolicyType, PolicyAction, and Description

**Example Rows:**
```csv
PolicyName,PolicyType,PolicyAction,Description,RuleType,RuleDestinations,RuleName,Provision
Dev_Tools-Allow,WebContentFiltering,Allow,Development tools,FQDN,github.com;*.github.io;stackoverflow.com,GitHub_StackOverflow,yes
Dev_Tools-Allow,WebContentFiltering,Allow,Development tools,URL,https://docs.microsoft.com/*;https://learn.microsoft.com/*,Microsoft_Docs,yes
Dev_Tools-Allow,WebContentFiltering,Allow,Development tools,webCategory,DeveloperTools;Programming,Dev_Categories,yes
Social_Media-Block,WebContentFiltering,Block,Block social media sites,webCategory,SocialNetworking;Entertainment,Social_Categories,yes
TLS_Finance-Inspect,TLSInspection,Inspect,Inspect financial traffic,bypass,*.internal-bank.com;secure-finance.contoso.com,Finance_Bypass,yes
Marketing_Sites-Allow,WebContentFiltering,Allow,Allow marketing tools,FQDN,*.google-analytics.com;*.adobe.com;hubspot.com,Marketing_Tools,yes
```

**Note:** Policy metadata (PolicyName, PolicyType, PolicyAction, Description) is repeated on every row. Each row represents one rule for the policy.

### 2.4 Security Profiles CSV File Format

**Row Structure:**
- Each row represents **one complete Security Profile** with its linked Conditional Access policy
- 1:1 relationship enforced: One Security Profile = One CA Policy
- Policy links specified as semicolon-separated `PolicyName:Priority` pairs
- User/group assignments apply to the CA policy

**Required Columns:**
- `SecurityProfileName` - Name of the security profile (required - always)
- `SecurityProfileLinks` - Semicolon-separated array of PolicyName:Priority pairs (required - always)
  - Format: `PolicyName1:100;PolicyName2:200`
  - Will be split by semicolon, trimmed, and parsed as PolicyName and Priority
  - If empty, the entire row is filtered out during CSV import
- `CADisplayName` - Conditional Access policy name (conditionally required)
  - Required only if at least one of `EntraUsers` or `EntraGroups` is populated
  - If both `EntraUsers` and `EntraGroups` are empty, `CADisplayName` can be empty (no CA policy will be created)
- `EntraUsers` - User Principal Names (email format), semicolon-separated (optional)
- `EntraGroups` - Group display names, semicolon-separated (optional)
  - If both `EntraUsers` and `EntraGroups` are empty, CA policy is NOT created
  - Security Profile and policy links are still created
- `Provision` - Whether to provision this item (required - always)
  - Values: `yes`, `no`
  - Rows with `Provision = no` are filtered out during CSV import

**Additional Columns:**
- Any other columns in the CSV are ignored by the provisioning script

**Example Rows:**
```csv
SecurityProfileName,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Profile_Finance_Strict,Policy_Web_Finance:100;Policy_TLS_Finance:200,CA_Finance_Access,john.doe@contoso.com;jane.smith@contoso.com,Finance_Group;Executives_Group,yes
Profile_Marketing_Standard,Policy_Web_Marketing:150,CA_Marketing_Access,marketing.team@contoso.com,Marketing_Group,yes
Profile_IT_NoCA,Policy_Web_Admin:50;Policy_TLS_Admin:75,,,,yes
Profile_Dev_NoCA,Policy_Web_Dev:80,,,,yes
Profile_Test,Policy_Test:100,CA_Test_Access,test.user@contoso.com,,no
```

**Notes:**
- Row 3 & 4 examples: Empty `CADisplayName`, empty users/groups → Security Profile created, CA policy skipped
- Row 5 example: `Provision=no` → Entire row filtered out during import

### 2.5 CSV File Validation

#### 2.5.1 CSV-Level Validation (Stop Script on Failure)
**When:** During CSV import (Import-PoliciesConfig, Import-SecurityProfilesConfig)
**Behavior:** `throw` error and stop entire script execution

**Validation Checks:**
- ✅ File existence and readability
- ✅ File contains data (not empty)
- ✅ All required columns present
  - Policies CSV: `PolicyName`, `PolicyType`, `PolicyAction`, `RuleType`, `RuleDestinations`, `RuleName`, `Provision`
  - Security Profiles CSV: `SecurityProfileName`, `SecurityProfileLinks`, `CADisplayName`, `EntraUsers`, `EntraGroups`, `Provision`
- ✅ **Policy Metadata Consistency** (Policies CSV only):
  - Group all rows by PolicyName
  - For each policy group, validate that all rows have identical:
    - `PolicyType`
    - `PolicyAction`
    - `Description` (if provided)
  - If inconsistent, throw error with details
- ✅ **Security Profile Validation** (Security Profiles CSV only):
  - No metadata consistency validation needed (one row per profile)
  - Empty `SecurityProfileLinks` validation handled during row filtering

**Error Handling:**
```powershell
if ($missingColumns.Count -gt 0) {
    throw "Missing required columns: $($missingColumns -join ', ')"
}

# Validate policy metadata consistency
$policyGroups = $csvData | Group-Object PolicyName
foreach ($policyGroup in $policyGroups) {
    $distinctTypes = $policyGroup.Group.PolicyType | Select-Object -Unique
    $distinctActions = $policyGroup.Group.PolicyAction | Select-Object -Unique
    
    if ($distinctTypes.Count -gt 1) {
        throw "Policy '$($policyGroup.Name)' has inconsistent PolicyType values: $($distinctTypes -join ', ')"
    }
    
    if ($distinctActions.Count -gt 1) {
        throw "Policy '$($policyGroup.Name)' has inconsistent PolicyAction values: $($distinctActions -join ', ')"
    }
}
```

#### 2.5.2 Row-Level Field Validation
**When:** During CSV import (for structural validation) and before provisioning (for business logic validation)
**Behavior:** 
- During import: Filter out invalid rows, mark with appropriate result, exclude from provisioning
- Before provisioning: Log ERROR, mark row as failed in output CSV, continue with next object

**Validation Checks by Object Type:**

**Policy Rules (all rows in Policies CSV):**
- Required fields for ALL rows:
  - `PolicyName` - Must be populated
  - `PolicyType` - Must be `WebContentFiltering` or `TLSInspection`
  - `PolicyAction` - Must be populated (converted to lowercase)
  - `RuleType` - Must be valid for the PolicyType
  - `RuleDestinations` - Must be populated
  - `RuleName` - Must be populated
- Optional fields:
  - `Description` - Can be empty, but should be consistent across all rows for same policy
- Validation pattern:
```powershell
if (-not $Row.PolicyName -or -not $Row.PolicyType -or -not $Row.PolicyAction -or 
    -not $Row.RuleType -or -not $Row.RuleDestinations -or -not $Row.RuleName) {
    Write-LogMessage "Skipping rule: missing required fields" -Level ERROR -Component "PolicyProvisioning"
    $Row.ProvisioningResult = "Failed: Missing required fields"
    # Continue with next row
}
```

**Security Profile with CA Policy (each row in Security Profiles CSV):**

**During Import (structural validation - filters rows out):**
- Missing `SecurityProfileName` → Row filtered out, marked as "Failed: Missing required field SecurityProfileName"
- Missing `CADisplayName` → Row filtered out, marked as "Failed: Missing required field CADisplayName"
- Empty `SecurityProfileLinks` → Row filtered out, marked as "Skipped: No policy links specified"
- `Provision = no` → Row filtered out, marked as "Filtered: Provision set to 'no'"

**Before Provisioning (business logic validation - skips individual operations):**
- By this point, all rows have passed structural validation
- Required fields validated during import: `SecurityProfileName`, `SecurityProfileLinks`
- Check for empty users/groups to determine CA policy creation:
  - If both `EntraUsers` and `EntraGroups` are empty → Skip CA policy creation, create Security Profile only
  - If at least one is populated → Validate `CADisplayName` is present, then create both Security Profile and CA policy
- Validation pattern:
```powershell
# This validation happens DURING PROVISIONING

# Business logic: Check if CA policy should be created
$hasUsers = -not [string]::IsNullOrWhiteSpace($Row.EntraUsers)
$hasGroups = -not [string]::IsNullOrWhiteSpace($Row.EntraGroups)

if (-not $hasUsers -and -not $hasGroups) {
    Write-LogMessage "Security Profile will be created without CA policy (no users/groups specified)" -Level INFO
    # Continue - create profile but skip CA policy
} else {
    # CA policy should be created - validate CADisplayName is present
    if ([string]::IsNullOrWhiteSpace($Row.CADisplayName)) {
        Write-LogMessage "Skipping row: CADisplayName is required when users or groups are specified" -Level ERROR -Component "SecurityProfileProvisioning"
        $Global:RecordLookup[$Row.UniqueRecordId].ProvisioningResult = "Failed: Missing required field CADisplayName (needed for CA policy)"
        return # Skip this row
    }
}
```

**Empty/Null/Whitespace Handling:**
- Use `-not` operator which treats `$null`, empty string `""`, and whitespace-only strings as empty
- PowerShell's `-not` evaluates to `$true` for: `$null`, `""`, `" "` (whitespace)
- Example: `if (-not $value)` catches all empty cases

#### 2.5.3 Post-Validation Actions
**After CSV import:**
- Filter to only required columns (remove extra columns)
- Add `ProvisioningResult` tracking column (empty by default)
- Add `UniqueRecordId` for efficient lookup
- Create global lookup hashtable for O(1) access

**After all validation:**
- If all rows filtered/invalid → Log ERROR, export results, `return` (stop gracefully)
- If some rows valid → Proceed with provisioning

---

## 3. Provisioning Strategy

### 3.1 Provisioning Order (Critical Dependencies)
1. **Web Content Filtering Policies** (and their rules)
2. **TLS Inspection Policies** (and their rules)  
3. **Security Profiles** (referencing the policies created in steps 1-2)
4. **Conditional Access Policies** (referencing security profiles from step 3)

### 3.2 CSV Data Structure Understanding

#### Policies CSV Structure
- **Every row is a rule:** CSV uses one row per rule with policy metadata repeated
  - Each row contains: Policy metadata + Rule data
  - Policy metadata is repeated on every rule row for the same policy
  - This is EXPECTED behavior for simpler CSV creation, not data duplication
- **Policy Creation Logic:**
  - Group rows by PolicyName to identify unique policies
  - Extract policy metadata from first row of each group (all rows should have identical metadata)
  - Create policy once per unique PolicyName
  - Create all rules from the grouped rows
- **Grouping Logic:** `$csvData | Group-Object PolicyName`

#### Security Profiles CSV Structure
- **One row per Security Profile:** CSV uses one row per complete Security Profile with CA policy
  - Each row contains: Security Profile metadata + Policy links + CA policy metadata + User/group assignments
  - 1:1 relationship: One Security Profile = One CA Policy
  - No data redundancy across rows
- **Policy Links Parsing:**
  - `SecurityProfileLinks` field contains semicolon-separated `PolicyName:Priority` pairs
  - Example: `Policy1:100;Policy2:200;Policy3:300`
  - Parsed during provisioning to create multiple policy links for the profile
- **Conditional Access Handling:**
  - If `EntraUsers` and `EntraGroups` both empty → Create Security Profile only, skip CA policy
  - If at least one populated → Create both Security Profile and CA policy
- **No Grouping Logic:** Each row is independent (one row = one complete entity)

### 3.3 TLS Inspection Policy Handling
- **Empty TLS Policies:** Create TLS policy object with just the default action (no rules)
- **TLS with Rules:** Create policy with default action plus all specified rules

### 3.4 Creation Order (Granular)
1. **Policies** (Web Content Filtering and TLS Inspection policies - create the container first)
2. **Rules** (Create rules for each policy, now that policies exist with IDs)
3. **Security Profiles** (linking to the policies created in step 1)
4. **Conditional Access Policies** (linking to security profiles, created in DISABLED state)

### 3.5 Conditional Access Policy State Management
- **Initial State:** Always create CA policies in `disabled` state regardless of CSV state
- **Admin Validation Required:** Admin must manually validate configuration and enable CA policies
- **Rationale:** Safety measure to prevent accidental access restrictions

### 3.6 Idempotent Re-Run Behavior

**Design Goal:** Script is fully idempotent - running multiple times with the same CSV produces the same final state, creating only missing objects/rules/links.

#### Policy Re-Use (Web Content Filtering & TLS Inspection)
If policy with same name already exists in target tenant:
- **Behavior:** Reuse existing policy, add only missing rules
- **Rule Matching:** Check if rule with same `RuleName` already exists in the policy
  - If rule exists: Skip it, mark as `"Reused: Rule already exists"`
  - If rule missing: Create it, mark as `"Provisioned: Rule created successfully"`
- **Policy Result:** Mark policy as `"Reused: Policy exists - added X new rules, Y rules already existed"`
- **Use Case:** Recover from partial failures, add new rules to existing policies

#### Security Profile Re-Use
If security profile with same name already exists in target tenant:
- **Behavior:** Reuse existing profile (ignore priority differences), add only missing policy links
- **Priority Handling:** Ignore difference between CSV priority and actual profile priority
  - Rationale: Profile may have been created with incremented priority in previous run
  - Keep existing profile as-is, do not attempt to modify priority
- **Policy Link Matching:** Check if link to same `PolicyName` already exists in the profile
  - If link exists: Skip it (ignore priority differences in link)
  - If link missing: Create new link with priority from CSV
- **Profile Result:** Mark profile as `"Reused: Profile exists - added X new policy links, Y links already existed"`
- **Use Case:** Recover from partial failures, add new policy links to existing profiles

#### Conditional Access Policy Re-Use
If CA policy with same name already exists in target tenant:
- **Behavior:** Skip CA policy creation entirely, mark as `"Reused: CA policy already exists"`
- **Rationale:** CA policies are sensitive security controls, do not modify existing policies
- **User/Group Assignments:** Do not update assignments on existing CA policies

#### Priority Conflicts (Security Profiles - New Creation Only)
If creating a **NEW** security profile and priority number conflicts with a **DIFFERENT** existing profile:
- **Behavior:** Automatically increment priority by 1 and attempt creation once
- **Single Attempt:** If incremented priority also fails, log WARN and skip
- Mark in output CSV with `ProvisioningResult = "Failed: Priority conflict - priority {priority} and {priority+1} already exist"`
- **Does NOT Apply:** When reusing existing profile with same name (priority ignored)

#### WhatIf Preview for Re-Runs
- `-WhatIf` mode detects existing objects and shows incremental changes:
  - "Policy_Web_Social: EXISTS - will add 3 new rules (12 rules already exist)"
  - "Profile_Finance: EXISTS - will add 1 new policy link (2 links already exist)"
  - "CA_Finance_Access: EXISTS - will skip (already provisioned)"

### 3.7 Filtering Parameters
- **Policy Name Filter:**
  - `-PolicyName "ExactPolicyName"` - Provision only the policy with this exact name (case-insensitive)
  - **Exact Match Only:** No wildcards or patterns supported
  - **Mutual Exclusivity:** Cannot be used with `-SecurityProfilesCsvPath`
  - **Use Case:** Testing individual policy provisioning or incremental updates
  - **Validation:** Script must error if both `-PolicyName` and `-SecurityProfilesCsvPath` are specified
  - **Filtering Behavior:** 
    - Filters policies CSV to include only rows matching the exact policy name (case-insensitive)
    - All rules for the matched policy are included
    - Filtered records are excluded from provisioning and marked in output CSV

- **Skip CA Policies Filter:**
  - `-SkipCAPoliciesProvisioning` - Skip creation of ALL Conditional Access policies
  - **Switch Parameter:** No value needed (presence enables the skip behavior)
  - **Behavior:** 
    - Security Profiles CSV is still processed and profiles are created
    - Policy links are created for all Security Profiles
    - NO Conditional Access policies are created (all CA policy creation is skipped)
    - User/group resolution is skipped (not needed without CA policies)
  - **Use Case:** 
    - Create Security Profiles without associated CA policies
    - Defer CA policy creation to later manual configuration
    - Testing Security Profile and policy link provisioning in isolation
  - **Logging:** 
    - Prominent log message at script start: "CA policy provisioning is DISABLED via -SkipCAPoliciesProvisioning parameter"
    - Each Security Profile logs: "CA policy creation skipped (disabled by parameter)"
  - **WhatIf Output:** Clearly shows CA policies will be skipped with reason
  - **CSV Marking:** 
    - Security Profile rows marked as: "Provisioned: Security Profile created (CA policy skipped by parameter)"
    - No validation errors for missing users/groups (not needed)
  - **Compatibility:** Can be used with `-PolicyName`, `-SecurityProfilesCsvPath`, `-WhatIf`, and `-Force`

### 3.8 Complete Parameter Design
```powershell
.\Start-EntraInternetAccessProvisioning.ps1 
    -PoliciesCsvPath "path\to\policies.csv"                          # REQUIRED
    [-SecurityProfilesCsvPath "path\to\security_profiles.csv"]       # OPTIONAL
    [-PolicyName "ExactPolicyName"]                                   # OPTIONAL - Filter to specific policy
    [-SkipCAPoliciesProvisioning]                                     # OPTIONAL - Skip ALL CA policy creation
    [-WhatIf]      # Preview mode with dedicated analysis log
    [-Debug]       # Enable debug logging (passed to internal functions)
    [-LogPath "path\to\logfile.log"]  # Defaults to $PWD\Start-EntraInternetAccessProvisioning.log
    [-Force]       # Skip confirmation prompts
```

**Parameter Notes:** 
- `-PoliciesCsvPath` is REQUIRED - contains web content filtering policies, TLS inspection policies, and their rules
- `-SecurityProfilesCsvPath` is OPTIONAL - contains security profiles (with links to policies) and Conditional Access policies; only needed if provisioning security profiles or CA policies
- `-PolicyName` is OPTIONAL - filters to provision only the policy with this exact name (case-insensitive); mutually exclusive with `-SecurityProfilesCsvPath`
- `-SkipCAPoliciesProvisioning` is OPTIONAL - switch parameter to skip ALL Conditional Access policy creation; Security Profiles are still created with policy links but no CA policies are provisioned
- `-Debug` is OPTIONAL - provided automatically by `[CmdletBinding()]`; enables debug logging and passes `-Debug` to internal functions when `$DebugPreference -eq 'Continue'`
- `-LogPath` is OPTIONAL - defaults to `$PWD\${timestamp}_Start-EntraInternetAccessProvisioning.log` (current directory where function is called, timestamped); if custom path provided, timestamp is NOT added
- `-Force` is OPTIONAL - skips user confirmation prompts for automated execution

### 3.9 Force Parameter Behavior
- **Purpose:** Skip user confirmation prompts for automated/unattended execution

---

## 4. Error Handling and Recovery

### 4.1 Error Categories
- **Validation errors:** CSV format, missing dependencies, name conflicts
- **API errors:** Permissions, throttling, service unavailable
- **Business logic errors:** Invalid configurations, missing references

### 4.2 Recovery Strategies
- **Partial Failure Handling:** Just log the failure and leave partial state
- **No Automatic Rollback:** Admin responsible for cleanup if needed
- **Continue Where Possible:** Don't stop entire process for single object failures

### 4.3 Logging and Reporting
- **Logging Function:** All logging uses `Write-LogMessage` (from internal/functions/Write-LogMessage.ps1)
  - Writes to console with color-coded output based on log level
  - Writes to log file simultaneously
  - Supports component tagging for categorization
- **Default Log Location:** `$PWD\${timestamp}_Start-EntraInternetAccessProvisioning.log` (current directory where function is called, timestamped)
- **Custom Log Path:** User can override with `-LogPath` parameter (custom path does not get timestamped)
- **Log File Initialization:** Generate timestamp and set `$script:LogPath` variable at function start for Write-LogMessage to use
- **Timestamp Consistency:** Same timestamp used for all output files (logs and CSVs) in a single execution
- **Debug Logging Approach:**
  - Function uses `[CmdletBinding(SupportsShouldProcess = $true)]` which provides `-Debug` switch
  - Check `$DebugPreference -eq 'Continue'` to conditionally pass `-Debug` to internal functions
  - Example pattern:
    ```powershell
    $params = @{
        Name = $policyName
        Action = $action
    }
    if ($DebugPreference -eq 'Continue') {
        $params['Debug'] = $true
    }
    $result = New-IntFilteringPolicy @params
    ```
  - Debug messages use component tagging like other log levels: `Write-LogMessage "Details..." -Level DEBUG -Component "PolicyProvisioning"`
- **WhatIf Mode:** Dedicated analysis log for preview operations (separate from execution logs)
  - WhatIf log file: `$PWD\${timestamp}_Start-EntraInternetAccessProvisioning_WhatIf.log`
  - Uses same timestamp as other output files from the same execution

---

## 5. Implementation Approach

### 5.1 Script Structure
- **Function Name:** `Start-EntraInternetAccessProvisioning`
- **Script File:** `Start-EntraInternetAccessProvisioning.ps1`
- **Location:** `Migrate2GSA\functions\GSA\`
- **Dependencies:** 
  - Microsoft.Graph.Authentication module
  - Internal shared functions: `Write-LogMessage`, `Invoke-InternalGraphRequest`, `Write-ProgressUpdate`, `Export-DataToFile`
  - Internal EIA functions (from `internal\functions\EIA\`):
    - `New-IntFilteringPolicy`, `Get-IntFilteringPolicy`
    - `New-IntFqdnFilteringRule`, `New-IntUrlFilteringRule`, `New-IntWebCategoryFilteringRule`
    - `New-IntTlsInspectionPolicy`, `Get-IntTlsInspectionPolicy`
    - `New-IntTlsInspectionRule`
    - `New-IntSecurityProfile`, `Get-IntSecurityProfile`
    - `New-IntFilteringPolicyLink`
  - Conditional Access internal functions (to be created)

### 5.2 Pre-Provisioning Validation
- **Required PowerShell Modules:** Use the `Test-RequiredModules` internal function from `internal/functions/Test-RequiredModules.ps1`
  - Microsoft.Graph.Authentication
  - The function handles validation and provides installation instructions if the module is missing
- **Target Tenant Connectivity:** 
  - **Assumption:** User has already connected via `Connect-MgGraph` or `Connect-Entra` before running script
  - Use `Test-GraphConnection` internal function from `internal/functions/Test-GraphConnection.ps1`
  - Validates Microsoft Graph authentication connection exists (via `Get-MgContext`)
  - Validates all required scopes are present in the current authentication context
  - If not connected or scopes missing, throws error with connection instructions
  - **Do NOT attempt to connect** - this is the user's responsibility
  - Function supports both Connect-MgGraph and Connect-Entra authentication
- **CSV File Validation:** 
  - File existence and readability for policies CSV (required)
  - File existence and readability for security profiles CSV (if provided)
  - CSV structure validation (headers, data types)
  - All required columns present
- **Dependency Validation:**
  - All policy references in security profiles CSV exist in policies CSV
  - Security profile references in CA policies are valid

### 5.3 Dependency Resolution During Provisioning
- **Failed Policy References:** If a Security Profile references a policy that failed to create:
  - Create the Security Profile WITHOUT that policy link
  - Log ERROR with details of missing policy reference
  - Update `ProvisioningResult` to indicate partial success (e.g., "Provisioned: Security Profile created with X policy links (Y links skipped - policies not found)")
  - Continue processing other policies for the profile

### 5.4 Logging and Reporting Structure

**Log Files (in $PWD by default):**
```
$PWD/
  └── YYYYMMDD_HHMMSS_Start-EntraInternetAccessProvisioning.log                # Main log file (timestamped)
  └── YYYYMMDD_HHMMSS_Start-EntraInternetAccessProvisioning_WhatIf.log         # WhatIf analysis log (if -WhatIf used)
  └── YYYYMMDD_HHMMSS_policies_provisioned.csv                                 # Policies results CSV (Provision field updated based on results)
  └── YYYYMMDD_HHMMSS_security_profiles_provisioned.csv                        # Security profiles results CSV (Provision field updated based on results, if provided)
```

**Output CSV Provision Field:**
- Successfully provisioned or reused items have `Provision=no` (skip on re-run)
- Failed, filtered, or skipped items retain original `Provision` value (retry on re-run)
- Output CSV can be used as input for re-run to retry only failed items

**Timestamp Consistency:**
- All output files (logs and CSVs) use the same timestamp generated at script start
- Timestamp format: `yyyyMMdd_HHmmss` (e.g., `20251022_143022`)
- Makes it easy to correlate logs and results from the same execution

**Write-LogMessage Usage:**
- All console and file logging uses `Write-LogMessage` function
- Automatic log file creation in `$PWD` (current directory)
- Timestamped log filename: `${timestamp}_Start-EntraInternetAccessProvisioning.log`
- Set timestamp and log path at function start:
  ```powershell
  $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
  $script:LogPath = if ($LogPath) { 
      $LogPath 
  } else { 
      "$PWD\${timestamp}_Start-EntraInternetAccessProvisioning.log" 
  }
  ```
- Write-LogMessage automatically uses script-scoped `$LogPath` variable

**Logging Components** (using `Write-LogMessage -Component`):
- `ModuleCheck` - PowerShell module validation
- `Auth` - Entra authentication validation
- `Config` - CSV import and validation (policies CSV and security profiles CSV)
- `Validation` - Dependency and conflict checks
- `PolicyProvisioning` - Web content filtering and TLS inspection policy creation
- `SecurityProfileProvisioning` - Security profile creation
- `ConditionalAccessProvisioning` - CA policy creation
- `GroupAssignment` - User/group assignments to CA policies
- `Export` - Results CSV export
- `Summary` - Execution summary statistics
- `Main` - Main orchestration flow
- `GraphAPI` - API request logging (via Invoke-InternalGraphRequest)

**Log Levels:**
- `INFO` - General informational messages (white)
- `SUCCESS` - Successful operations (green)
- `WARN` - Warnings and non-critical issues (yellow)
- `ERROR` - Errors and failures (red)
- `DEBUG` - Debug information (cyan) - requires `-Debug` switch
- `SUMMARY` - Summary and high-level reporting (magenta)

### 5.5 Final Output and Summary
- **Summary Report:** Count of created/reused/failed objects by type:
  ```
  Provisioning Summary:
  =====================
  Web Content Filtering Policies: 5 created, 1 reused (added 3 rules), 0 failed
  TLS Inspection Policies: 2 created, 1 reused (added 2 rules), 1 failed  
  Security Profiles: 3 created, 1 reused (added 1 policy link), 0 failed
  Conditional Access Policies: 2 created, 1 reused (skipped), 0 failed
  
  Manual Attention Required:
  - 2 CA policies created in DISABLED state (require manual validation)
  - 1 Security Profile missing policy links (see error log)
  ```

---

## 6. WhatIf Mode - Preview and Analysis

### 6.1 Purpose and Benefits
- **Safe Planning:** Preview all operations before execution
- **Conflict Detection:** Identify naming conflicts, priority collisions, and missing dependencies
- **Assignment Validation:** Check user/group existence in target tenant
- **Admin Confidence:** Provide clear visibility into what will be created, skipped, or failed

### 6.2 WhatIf Output Structure

#### 6.2.1 Dedicated WhatIf Log
**File:** `$PWD\${timestamp}_Start-EntraInternetAccessProvisioning_WhatIf.log` (default location, timestamped)

**Content Structure:****
```
===============================================
PROVISION WHAT-IF ANALYSIS
===============================================
Target Tenant: contoso.onmicrosoft.com
Analysis Date: 2025-10-10 15:30:22
CSV Files: 
  - Policies: .\policies.csv (150 rows)
  - Security Profiles: .\security_profiles.csv (75 rows)
Filters Applied:
  - Policy Name Filter: None

OBJECTS TO BE CREATED:
======================
✅ Web Content Filtering Policies: 8 policies
   - Policy_Web_Social: 15 rules (ALLOW social media)
   - Policy_Web_Security: 22 rules (BLOCK malware sites)
   
✅ TLS Inspection Policies: 3 policies  
   - Policy_TLS_Finance: 5 rules (INSPECT finance sites)
   
✅ Security Profiles: 4 profiles
   - Profile_Finance_Strict: Links 2 policies, Priority 100
   - Profile_Marketing_Standard: Links 1 policy, Priority 200

✅ Conditional Access Policies: 2 policies
   - CA_Finance_Access: Links Profile_Finance_Strict, 15 users, 2 groups
   - CA_Marketing_Access: Links Profile_Marketing_Standard, 8 users, 1 group

CONFLICTS DETECTED:
==================
❌ Security Profile "Profile_Finance_Strict" already exists
   → Resolution: Will be SKIPPED
   
⚠️  Priority 100 already used by existing profile "Legacy_Profile"  
   → Resolution: Will attempt creation with priority 101

❌ User "john.doe@contoso.com" not found in target tenant
   → Resolution: Script will STOP - fix CSV before provisioning

❌ Group "Finance_Group" not found in target tenant
   → Resolution: Script will STOP - fix CSV before provisioning

SUMMARY:
========
Total Objects to Create: 15
- Will Create Successfully: 13
- Will Skip (Name Conflicts): 1
- Will Attempt with Adjusted Priority: 1
- Errors (Missing Users/Groups): 2 - SCRIPT WILL STOP

RECOMMENDATION:
- Review conflicts above
- Name conflicts must be resolved manually in CSV
- Missing users/groups must be fixed before provisioning can proceed
- Verify user/group names in target tenant or remove from CSV
```

#### 6.2.2 Enhanced Console Output
```powershell
=== PROVISION WHAT-IF ANALYSIS ===
Target: contoso.onmicrosoft.com

Objects to Create: 15 total
✅ Will Create: 13 objects  
❌ Name Conflicts: 1 object (will skip)
⚠️  Priority Conflicts: 1 object (will attempt with priority+1)
❌ Errors: 2 missing users/groups - WILL STOP

Conflicts Found:
• Profile "Profile_Finance_Strict" exists (will be skipped)
• Priority 100 already used (will attempt with priority 101)

Missing Users/Groups (BLOCKING):
• User "john.doe@contoso.com" not found
• Group "Finance_Group" not found

📝 Detailed analysis: $PWD\${timestamp}_Start-EntraInternetAccessProvisioning_WhatIf.log

Ready to proceed? Run without -WhatIf to execute.
```

### 6.3 WhatIf Analysis Features
- **Object Counting:** Total objects to be created by type
- **Conflict Detection:** Name conflicts, priority collisions, existing objects
- **Dependency Validation:** Missing references between CSV files, missing users/groups in target tenant
- **Assignment Verification:** User/group existence in target tenant (blocking errors if missing)
- **Priority Increment Preview:** Show which objects will use priority+1 strategy
- **Clear Recommendations:** Next steps for admin based on analysis results
- **Blocking Errors:** Script will stop if any users or groups are not found in target tenant

### 6.4 WhatIf vs Execution Logs
- **WhatIf Log:** Contains analysis, predictions, and recommendations (no actual changes)
- **Execution Logs:** Contains actual API calls, success/failure results, and audit trail
- **No Overlap:** WhatIf and execution create separate, distinct log files
- **Reference Value:** WhatIf log serves as planning document for stakeholder review

---

## 7. Technical Implementation Details

### 7.1 Required Microsoft Graph API Permissions
- `NetworkAccess.ReadWrite.All` - For creating/updating GSA configurations
- `Policy.ReadWrite.ConditionalAccess` - For creating CA policies
- `User.Read.All` - For resolving user assignments
- `Group.Read.All` - For resolving group assignments

### 7.2 Graph API Integration

**All Graph API calls are abstracted through internal helper functions** that use `Invoke-InternalGraphRequest` internally for consistent error handling, automatic throttling detection, and retry logic.

**Architecture Pattern:**
- Main function (`Start-EntraInternetAccessProvisioning`) does NOT call `Invoke-InternalGraphRequest` directly
- All API interactions go through internal helper functions (e.g., `New-IntFilteringPolicy`, `Get-IntUser`, `Get-IntGroup`)
- Internal helper functions use `Invoke-InternalGraphRequest` for all Graph API calls
- This ensures consistent error handling, logging, and retry logic across all operations

**Key Features (via Invoke-InternalGraphRequest):**
- Automatic 429 throttling detection with exponential backoff
- Respects Retry-After headers
- Component-based logging via Write-LogMessage
- Automatic pagination for collection responses

**Internal Helper Functions Usage:**
```powershell
# Main function calls internal helper functions, NOT Invoke-InternalGraphRequest directly

# Create filtering policy
$result = New-IntFilteringPolicy -Name "Policy_Web_Social" -Action "allow" -Description "Social media policy"

# Resolve user
$user = Get-IntUser -Filter "userPrincipalName eq 'john@contoso.com'"

# Resolve group
$group = Get-IntGroup -Filter "displayName eq 'Finance_Group'"

# Create conditional access policy
$caPolicy = New-IntConditionalAccessPolicy -DisplayName "CA_Finance" -State "disabled" -Conditions $conditions -GrantControls $grants
```

### 7.3 Error Handling Categories
- **Validation Errors:** CSV format issues, missing dependencies
- **API Errors:** Permissions, throttling, service unavailable, object conflicts
- **Business Logic Errors:** Invalid configurations, circular references
- **Assignment Errors:** Unresolvable user/group names in CA policies

---

## 8. Internal Helper Functions

### 8.1 Authentication and Validation Functions

#### Test-RequiredModules
**Purpose:** Validate required PowerShell modules are installed  
**Module:**
- Microsoft.Graph.Authentication

#### Test-GraphConnection
**Purpose:** Validate Microsoft Graph PowerShell SDK connection and required permissions
**Location:** `internal/functions/Test-GraphConnection.ps1`
**Assumption:** User is already connected (via Connect-Entra or Connect-MgGraph)
**Validation:**
- Check that `Get-MgContext` returns a valid context
- Verify required scopes are present in the context (case-insensitive comparison)
- If connection not found or scopes missing, throw error with detailed instructions
- Do NOT handle authentication - user must connect before running script
**Scopes (conditional based on parameters):**
- Always required: `NetworkAccess.ReadWrite.All`
- Required if provisioning CA policies: `Policy.ReadWrite.ConditionalAccess`, `User.Read.All`, `Group.Read.All`
- CA policies are provisioned when: SecurityProfilesCsvPath is provided AND SkipCAPoliciesProvisioning is NOT set
**Usage Pattern:**
```powershell
# Determine required scopes based on parameters
$requiredScopes = @('NetworkAccess.ReadWrite.All')
if ($SecurityProfilesCsvPath -and -not $SkipCAPoliciesProvisioning) {
    $requiredScopes += @(
        'Policy.ReadWrite.ConditionalAccess',
        'User.Read.All',
        'Group.Read.All'
    )
}
Test-GraphConnection -RequiredScopes $requiredScopes
```

### 8.2 Configuration Management Functions

#### Import-PoliciesConfig
**Purpose:** Load and validate policies CSV (REQUIRED parameter)
**Parameters:**
- `ConfigPath` - Path to policies CSV file
- `PolicyFilter` - Optional exact policy name to filter (string, default empty)
**Validation:**
- File existence and readability
- Required columns present: `PolicyName`, `PolicyType`, `PolicyAction`, `RuleType`, `RuleDestinations`, `RuleName`, `Provision`
- Valid PolicyType values: `WebContentFiltering`, `TLSInspection` (case-insensitive)
- Valid PolicyAction values: `Allow`, `Block` (WebContentFiltering), `Inspect` (TLSInspection) - case-insensitive
- Valid RuleType values: `FQDN`, `URL`, `webCategory` (WebContentFiltering), `bypass` (TLSInspection) - case-insensitive
- **Policy Metadata Consistency Validation:**
  - Group rows by PolicyName
  - Validate all rows for same policy have identical PolicyType, PolicyAction, Description
  - Throw error if inconsistent (stops script execution)
- Add UniqueRecordId for tracking
- Create global lookup hashtable
- Ignore any additional columns not listed above
**Content:** Every row is a rule with policy metadata; policies are derived by grouping rows
**Filtering Logic (EPA Pattern):**
- Filter out rows where `Provision = no` during import
- Mark filtered rows with `ProvisioningResult = "Filtered: Provision set to 'no'"`
- If PolicyFilter provided, include only rows where `PolicyName -eq $PolicyFilter` (case-insensitive exact match)
- Mark PolicyName-filtered records with `ProvisioningResult = "Filtered: Policy name does not match filter '$PolicyFilter'"`
- Filtered rows are stored in `$Global:ProvisioningResults` but excluded from `$filteredData` returned for provisioning
**Data Parsing:**
- Split `RuleDestinations` by semicolon, trim whitespace from each value
- Convert `PolicyAction` to lowercase for API compatibility (e.g., "Block" → "block")
**Policy Grouping:**
- After filtering, group remaining rows by PolicyName to identify policies to create
- Extract policy metadata from first row of each group (validated to be consistent)

#### Import-SecurityProfilesConfig
**Purpose:** Load and validate security profiles CSV (optional)  
**Parameters:**
- `ConfigPath` - Path to security profiles CSV file (optional)
**Validation:**
- File existence and readability
- Required columns present (headers must exist): `SecurityProfileName`, `SecurityProfileLinks`, `CADisplayName`, `EntraUsers`, `EntraGroups`, `Provision`
  - Note: `CADisplayName` header is required, but values can be empty if no users/groups are specified
- Add UniqueRecordId for tracking
- Create global lookup hashtable
- Ignore any additional columns not listed above
**Content:** One row per Security Profile with combined CA policy (1:1 relationship)
**Filtering Logic (EPA Pattern):**
- Filter out rows where `Provision = no` during import
- Mark filtered rows with `ProvisioningResult = "Filtered: Provision set to 'no'"`
- Filter out rows where `SecurityProfileName` is empty
- Mark rows with `ProvisioningResult = "Failed: Missing required field SecurityProfileName"`
- Filter out rows where `SecurityProfileLinks` is empty
- Mark empty links rows with `ProvisioningResult = "Skipped: No policy links specified"`
- **Do NOT filter rows with empty `CADisplayName`** - this is validated during provisioning based on users/groups presence
- Filtered rows are stored in `$Global:ProvisioningResults` but excluded from `$filteredData` returned for provisioning
**Data Parsing:**
- Split `SecurityProfileLinks` by semicolon, trim whitespace from each value
- Parse each link as `PolicyName:Priority` format
  - Example: `"Policy1:100;Policy2:200"` → `@(@{PolicyName="Policy1"; Priority=100}, @{PolicyName="Policy2"; Priority=200})`
- Split `EntraUsers` and `EntraGroups` by semicolon, trim whitespace
- Detect empty users/groups condition for CA policy skip logic

#### Show-ProvisioningPlan
**Purpose:** Display provisioning plan summary  
**Content:**
- Object counts by type
- Detailed plan in WhatIf mode
- Policy/profile relationships

### 8.3 Resource Resolution Functions

#### Resolve-EntraUsers
**Purpose:** Find and cache Entra ID users for CA policy assignments  
**Parameters:**
- `ConfigData` - Security profiles configuration data (one row per profile with combined CA)
**Validation:**
- Parse EntraUsers column from all Security Profile rows (semicolon-separated)
- Skip rows where EntraUsers is empty
- Aggregate and deduplicate user principal names across all profiles
- Filter out placeholders (e.g., "_Replace_Me")
- Resolve each unique user via `Get-IntUser -Filter "userPrincipalName eq '{upn}'"`
**Caching:** Store in `$Global:EntraUserCache` hashtable (UserPrincipalName → UserId)
**Error Handling:**
- If user not found, log WARN and cache as `$null`
- After resolving all users, check for any `$null` values in cache
- If any users are missing, throw error with list of all missing users and stop script

#### Resolve-EntraGroups
**Purpose:** Find and cache Entra ID groups for CA policy assignments  
**Parameters:**
- `ConfigData` - Security profiles configuration data (one row per profile with combined CA)
**Validation:**
- Parse EntraGroups column from all Security Profile rows (semicolon-separated)
- Skip rows where EntraGroups is empty
- Aggregate and deduplicate group names across all profiles
- Filter out placeholders (e.g., "_Replace_Me")
- Resolve each unique group via `Get-IntGroup -Filter "displayName eq '{name}'"`
**Caching:** Store in `$Global:EntraGroupCache` hashtable (GroupName → GroupId)
**Error Handling:**
- If group not found, log WARN and cache as `$null`
- After resolving all groups, check for any `$null` values in cache
- If any groups are missing, throw error with list of all missing groups and stop script

#### Test-UserGroupDependencies
**Purpose:** Validate that all referenced users and groups exist before provisioning
**Parameters:**
- `ConfigData` - Security profiles configuration data
**Validation:**
- Check `$Global:EntraUserCache` for any `$null` values
- Check `$Global:EntraGroupCache` for any `$null` values
- If any missing users or groups found, throw error with complete list
**Error Message Format:**
```powershell
"Cannot proceed with provisioning. The following users/groups were not found in the target tenant:\n" +
"Missing Users: user1@contoso.com, user2@contoso.com\n" +
"Missing Groups: Finance_Group, Marketing_Group\n" +
"Please verify these users/groups exist in the target tenant and update the CSV accordingly."
```
**Behavior:** Stop script execution if any dependencies are missing

#### Test-ObjectDependencies
**Purpose:** Validate dependencies before provisioning  
**Checks:**
- Policy references in security profiles exist
- Security profile references in CA policies exist
- No circular dependencies

### 8.4 Provisioning Functions

#### New-WebContentFilteringPolicy
**Purpose:** Create web content filtering policies from grouped rule rows, or reuse existing policy
**Internal Function:** `New-IntFilteringPolicy` (from internal/functions/EIA)
**Parameters:**
- `Name` - Policy name from first row of policy group
- `Description` - Policy description from first row of policy group (optional)
- `Action` - Policy action from first row of policy group (converted to lowercase: "allow" or "block")
**Idempotent Behavior:**
- Check if policy exists using `Get-IntFilteringPolicy -Name`
- If exists: Reuse existing policy, return PolicyId for rule provisioning
- If not exists: Create new policy using `New-IntFilteringPolicy`
**Policy-Level Validation:** Before creating policy
```powershell
# Get first row from policy group to extract metadata
$policyMetadata = $policyGroup.Group[0]

if (-not $policyMetadata.PolicyName -or -not $policyMetadata.PolicyType -or -not $policyMetadata.PolicyAction) {
    Write-LogMessage "Skipping policy: missing required fields (PolicyName, PolicyType, or PolicyAction)" -Level ERROR -Component "PolicyProvisioning"
    # Mark all rows in this policy group as failed
    foreach ($row in $policyGroup.Group) {
        $Global:RecordLookup[$row.UniqueRecordId].ProvisioningResult = "Failed: Missing required policy metadata"
    }
    return @{ Success = $false; Action = "Failed"; Error = "Missing required fields" }
}
```
**Duplicate Detection:** Use `Get-IntFilteringPolicy -Name` to check existence before creation
- If exists: Log INFO "Policy exists, will add missing rules", return `@{Success=$true; Action="Reused"; PolicyId=$existingPolicy.Id}`
- If not exists: Create new policy, internal function returns PolicyId in response
**Progress:** Use `Write-ProgressUpdate` showing policy name
**Return:** Hashtable with Success (bool), Action (string: "Created", "Reused", "Failed"), PolicyId, Error

#### New-WebContentFilteringRules
**Purpose:** Create rules for web content filtering policies from rule rows, skipping existing rules
**Idempotent Behavior:**
- For each rule, check if rule with same `RuleName` already exists in policy
- **Rule Lookup:** Retrieve existing rules from policy using internal Get function
- If rule exists: Skip creation, mark as `"Reused: Rule already exists"`
- If rule missing: Create new rule, mark as `"Provisioned: Rule created successfully"`
**Row-Level Validation:** Before creating each rule
```powershell
if (-not $Row.PolicyName -or -not $Row.RuleType -or -not $Row.RuleDestinations -or -not $Row.RuleName) {
    Write-LogMessage "Skipping rule: missing required fields" -Level ERROR -Component "PolicyProvisioning"
    $Global:RecordLookup[$Row.UniqueRecordId].ProvisioningResult = "Failed: Missing required fields"
    # Continue with next rule
}
```
**Success Tracking:**
```powershell
# After successful rule creation
$Global:RecordLookup[$Row.UniqueRecordId].ProvisioningResult = "Provisioned: Rule created successfully"

# For existing rules
$Global:RecordLookup[$Row.UniqueRecordId].ProvisioningResult = "Reused: Rule already exists"
```
**Internal Functions:** Based on RuleType from CSV:
- `New-IntFqdnFilteringRule` - for FQDN rules
- `New-IntUrlFilteringRule` - for URL rules
- `New-IntWebCategoryFilteringRule` - for webCategory rules
**Parameters:**
- `PolicyId` - ID of the parent policy
- `Name` - Rule name from CSV
- `Destinations` - Array from RuleDestinations (split by semicolon, trimmed)
**Data Parsing:** Split `RuleDestinations` by semicolon (`;`), trim whitespace, pass as array
**Progress:** Use `Write-ProgressUpdate` showing rule name

#### New-TLSInspectionPolicy
**Purpose:** Create TLS inspection policies from grouped rule rows, or reuse existing policy
**Internal Function:** `New-IntTlsInspectionPolicy` (from internal/functions/EIA)
**Parameters:**
- `Name` - Policy name from first row of policy group
- `Description` - Policy description from first row of policy group (optional)
**Idempotent Behavior:**
- Check if policy exists using `Get-IntTlsInspectionPolicy -Name`
- If exists: Reuse existing policy, return PolicyId for rule provisioning
- If not exists: Create new policy using `New-IntTlsInspectionPolicy`
**Policy-Level Validation:** Before creating policy
```powershell
# Get first row from policy group to extract metadata
$policyMetadata = $policyGroup.Group[0]

if (-not $policyMetadata.PolicyName -or -not $policyMetadata.PolicyType) {
    Write-LogMessage "Skipping TLS policy: missing required fields (PolicyName or PolicyType)" -Level ERROR -Component "PolicyProvisioning"
    # Mark all rows in this policy group as failed
    foreach ($row in $policyGroup.Group) {
        $Global:RecordLookup[$row.UniqueRecordId].ProvisioningResult = "Failed: Missing required policy metadata"
    }
    return @{ Success = $false; Action = "Failed"; Error = "Missing required fields" }
}
```
**Note:** No Action parameter - TLS inspection policies always inspect; action is specified at rule level
**Duplicate Detection:** Use `Get-IntTlsInspectionPolicy -Name` to check existence before creation
- If exists: Log INFO "TLS policy exists, will add missing rules", return `@{Success=$true; Action="Reused"; PolicyId=$existingPolicy.Id}`
- If not exists: Create new policy, internal function returns PolicyId in response
**Progress:** Use `Write-ProgressUpdate` showing policy name
**Return:** Hashtable with Success (bool), Action (string: "Created", "Reused", "Failed"), PolicyId, Error

#### New-TLSInspectionRules
**Purpose:** Create rules for TLS inspection policies from rule rows, skipping existing rules
**Idempotent Behavior:**
- For each rule, check if rule with same `RuleName` already exists in policy
- **Rule Lookup:** Retrieve existing rules from policy using internal Get function
- If rule exists: Skip creation, mark as `"Reused: Rule already exists"`
- If rule missing: Create new rule, mark as `"Provisioned: Rule created successfully"`
**Internal Function:** `New-IntTlsInspectionRule` (from internal/functions/EIA)
**Parameters:**
- `PolicyId` - ID of the parent policy
- `Name` - Rule name from CSV row
- `Priority` - Rule priority (auto-assigned sequentially)
- `Action` - Rule action ("bypass" from RuleType column)
- `Status` - Rule status ("enabled" by default)
- `Fqdns` - Array from RuleDestinations (split by semicolon, trimmed)
**Row-Level Validation:** Before creating each rule
```powershell
if (-not $Row.PolicyName -or -not $Row.RuleType -or -not $Row.RuleDestinations -or -not $Row.RuleName) {
    Write-LogMessage "Skipping TLS rule: missing required fields" -Level ERROR -Component "PolicyProvisioning"
    $Global:RecordLookup[$Row.UniqueRecordId].ProvisioningResult = "Failed: Missing required fields"
    # Continue with next rule
}
```
**Success Tracking:**
```powershell
# After successful rule creation
$Global:RecordLookup[$Row.UniqueRecordId].ProvisioningResult = "Provisioned: Rule created successfully"

# For existing rules
$Global:RecordLookup[$Row.UniqueRecordId].ProvisioningResult = "Reused: Rule already exists"
```
**Data Parsing:** Split `RuleDestinations` by semicolon (`;`), trim whitespace, pass as array to Fqdns parameter
**Note:** TLS rules support both FQDN and webCategory destinations, but CSV currently only provides FQDN destinations
**Progress:** Use `Write-ProgressUpdate` showing rule name

#### New-SecurityProfile
**Purpose:** Create security profiles linking to policies, or reuse existing profile and add missing links
**Idempotent Behavior:**
- Check if profile exists using `Get-IntSecurityProfile -Name`
- If exists: Reuse existing profile (ignore priority differences between CSV and actual)
  - Retrieve existing policy links from profile
  - For each policy link in CSV: Check if link to same `PolicyName` already exists
  - If link exists: Skip it (ignore priority differences)
  - If link missing: Create new link with priority from CSV
- If not exists: Create new profile with all policy links
**Internal Functions:**
- `New-IntSecurityProfile` - Create the profile (from internal/functions/EIA)
- `New-IntFilteringPolicyLink` - Link policies to profile (from internal/functions/EIA)
**Business Logic Validation:** Before creating profile
```powershell
# Note: All required fields validated during import
# SecurityProfileName, CADisplayName, and SecurityProfileLinks are guaranteed to be populated

# Check if CA policy should be created (business logic decision)
$skipCA = [string]::IsNullOrWhiteSpace($Row.EntraUsers) -and [string]::IsNullOrWhiteSpace($Row.EntraGroups)
if ($skipCA) {
    Write-LogMessage "CA policy will be skipped: no users or groups specified" -Level INFO -Component "SecurityProfileProvisioning"
}
```
**Duplicate Detection:** Use `Get-IntSecurityProfile -Name` to check existence before creation
- If exists: Log INFO "Security Profile exists, will add missing policy links", return `@{Success=$true; Action="Reused"; ProfileId=$existingProfile.Id}`
- If not exists: Create new profile using `New-IntSecurityProfile`, internal function returns ProfileId in response
**Priority Conflict Handling (New Profile Creation Only):**
- **Only applies when creating NEW security profile** (not when reusing existing)
- If creation fails due to priority conflict, increment priority by 1 and retry once
- If second attempt also fails, log WARN and skip profile
- Mark with `ProvisioningResult = "Failed: Priority conflict - priority {priority} and {priority+1} already exist"`
**Progress:** Use `Write-ProgressUpdate` showing profile name
**Policy Linking:**
- Parse `SecurityProfileLinks` field (e.g., `"Policy1:100;Policy2:200"`)
- For reused profiles: Check existing links, add only missing PolicyName links
- For new profiles: Add all policy links from CSV
- Use `New-IntFilteringPolicyLink` to link each policy to profile
- Parameters: ProfileId, PolicyId, Priority, State ("enabled"/"disabled")
- **Do NOT pass Action parameter** when creating policy links (uses policy's default action)
- Validate referenced policy names exist (via Test-ObjectDependencies)
**CA Policy Creation Logic:**
- If `-SkipCAPoliciesProvisioning` parameter is set: Skip all CA policy creation, log INFO message
- Otherwise, check if `EntraUsers` and `EntraGroups` are both empty
- If both empty: Skip CA policy creation, log INFO message
- If at least one populated: Create CA policy with assignments (see New-ConditionalAccessPolicy for reuse behavior)
**Return:** Hashtable with Success (bool), Action (string: "Created", "Reused", "Failed"), ProfileId, CASkipped (bool), CASkipReason (string: "Parameter" or "NoAssignments"), NewLinksAdded (int), ExistingLinksSkipped (int), Error

#### New-ConditionalAccessPolicy
**Purpose:** Create CA policies in DISABLED state, or skip if already exists (optional based on user/group assignments)
**Idempotent Behavior:**
- Check if CA policy with same name already exists using `Get-IntConditionalAccessPolicy -Filter`
- If exists: Skip creation, mark as `"Reused: CA policy already exists"`
  - Do NOT modify existing CA policy (sensitive security control)
  - Do NOT update user/group assignments
- If not exists: Create new CA policy in DISABLED state using `New-IntConditionalAccessPolicy`
**Internal Functions:** 
- `Get-IntConditionalAccessPolicy` - Check if CA policy exists (to be created, see section 8.7)
- `New-IntConditionalAccessPolicy` - Create new CA policy (to be created, see section 8.7)
**Row-Level Validation:** Before creating CA policy
```powershell
# Check if CA policy should be created (requires users or groups)
if ([string]::IsNullOrWhiteSpace($Row.EntraUsers) -and [string]::IsNullOrWhiteSpace($Row.EntraGroups)) {
    Write-LogMessage "Skipping CA policy creation: no users or groups specified" -Level INFO -Component "ConditionalAccessProvisioning"
    return @{ Success = $true; Action = "Skipped"; Reason = "No user/group assignments" }
}

if (-not $Row.CADisplayName) {
    Write-LogMessage "Skipping CA policy: missing CADisplayName" -Level ERROR -Component "ConditionalAccessProvisioning"
    return @{ Success = $false; Action = "Failed"; Error = "Missing CADisplayName" }
}
```
**Duplicate Detection:** Check by display name using `Get-IntConditionalAccessPolicy -Filter "displayName eq '{name}'"`, return @{Success=$true; Action="Reused"} if exists
- Log INFO "CA policy already exists, skipping creation (existing policies not modified)"
**Progress:** Use `Write-ProgressUpdate` showing CA policy name
**Security Profile Reference:** Link CA policy to the Security Profile ID via sessionControls in policy body (only for new CA policies)
**Return:** Hashtable with Success (bool), Action (string: "Created", "Reused", "Skipped", "Failed"), PolicyId, Reason (string, if skipped), Error

#### Set-ConditionalAccessAssignments
**Purpose:** Assign users/groups to CA policies  
**Error Handling:** Continue on missing users/groups, log warnings

### 8.7 Conditional Access Internal Functions (To Be Created)

#### Get-IntUser
**Purpose:** Retrieve user from Microsoft Entra ID with optional filtering
**Location:** `internal/functions/Get-IntUser.ps1` (to be created)
**Pattern:** Follow `Get-IntGroup.ps1` implementation pattern
**Microsoft Graph API Reference:** https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-beta&tabs=http
**Parameters:**
- `Filter` - OData filter expression (optional)
  - Example: `"userPrincipalName eq 'john@contoso.com'"`
**Implementation:**
- Use `[CmdletBinding()]`
- Use `Invoke-InternalGraphRequest` for all API calls
- Endpoint: `GET /beta/users` with optional `?$filter=` query
- Support advanced query patterns (requires ConsistencyLevel header)
- Return user object(s) or `$null` if not found
**Return:** User object(s) from Graph API, or `$null`

#### Get-IntConditionalAccessPolicy
**Purpose:** Retrieve Conditional Access policy from Entra ID with optional filtering
**Location:** `internal/functions/CA/Get-IntConditionalAccessPolicy.ps1` (to be created)
**Pattern:** Follow `Get-IntGroup.ps1` implementation pattern
**Microsoft Graph API Reference:** https://learn.microsoft.com/en-us/graph/api/conditionalaccesspolicy-get?view=graph-rest-beta&tabs=http
**Parameters:**
- `Filter` - OData filter expression (optional)
  - Example: `"displayName eq 'CA_Finance_Access'"`
**Implementation:**
- Use `[CmdletBinding()]`
- Use `Invoke-InternalGraphRequest` for all API calls
- Endpoint: `GET /beta/identity/conditionalAccess/policies` with optional `?$filter=` query
- Support advanced query patterns (requires ConsistencyLevel header)
- Return CA policy object(s) or `$null` if not found
**Return:** Conditional Access policy object(s) from Graph API, or `$null`

#### New-IntConditionalAccessPolicy
**Purpose:** Create new Conditional Access policy in Entra ID
**Location:** `internal/functions/CA/New-IntConditionalAccessPolicy.ps1` (to be created)
**Pattern:** Follow EIA internal function patterns (e.g., `New-IntFilteringPolicy`)
**Microsoft Graph API Reference:** https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-post-policies?view=graph-rest-beta&tabs=http
**Parameters:**
- `DisplayName` - CA policy display name (required)
- `State` - Policy state: "enabled", "disabled", "enabledForReportingButNotEnforced" (required)
- `Conditions` - Conditions object (users, applications, locations, etc.) (required)
- `GrantControls` - Grant controls object (block/allow, MFA requirements, etc.) (optional)
- `SessionControls` - Session controls object (includes secureWebSessionControlType for Global Secure Access) (optional)
**Implementation:**
- Use `[CmdletBinding()]`
- Use `Invoke-InternalGraphRequest` for all API calls
- Endpoint: `POST /beta/identity/conditionalAccess/policies`
- Build request body from parameters following Graph API schema
- Return created policy object with PolicyId
- No retry logic for object retrieval (API returns created object immediately)
**Return:** Hashtable with Success (bool), Data (policy object with id property), Error (string if failed)

### 8.5 Results and Reporting Functions

#### Export-ProvisioningResults
**Pattern:** Same as Start-EntraPrivateAccessProvisioning implementation  
**Purpose:** Export results CSV with ProvisioningResult column and updated Provision field
**Filename:** `${timestamp}_${baseName}_provisioned.csv`
**Provision Field Update Logic:**
- Set `Provision=no` if provisioning was successful or object was reused:
  - ProvisioningResult starts with `"Provisioned: "`
  - ProvisioningResult starts with `"Reused: "`
- Keep original `Provision` value for all other cases:
  - Failed to provision (`"Failed: ..."`)
  - Filtered by parameter (`"Filtered: Policy name does not match filter"`)
  - Originally marked as no (`"Filtered: Provision set to 'no'"`)
  - Skipped due to validation (`"Skipped: ..."`)
  - Any other validation or structural issues
**Rationale:** Output CSV can be used as input for re-run; successfully provisioned items (Provision=no) will be skipped, while failed items (Provision=yes) will be retried

#### Show-ExecutionSummary
**Pattern:** Same as Start-EntraPrivateAccessProvisioning implementation  
**Purpose:** Display comprehensive execution summary  
**Content:**
- Execution duration
- Object counts by type (created/skipped/failed)
- Warnings and recommendations

### 8.6 Main Orchestration Function

#### Invoke-ProvisioningProcess
**Purpose:** Main orchestration function  
**Flow:**
1. Test-RequiredModules
2. Test-GraphConnection (with conditional scopes based on parameters)
3. Validate parameter mutual exclusivity (PolicyName vs SecurityProfilesCsvPath)
4. Log prominent message if `-SkipCAPoliciesProvisioning` is enabled
5. Import-PoliciesConfig (required parameter, with optional PolicyName filter)
6. Import-SecurityProfilesConfig (if provided and PolicyName not specified)
7. Show-ProvisioningPlan
8. Resolve-EntraUsers (parse and cache all users from Security Profiles CSV) - **SKIP if `-SkipCAPoliciesProvisioning` is set**
9. Resolve-EntraGroups (parse and cache all groups from Security Profiles CSV) - **SKIP if `-SkipCAPoliciesProvisioning` is set**
10. Test-UserGroupDependencies (validate all users/groups exist, stop if any missing) - **SKIP if `-SkipCAPoliciesProvisioning` is set**
11. User confirmation (unless -Force or -WhatIf)
12. Test-ObjectDependencies (validate policy references)
13. Provision objects in dependency order (CA policies skipped if `-SkipCAPoliciesProvisioning` is set)
14. Export-ProvisioningResults
15. Show-ExecutionSummary

---

## 9. Usage Examples

### 8.1 Full Provisioning with Preview
```powershell
# Preview what would be created
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv" `
    -WhatIf

# Full provisioning
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv" `
    -Force

# Provisioning policies only (omit Security Profiles CSV)
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv"

# Provision policies and Security Profiles WITHOUT CA policies
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv" `
    -SkipCAPoliciesProvisioning `
    -Force
```

### 8.2 Policy Name Filtering
```powershell
# Provision only a specific policy by exact name (for testing/incremental updates)
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -PolicyName "Dev_Tools-Allow"

# ERROR: Cannot use PolicyName filter with SecurityProfilesCsvPath
# This will throw an error:
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv" `
    -PolicyName "Dev_Tools-Allow"  # ❌ Not allowed
```

### 8.3 Selective Provisioning via Provision Field and Parameters
```powershell
# Control what to provision by setting Provision = "no" in CSV
# Example: Set Provision = "no" for all Security Profiles and CA policies in security_profiles.csv
# Then run full provisioning - only policies will be created
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv"

# Provision only specific policies by setting Provision = "no" for unwanted policies
# in policies.csv, then run:
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv"

# Skip CA policy creation using parameter (cleaner than editing CSV)
# Creates all policies and Security Profiles, but NO CA policies
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv" `
    -SkipCAPoliciesProvisioning

# Preview mode with CA policies skipped
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv" `
    -SkipCAPoliciesProvisioning `
    -WhatIf
```

### 8.4 Idempotent Re-Run Examples
```powershell
# Re-run provisioning - script automatically reuses existing objects and adds missing items
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv"

# Output CSV will show:
# - ProvisioningResult = "Provisioned: Rule created successfully" for new objects
# - ProvisioningResult = "Reused: Policy exists - added 3 new rules, 5 rules already existed" for existing policies
# - ProvisioningResult = "Reused: Profile exists - added 1 new policy link, 2 links already existed" for existing profiles
# - ProvisioningResult = "Reused: Rule already exists" for duplicate rules (skipped)
# - ProvisioningResult = "Reused: CA policy already exists" for existing CA policies (not modified)
# - ProvisioningResult = "Failed: Priority conflict - priority {X} and {X+1} already exist" for priority conflicts (new profiles only)

# Force mode - skip confirmation prompts (re-run behavior still applies)
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv" `
    -Force

# Recovery from partial failure - re-run to complete provisioning
# Example: First run failed after creating 2 policies with 5 rules each
# Re-run will:
# - Reuse 2 existing policies (skip rule creation for 10 existing rules)
# - Create remaining policies and all their rules
# - Create all security profiles and CA policies
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath ".\policies.csv" `
    -SecurityProfilesCsvPath ".\security_profiles.csv"
```

---

## 10. Success Criteria

### 9.1 Functional Requirements Met
- ✅ Selective provisioning by object type
- ✅ Idempotent re-run behavior (reuse existing objects, add missing items)
- ✅ Conflict detection and resolution
- ✅ Dependency order enforcement  
- ✅ Comprehensive error handling and logging
- ✅ Preview mode for safe planning
- ✅ Missing assignment graceful handling
- ✅ Recovery from partial failures

### 9.2 Quality Requirements
- ✅ Comprehensive logging for audit and troubleshooting
- ✅ Clear summary reporting for admin visibility
- ✅ Safe defaults (CA policies disabled, conflicts logged)
- ✅ Partial failure recovery (continue where possible)
- ✅ Dedicated WhatIf analysis for safe planning and stakeholder review

---

*Specification Complete - Ready for Implementation*