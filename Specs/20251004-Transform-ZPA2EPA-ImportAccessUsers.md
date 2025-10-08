# ZPA Access Policy SCIM Username Import - Technical Specification

## Overview
Extend the existing ZPA Access Policy integration in Transform-ZPA2EPA.ps1 to also capture individual SCIM usernames from access policies. This enhancement will add a new `EntraUsers` column to the output CSV alongside the existing `EntraGroups` column.

---

## Purpose & Goals

### Primary Goal
Enhance the existing **APP-centric lookup structure** to capture both:
- **SCIM Groups** (existing functionality from spec 20251001)
- **SCIM Usernames** (new functionality - individual user assignments)

### Use Case
The enhanced functionality will:
1. Process SCIM username operands from access policies (in addition to SCIM_GROUP operands)
2. Build lookup structure mapping APP IDs to both SCIM groups AND individual usernames
3. Populate two separate CSV columns:
   - `EntraGroups` - Semicolon-separated SCIM group names (existing)
   - `EntraUsers` - Semicolon-separated SCIM usernames (NEW)
4. Leave `EntraUsers` column empty when no individual users are assigned

### Why Separate Columns?
- Clear distinction between **group-based access** and **individual user access**
- Enables different migration strategies for groups vs. individual users
- Maintains clarity when policies grant access to both groups and specific users
- Simplifies post-processing and validation

---

## Changes from Previous Implementation (20251001)

This spec **extends** the existing group-based implementation with the following changes:

### Modified Components
1. **Function Rename**: `Build-AppToScimGroupLookup` → `Build-AppToScimAccessLookup`
2. **Return Structure**: Enhanced to include both Groups and Users arrays
3. **Policy Processing**: Extended to extract SCIM username operands alongside SCIM_GROUP operands
4. **CSV Output**: Added new `EntraUsers` column
5. **Statistics**: Enhanced to show both group and user assignment metrics

### Unchanged Components
- Policy filtering criteria (same as spec 20251001)
- Error handling patterns
- File loading and validation logic
- APP_GROUP expansion logic
- Main integration points in script flow

---

## Input Data Structure

### SCIM Username Operands in Access Policies

Access policies can contain **SCIM username conditions** with `objectType` == `"SCIM"` and `name` == `"userName"`.

**Sample Policy Structure:**
```json
{
  "id": "217246660303025580",
  "name": "App Access - Individual Users",
  "policyType": "1",
  "operator": "AND",
  "action": "ALLOW",
  "conditions": [
    {
      "id": "635820",
      "operator": "OR",
      "negated": false,
      "operands": [
        {
          "objectType": "APP",
          "lhs": "id",
          "rhs": "217246660303025577",
          "name": "TEST-APP"
        }
      ]
    },
    {
      "id": "36922417",
      "operator": "OR",
      "negated": false,
      "operands": [
        {
          "id": "36922418",
          "objectType": "SCIM",
          "lhs": "216197681112940649",
          "rhs": "user1@contoso.com",
          "name": "userName",
          "idpId": "216197681112940647",
          "idpName": "IDP1"
        },
        {
          "id": "36922419",
          "objectType": "SCIM",
          "lhs": "216197681112940649",
          "rhs": "user2@contoso.com",
          "name": "userName",
          "idpId": "216197681112940647",
          "idpName": "IDP1"
        },
        {
          "id": "36922420",
          "objectType": "SCIM",
          "lhs": "216197681112940649",
          "rhs": "user3@contoso.com",
          "name": "userName",
          "idpId": "216197681112940647",
          "idpName": "IDP1"
        }
      ]
    }
  ]
}
```

**Key Characteristics:**
- `objectType`: `"SCIM"` (different from `"SCIM_GROUP"`)
- `name`: `"userName"` (identifies this as a username condition)
- `rhs`: Contains the actual username (typically email format)
- `lhs`: IdP-specific identifier (not needed for username extraction)
- `idpId` and `idpName`: Identity provider references

### Mixed Policy Example (Groups + Users)

Policies can grant access to **both groups and individual users** in the same policy:

```json
{
  "id": "217246660303025581",
  "name": "App Access - Mixed",
  "policyType": "1",
  "operator": "AND",
  "action": "ALLOW",
  "conditions": [
    {
      "id": "635821",
      "operator": "OR",
      "operands": [
        {
          "objectType": "APP",
          "lhs": "id",
          "rhs": "217246660303025578"
        }
      ]
    },
    {
      "id": "635822",
      "operator": "OR",
      "operands": [
        {
          "objectType": "SCIM_GROUP",
          "lhs": "216197681112940647",
          "rhs": "843089",
          "idpId": "216197681112940647"
        },
        {
          "objectType": "SCIM",
          "lhs": "216197681112940649",
          "rhs": "admin1@contoso.com",
          "name": "userName",
          "idpId": "216197681112940647"
        },
        {
          "objectType": "SCIM",
          "lhs": "216197681112940649",
          "rhs": "admin2@contoso.com",
          "name": "userName",
          "idpId": "216197681112940647"
        }
      ]
    }
  ]
}
```

In this case:
- `EntraGroups` = Resolved name of SCIM_GROUP 843089 (e.g., "Engineering-Users")
- `EntraUsers` = "admin1@contoso.com; admin2@contoso.com"

---

## Processing Logic Changes

### Enhanced Function: Build-AppToScimAccessLookup (RENAMED)

**Previous Name**: `Build-AppToScimGroupLookup`  
**New Name**: `Build-AppToScimAccessLookup`

#### Modified Return Structure

**Previous (Spec 20251001):**
```powershell
@{
    "app_id_1" = @("Group1", "Group2")
    "app_id_2" = @("Group3")
}
```

**New (This Spec):**
```powershell
@{
    "app_id_1" = @{
        Groups = @("Group1", "Group2")
        Users = @("user1@contoso.com", "user2@contoso.com")
    }
    "app_id_2" = @{
        Groups = @("Group3")
        Users = @()
    }
    "app_id_3" = @{
        Groups = @()
        Users = @("admin@contoso.com")
    }
}
```

#### Enhanced Policy Processing Steps

**Modified Step 5c: Extract SCIM Groups AND Usernames**

The existing Step 5c (Extract SCIM Groups) will be enhanced to also capture usernames:

**NEW Logic:**
```
For each policy condition:
    For each operand in condition.operands:
        
        # EXISTING: SCIM_GROUP extraction
        If operand.objectType == "SCIM_GROUP":
            - Extract SCIM_GROUP ID from operand.rhs
            - Look up group name in SCIM groups lookup
            - Add to Groups collection for this APP
            - Error Handling: If SCIM_GROUP not found, log warning and skip
        
        # NEW: SCIM username extraction
        If operand.objectType == "SCIM" AND operand.name == "userName":
            - Extract username from operand.rhs
            - Validate username format (non-empty string)
            - Add to Users collection for this APP
            - Error Handling: If username empty/null, log warning and skip
```

**Key Points:**
- Both SCIM_GROUP and SCIM username operands can exist in the same condition
- Both are processed in a single iteration through conditions
- No dependency between group and user extraction
- Each collection is maintained separately

#### Enhanced Step 6: Deduplication & Aggregation

**Modified Logic:**

For each APP ID across all processed policies:

**Groups (EXISTING):**
1. Collect all SCIM group names
2. Deduplicate by SCIM group ID
3. Sort alphabetically
4. Store final array

**Users (NEW):**
1. Collect all SCIM usernames
2. **Deduplicate case-insensitive** (e.g., "User@Domain.com" and "user@domain.com" → keep one)
3. **Preserve original casing** of first occurrence
4. Sort alphabetically (case-insensitive sort)
5. Store final array

**Example:**
```powershell
# Input from multiple policies:
Policy1: user1@contoso.com, User2@Contoso.com
Policy2: USER1@CONTOSO.COM, user3@contoso.com

# After deduplication (case-insensitive):
@("user1@contoso.com", "User2@Contoso.com", "user3@contoso.com")
# First occurrence casing is preserved
```

---

## Main Processing Loop Integration

### Enhanced EntraGroups and EntraUsers Assignment

**Current Logic (from Spec 20251001):**
```powershell
# Determine EntraGroups value
$entraGroupsValue = "Placeholder_Replace_Me"

if ($null -ne $appToScimGroupLookup) {
    $appId = $segment.id
    if ($appToScimGroupLookup.ContainsKey($appId)) {
        $groupNames = $appToScimGroupLookup[$appId]
        if ($groupNames -and $groupNames.Count -gt 0) {
            $entraGroupsValue = ($groupNames -join "; ")
        } else {
            $entraGroupsValue = "No_Access_Policy_Found_Replace_Me"
        }
    } else {
        $entraGroupsValue = "No_Access_Policy_Found_Replace_Me"
    }
}

EntraGroups = $entraGroupsValue
```

**Enhanced Logic (This Spec):**
```powershell
# Determine EntraGroups and EntraUsers values
$entraGroupsValue = "Placeholder_Replace_Me"
$entraUsersValue = ""  # Empty by default

if ($null -ne $appToScimAccessLookup) {
    $appId = $segment.id
    
    if ($appToScimAccessLookup.ContainsKey($appId)) {
        $accessInfo = $appToScimAccessLookup[$appId]
        
        # Process Groups
        if ($accessInfo.Groups -and $accessInfo.Groups.Count -gt 0) {
            $entraGroupsValue = ($accessInfo.Groups -join "; ")
        } else {
            $entraGroupsValue = "No_Access_Policy_Found_Replace_Me"
        }
        
        # Process Users (NEW)
        if ($accessInfo.Users -and $accessInfo.Users.Count -gt 0) {
            $entraUsersValue = ($accessInfo.Users -join "; ")
        }
        # else: Leave empty (no individual users assigned)
        
    } else {
        # APP not found in any access policy
        $entraGroupsValue = "No_Access_Policy_Found_Replace_Me"
        # EntraUsers remains empty
    }
}

# Use in PSCustomObject
EntraGroups = $entraGroupsValue
EntraUsers = $entraUsersValue  # NEW COLUMN
```

**Behavior Summary:**

| Scenario | EntraGroups Value | EntraUsers Value |
|----------|------------------|------------------|
| No policy files provided | `Placeholder_Replace_Me` | `` (empty) |
| Policy files provided, APP has groups only | Group names (semicolon-separated) | `` (empty) |
| Policy files provided, APP has users only | `No_Access_Policy_Found_Replace_Me` | User emails (semicolon-separated) |
| Policy files provided, APP has both | Group names | User emails |
| Policy files provided, APP has neither | `No_Access_Policy_Found_Replace_Me` | `` (empty) |

---

## Output Specification

### CSV Column Structure

The output CSV will now have **both** columns:

```csv
AppName,FQDN,EntraGroups,EntraUsers,Protocol,FromPort,ToPort
App1,app1.contoso.com,Engineering-Users; QA-Team,user1@contoso.com; user2@contoso.com,TCP,443,443
App2,app2.contoso.com,Finance-Users,,TCP,443,443
App3,app3.contoso.com,No_Access_Policy_Found_Replace_Me,admin@contoso.com,TCP,443,443
App4,app4.contoso.com,Placeholder_Replace_Me,,TCP,443,443
```

### Example Scenarios

#### Scenario 1: No Policy Files Provided (Backward Compatibility)
```csv
EntraGroups,EntraUsers
Placeholder_Replace_Me,
Placeholder_Replace_Me,
```

#### Scenario 2: Groups Only
```csv
EntraGroups,EntraUsers
Engineering-Users; QA-Team,
Finance-Users,
```

#### Scenario 3: Users Only
```csv
EntraGroups,EntraUsers
No_Access_Policy_Found_Replace_Me,user1@contoso.com; user2@contoso.com
No_Access_Policy_Found_Replace_Me,admin@contoso.com
```

#### Scenario 4: Mixed (Groups + Users)
```csv
EntraGroups,EntraUsers
Engineering-Users; QA-Team,admin1@contoso.com; admin2@contoso.com
Finance-Users,cfo@contoso.com
DevOps-Team,
```

#### Scenario 5: Neither Groups nor Users
```csv
EntraGroups,EntraUsers
No_Access_Policy_Found_Replace_Me,
```

---

## Console Logging Output

### Enhanced Loading and Processing Logs

**Modified Output (additions highlighted with [NEW]):**

```
=== LOADING ACCESS POLICY DATA ===
Loading SCIM groups from: c:\path\to\scim_groups.json
Loaded 127 SCIM groups

Loading access policies from: c:\path\to\access_policies.json
Loaded 45 access policies

=== PROCESSING ACCESS POLICIES ===
Processing 45 access policies...
  Valid policies: 32
  Skipped policies: 13
    - No SCIM_GROUP/SCIM username conditions: 5
    - No APP/APP_GROUP targets: 4
    - Negated conditions: 3
    - Complex OR logic at root: 1

Expanding APP_GROUP targets using segment group membership...
  Total APP targets (direct): 89
  Total APP_GROUP targets: 12
  APP_GROUPs expanded to: 47 APPs
  Total unique APPs with access policies: 112

Building APP to SCIM access lookup...
  APPs with access policies: 112
  [NEW] APPs with group-based access: 98
  [NEW] APPs with user-based access: 47
  [NEW] APPs with both groups and users: 33
  [NEW] Total unique usernames found: 156
  Warnings:
    - SCIM Groups not found: 3 (IDs logged below)
    - APP_GROUPs not found in segment groups: 1
    [NEW] - Invalid/empty usernames skipped: 2

Access policy lookup built successfully
```

### Enhanced Summary Section

**Modified Final Summary (additions highlighted with [NEW]):**

```
=== TRANSFORMATION SUMMARY ===
Total segments loaded: 150
Segments processed: 150
Total result records: 450
Grouped result records: 320
Conflicts detected: 5

Access Policy Integration:
  Access policy files: Provided
  APPs with assigned groups: 98 (65.3%)
  [NEW] APPs with assigned users: 47 (31.3%)
  [NEW] APPs with both groups and users: 33 (22.0%)
  APPs without any access policies: 38 (25.3%)
  APPs using placeholder: 0 (0.0%)
  [NEW] Total unique users across all policies: 156

Output file: c:\output\20251004_123456_GSA_EnterpriseApps_All.csv
```

**If access policy files NOT provided:**

```
Access Policy Integration:
  Access policy files: Not provided
  All APPs using placeholder: 150 (100.0%)
  [NEW] No user assignments: 150 (100.0%)
```

---

## Function Design Changes

### Renamed Main Function
```powershell
function Build-AppToScimAccessLookup {
    <#
    .SYNOPSIS
        Builds a lookup table mapping APP IDs to SCIM groups and usernames with access.
    
    .DESCRIPTION
        Processes ZPA Access Policies to extract both SCIM_GROUP and SCIM username 
        assignments. Returns a hashtable mapping APP IDs to access information including
        both group names and individual usernames.
    
    .PARAMETER AccessPolicyPath
        Path to ZPA Access Policies JSON file.
    
    .PARAMETER ScimGroupPath
        Path to SCIM Groups JSON file.
    
    .PARAMETER SegmentGroupMembership
        Hashtable containing APP_GROUP to APP IDs mapping (from Load-ApplicationSegments).
    
    .PARAMETER EnableDebugLogging
        Enable verbose debug logging.
    
    .OUTPUTS
        Hashtable with APP IDs as keys and hashtables containing Groups and Users arrays as values.
        Returns $null if files not found or prerequisites not met.
        
        Structure:
        @{
            "app_id" = @{
                Groups = @("Group1", "Group2")
                Users = @("user1@domain.com", "user2@domain.com")
            }
        }
    
    .EXAMPLE
        $lookup = Build-AppToScimAccessLookup `
            -AccessPolicyPath "c:\path\to\access_policies.json" `
            -ScimGroupPath "c:\path\to\scim_groups.json" `
            -SegmentGroupMembership $loadResult.SegmentGroupMembership `
            -EnableDebugLogging:$EnableDebugLogging
        
        # Access groups and users for an app
        $appAccess = $lookup["217246660303025577"]
        $groups = $appAccess.Groups
        $users = $appAccess.Users
    #>
}
```

### Modified Helper Function: Get-ScimGroupsFromPolicy

**Previous Version (Spec 20251001):**
```powershell
function Get-ScimGroupsFromPolicy {
    # Extracts SCIM_GROUP operands
    # Returns array of SCIM_GROUP IDs
}
```

**Enhanced Version (This Spec):**
```powershell
function Get-ScimAccessFromPolicy {
    <#
    .SYNOPSIS
        Extracts SCIM_GROUP and SCIM username operands from a policy.
    
    .DESCRIPTION
        Processes policy conditions to extract both:
        - SCIM_GROUP operands (objectType == "SCIM_GROUP")
        - SCIM username operands (objectType == "SCIM" AND name == "userName")
    
    .PARAMETER Policy
        The access policy object to process.
    
    .OUTPUTS
        Hashtable with two arrays:
        @{
            ScimGroupIds = @("843089", "843090")
            Usernames = @("user1@contoso.com", "user2@contoso.com")
        }
    #>
    
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Policy
    )
    
    $scimGroupIds = @()
    $usernames = @()
    
    foreach ($condition in $Policy.conditions) {
        if ($condition.operands) {
            foreach ($operand in $condition.operands) {
                # EXISTING: Extract SCIM_GROUP
                if ($operand.objectType -eq "SCIM_GROUP") {
                    if ($operand.rhs) {
                        $scimGroupIds += $operand.rhs
                    }
                }
                
                # NEW: Extract SCIM username
                if ($operand.objectType -eq "SCIM" -and $operand.name -eq "userName") {
                    if (![string]::IsNullOrWhiteSpace($operand.rhs)) {
                        $usernames += $operand.rhs.Trim()
                    } else {
                        Write-LogMessage -Level Warning -Message "Found SCIM username operand with empty/null username in policy $($Policy.id)"
                    }
                }
            }
        }
    }
    
    return @{
        ScimGroupIds = $scimGroupIds
        Usernames = $usernames
    }
}
```

### No Changes Required
These functions remain unchanged from Spec 20251001:
- `Load-AccessPolicies`
- `Load-ScimGroups`
- `Test-ValidAccessPolicy`
- `Get-AppTargetsFromPolicy`
- `Expand-AppGroupToApps`

---

## Error Handling & Logging

### No Changes to Critical Errors
All critical error conditions from Spec 20251001 remain the same.

### Enhanced Warnings (New)

**Additional Warning Conditions:**
- **Empty/null username in SCIM operand** → Log warning with policy ID, skip that username
- **Username not in email format** → No validation required (assumption: all usernames are emails, but accept any non-empty string)

**Log Message Examples:**
```
WARNING: Found SCIM username operand with empty/null username in policy 217246660303025580
WARNING: Policy 217246660303025581 has no SCIM_GROUP or SCIM username conditions, skipping
```

### Enhanced Information Logging

**Additional Statistics (INFO level):**
- Total unique usernames found across all policies
- Count of APPs with user-based access
- Count of APPs with both groups and users
- Count of invalid/empty usernames skipped

---

## Implementation Plan

### Phase 1: Rename and Enhance Return Structure
1. ✅ Rename `Build-AppToScimGroupLookup` → `Build-AppToScimAccessLookup`
2. ✅ Modify return structure to include both Groups and Users arrays
3. ✅ Update all references in main script flow
4. ✅ Test backward compatibility with existing group functionality

### Phase 2: Enhance Policy Processing
1. ✅ Rename `Get-ScimGroupsFromPolicy` → `Get-ScimAccessFromPolicy`
2. ✅ Add username extraction logic to the function
3. ✅ Update function to return hashtable with both ScimGroupIds and Usernames
4. ✅ Add validation for empty/null usernames
5. ✅ Update policy filtering to accept policies with SCIM usernames (in addition to SCIM_GROUP)

### Phase 3: Implement Deduplication
1. ✅ Add case-insensitive deduplication for usernames
2. ✅ Implement casing preservation (first occurrence)
3. ✅ Add case-insensitive sorting
4. ✅ Test with various casing scenarios

### Phase 4: Update Main Processing Loop
1. ✅ Modify lookup variable name: `$appToScimGroupLookup` → `$appToScimAccessLookup`
2. ✅ Update EntraGroups assignment logic to use `$accessInfo.Groups`
3. ✅ Add EntraUsers assignment logic using `$accessInfo.Users`
4. ✅ Add EntraUsers to PSCustomObject output
5. ✅ Test all scenarios (no files, groups only, users only, both, neither)

### Phase 5: Enhance Logging and Statistics
1. ✅ Add user-related statistics to policy processing logs
2. ✅ Update final summary to include user assignment metrics
3. ✅ Add warning logs for invalid usernames
4. ✅ Test logging output with various data scenarios

### Phase 6: Testing & Validation
1. ✅ Test with no access policy files (backward compatibility)
2. ✅ Test with groups only (existing functionality preserved)
3. ✅ Test with users only (new functionality)
4. ✅ Test with both groups and users
5. ✅ Test with neither groups nor users
6. ✅ Test case-insensitive deduplication
7. ✅ Test with large datasets (performance)
8. ✅ Validate CSV output format and column order

---

## Success Criteria

### Backward Compatibility (From Spec 20251001)
1. ✅ All existing group-based functionality works unchanged
2. ✅ EntraGroups column behavior remains identical when no SCIM usernames present
3. ✅ Script runs successfully without any user-based policies
4. ✅ Existing error handling and logging preserved

### New Functionality
5. ✅ Script extracts SCIM usernames from access policies
6. ✅ Correctly identifies SCIM operands with `objectType` == "SCIM" and `name` == "userName"
7. ✅ Populates new EntraUsers column with semicolon-separated usernames
8. ✅ Leaves EntraUsers empty when no individual users assigned
9. ✅ Handles mixed policies (both groups and users) correctly
10. ✅ Case-insensitive deduplication works correctly
11. ✅ Original casing preserved for first occurrence
12. ✅ Usernames sorted alphabetically (case-insensitive)

### Enhanced Integration
13. ✅ Function renamed from `Build-AppToScimGroupLookup` to `Build-AppToScimAccessLookup`
14. ✅ Return structure includes both Groups and Users arrays
15. ✅ Single pass through policies extracts both groups and users
16. ✅ Main processing loop cleanly handles new structure
17. ✅ CSV output includes EntraUsers column in correct position
18. ✅ Final summary includes user assignment statistics
19. ✅ Code follows existing Transform-ZPA2EPA.ps1 patterns
20. ✅ Performance remains acceptable with large datasets

---

## Migration Notes

### For Users Upgrading from Spec 20251001 Implementation

**Breaking Changes:**
- Variable name changed: `$appToScimGroupLookup` → `$appToScimAccessLookup`
- Lookup structure changed from array to hashtable with Groups/Users properties
- Function renamed: `Build-AppToScimGroupLookup` → `Build-AppToScimAccessLookup`

**Access Pattern Changes:**

**Before (Spec 20251001):**
```powershell
$groups = $appToScimGroupLookup[$appId]
if ($groups -and $groups.Count -gt 0) {
    $entraGroupsValue = ($groups -join "; ")
}
```

**After (This Spec):**
```powershell
$accessInfo = $appToScimAccessLookup[$appId]
if ($accessInfo.Groups -and $accessInfo.Groups.Count -gt 0) {
    $entraGroupsValue = ($accessInfo.Groups -join "; ")
}
if ($accessInfo.Users -and $accessInfo.Users.Count -gt 0) {
    $entraUsersValue = ($accessInfo.Users -join "; ")
}
```

**CSV Output Changes:**
- New column `EntraUsers` added after `EntraGroups`
- All existing columns remain in same order

---

## File Naming & Location

### Input Files (No Changes)
All files remain the same as Spec 20251001:
- `application_segments.json`
- `segment_groups.json`
- `access_policies.json` - **Contains SCIM username operands (enhanced usage)**
- `scim_groups.json`

### Output
- Enhanced CSV file with **two** access columns: `EntraGroups` and `EntraUsers`
- Console logging with enhanced statistics
- Existing log file with additional user-related processing details

---

## Example Test Data

### Test Policy 1: Users Only
```json
{
  "id": "TEST-001",
  "name": "Direct User Access",
  "policyType": "1",
  "operator": "AND",
  "action": "ALLOW",
  "conditions": [
    {
      "operator": "OR",
      "operands": [
        { "objectType": "APP", "rhs": "app-123" }
      ]
    },
    {
      "operator": "OR",
      "operands": [
        {
          "objectType": "SCIM",
          "name": "userName",
          "rhs": "alice@contoso.com"
        },
        {
          "objectType": "SCIM",
          "name": "userName",
          "rhs": "bob@contoso.com"
        }
      ]
    }
  ]
}
```

**Expected Output:**
- EntraGroups: `No_Access_Policy_Found_Replace_Me`
- EntraUsers: `alice@contoso.com; bob@contoso.com`

### Test Policy 2: Groups + Users
```json
{
  "id": "TEST-002",
  "name": "Mixed Access",
  "policyType": "1",
  "operator": "AND",
  "action": "ALLOW",
  "conditions": [
    {
      "operator": "OR",
      "operands": [
        { "objectType": "APP", "rhs": "app-456" }
      ]
    },
    {
      "operator": "OR",
      "operands": [
        {
          "objectType": "SCIM_GROUP",
          "rhs": "843089"
        },
        {
          "objectType": "SCIM",
          "name": "userName",
          "rhs": "admin@contoso.com"
        }
      ]
    }
  ]
}
```

**Expected Output (assuming group 843089 = "Engineering-Team"):**
- EntraGroups: `Engineering-Team`
- EntraUsers: `admin@contoso.com`

### Test Policy 3: Case Deduplication
```json
{
  "conditions": [
    {
      "operator": "OR",
      "operands": [
        { "objectType": "SCIM", "name": "userName", "rhs": "User@Contoso.com" },
        { "objectType": "SCIM", "name": "userName", "rhs": "user@contoso.com" },
        { "objectType": "SCIM", "name": "userName", "rhs": "USER@CONTOSO.COM" }
      ]
    }
  ]
}
```

**Expected Output (after deduplication):**
- EntraUsers: `User@Contoso.com` (first occurrence preserved, other two removed)

---

## Appendix: Sample Access Policy with SCIM Usernames

### Full Policy Example
```json
{
  "id": "217246660303025590",
  "name": "Production App - Engineering and Admins",
  "ruleOrder": "5",
  "priority": "25",
  "policyType": "1",
  "operator": "AND",
  "action": "ALLOW",
  "conditions": [
    {
      "id": "635830",
      "operator": "OR",
      "negated": false,
      "operands": [
        {
          "objectType": "APP",
          "lhs": "id",
          "rhs": "217246660303025577",
          "name": "Production-API"
        },
        {
          "objectType": "APP_GROUP",
          "lhs": "id",
          "rhs": "217246660303025575",
          "name": "Production-Apps"
        }
      ]
    },
    {
      "id": "635831",
      "operator": "OR",
      "negated": false,
      "operands": [
        {
          "objectType": "SCIM_GROUP",
          "lhs": "216197681112940647",
          "rhs": "843089",
          "idpId": "216197681112940647",
          "idpName": "IDP1"
        },
        {
          "objectType": "SCIM_GROUP",
          "lhs": "216197681112940647",
          "rhs": "843090",
          "idpId": "216197681112940647",
          "idpName": "IDP1"
        },
        {
          "objectType": "SCIM",
          "lhs": "216197681112940649",
          "rhs": "senior.admin@contoso.com",
          "name": "userName",
          "idpId": "216197681112940647",
          "idpName": "IDP1"
        },
        {
          "objectType": "SCIM",
          "lhs": "216197681112940649",
          "rhs": "lead.engineer@contoso.com",
          "name": "userName",
          "idpId": "216197681112940647",
          "idpName": "IDP1"
        },
        {
          "objectType": "SCIM",
          "lhs": "216197681112940649",
          "rhs": "emergency.access@contoso.com",
          "name": "userName",
          "idpId": "216197681112940647",
          "idpName": "IDP1"
        }
      ]
    }
  ]
}
```

**Processing Result:**
- Target Apps: `217246660303025577` + all apps in APP_GROUP `217246660303025575`
- SCIM Groups: IDs `843089`, `843090` (resolve to names via scim_groups.json)
- SCIM Users: `emergency.access@contoso.com; lead.engineer@contoso.com; senior.admin@contoso.com` (sorted alphabetically)

---

## Document Information

**Specification Version**: 1.0  
**Date**: October 4, 2025  
**Depends On**: Spec 20251001-Transform-ZPA2EPA-ImportAccessGroups.md  
**Status**: Ready for Implementation  
**Author**: Andres Canello
