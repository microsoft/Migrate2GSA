# ZPA Access Policy to SCIM Group Mapping - Technical Specification

## Overview
Integrate ZPA Access Policy processing into Transform-ZPA2EPA.ps1 to build a lookup structure mapping Application Segment IDs to SCIM Groups that have access. This will enable automatic population of the `EntraGroup` column in the output CSV.

---

## Purpose & Goals

### Primary Goal
Build an **APP-centric lookup structure** where:
- **Key**: Application Segment ID (APP ID)
- **Value**: Array of SCIM Group Names that have access to that application

### Use Case
The integrated functionality will:
1. Optionally load access policy and SCIM group data
2. Build lookup hashtable mapping APP IDs to SCIM group names
3. During application segment processing, look up the APP ID to get all SCIM groups with access
4. Populate the `EntraGroup` CSV column with semicolon-separated group names (instead of "Placeholder_Replace_Me")
5. Use "No_Access_Policy_Found_Replace_Me" when files are provided but no policy matches the APP

### Why APP-centric?
- ZPA Access Policies can target both individual APPs and APP_GROUPs (segment groups)
- APP_GROUPs contain multiple APPs as members
- The lookup must aggregate groups from **both direct APP policies and indirect APP_GROUP policies**
- Transform-ZPA2EPA.ps1 processes individual APP segments, so lookup by APP ID is required

---

## Integration Approach

### Script Modifications to Transform-ZPA2EPA.ps1

#### New Optional Parameters
- `-AccessPolicyPath` - Path to `access_policies.json` (default: `Join-Path $PSScriptRoot "access_policies.json"`)
- `-ScimGroupPath` - Path to `scim_groups.json` (default: `Join-Path $PSScriptRoot "scim_groups.json"`)
- Existing `-SegmentGroupPath` will be reused for APP_GROUP expansion

#### Execution Flow
1. **Parameter validation** (existing)
2. **Initialize logging** (existing)
3. **Load-ApplicationSegments** - Enhanced to return SegmentGroupMembership hashtable (modified)
4. **Build-AppToScimGroupLookup** - New function, builds APP ID → SCIM groups lookup (NEW)
5. **Filter segments** (existing)
6. **Main processing loop** - Uses lookup to populate EntraGroup field (modified)
7. **Export & Summary** - Includes access policy statistics (modified)

#### Fallback Behavior
- **If access policy files not provided or not found**: Use "Placeholder_Replace_Me" (current behavior)
- **If files provided but APP ID not in lookup**: Use "No_Access_Policy_Found_Replace_Me"
- **If files provided and APP ID found**: Use semicolon-separated SCIM group names (e.g., "Group1; Group2; Group3")

#### Error Handling
- **AccessPolicyPath invalid**: Terminate with error
- **ScimGroupPath invalid**: Terminate with error
- **Policy parsing errors**: Log warning and continue with placeholders
- **SCIM group not found**: Log warning, skip that group, continue processing

---

## Input Files

### 1. access_policies.json
**File produced by**: Export-ZPAConfig.ps1 (Get-ZPAAccessPolicies function)

ZPA Access Policies that define which SCIM groups can access which applications or application groups.

**Sample structure:**
```json
{
  "totalPages": "16",
  "list": [
    {
      "id": "217246660303025578",
      "name": "Test all access",
      "ruleOrder": "1",
      "priority": "31",
      "policyType": "1",
      "operator": "AND",
      "action": "ALLOW",
      "conditions": [
        {
          "id": "635818",
          "operator": "OR",
          "negated": false,
          "operands": [
            {
              "objectType": "APP",
              "lhs": "id",
              "rhs": "217246660303025577",
              "name": "TEST-MOCK"
            },
            {
              "objectType": "APP_GROUP",
              "lhs": "id",
              "rhs": "217246660303025575",
              "name": "TEST-GROUP"
            }
          ]
        },
        {
          "id": "635819",
          "operator": "OR",
          "negated": false,
          "operands": [
            {
              "objectType": "SCIM_GROUP",
              "lhs": "216197681112940647",
              "rhs": "843089",
              "idpId": "216197681112940647",
              "idpName": "IDP1"
            }
          ]
        }
      ]
    }
  ]
}
```

### 2. scim_groups.json
**File produced by**: Export-ZPAConfig.ps1 (Get-AllZPAScimGroups function)

SCIM groups synchronized from the identity provider.

**Sample structure:**
```json
{
  "totalCount": 2,
  "list": [
    {
      "id": 1353670,
      "name": "Group1",
      "idpId": 216197681112940647,
      "idpGroupId": "ef5059f6-fc08-4ad4-beb7-a0671e9a123d",
      "sourceIdpName": "IDP1"
    },
    {
      "id": 272705,
      "name": "Group2",
      "idpId": 216197681112940647,
      "idpGroupId": "59f1d831-d2ec-4654-8f6e-0803268c1db0",
      "sourceIdpName": "IDP1"
    }
  ]
}
```

### 3. segment_groups.json
**File produced by**: Export-ZPAConfig.ps1 (Get-ZPASegmentGroups function)

Application segment groups that contain multiple application segments as members.

**Note**: This file is already used by Load-ApplicationSegments for deduplication. The Build-AppToScimGroupLookup function will **reuse the SegmentGroupMembership hashtable** returned by Load-ApplicationSegments instead of re-parsing the file.

**Sample structure:**
```json
{
  "totalCount": 1,
  "list": [
    {
      "id": "217246660303025575",
      "name": "AppGroup-Production",
      "applications": [
        {
          "id": "217246660303025577",
          "name": "App1"
        },
        {
          "id": "217246660303025578",
          "name": "App2"
        }
      ]
    }
  ]
}
```

---

## Processing Logic

### Phase 1: Enhanced Load-ApplicationSegments Function

**Modification to existing function**: Update return value to include SegmentGroupMembership hashtable.

#### Current Return Structure
```powershell
return @{
    Segments = $mergedSegments
    Stats = @{ ... }
}
```

#### Enhanced Return Structure
```powershell
return @{
    Segments = $mergedSegments
    Stats = @{ ... }
    SegmentGroupMembership = @{
        "APP_GROUP_ID_1" = @("APP_ID_1", "APP_ID_2", ...)
        "APP_GROUP_ID_2" = @("APP_ID_3", "APP_ID_4", ...)
    }
}
```

**Purpose**: This hashtable will be reused by Build-AppToScimGroupLookup to avoid re-parsing segment_groups.json.

**Implementation**: Extract the APP_GROUP → APP_IDs mapping during the existing Load-SegmentGroups function and include in the return value.

---

### Phase 2: Build-AppToScimGroupLookup Function (NEW)

**Called immediately after Load-ApplicationSegments in main script flow.**

#### Input Parameters
- `AccessPolicyPath` - Path to access_policies.json
- `ScimGroupPath` - Path to scim_groups.json
- `SegmentGroupMembership` - Hashtable from Load-ApplicationSegments (reused, no file parsing needed)
- `EnableDebugLogging` - Pass through from script parameter

#### Function Logic

##### Step 1: Load SCIM Groups
1. Read and parse `scim_groups.json`
2. Handle paginated format (`list` property) or direct array
3. Build SCIM group lookup: `scimGroupId → groupName`
4. Log total groups loaded
5. **Error Handling**: Terminate if file path provided but invalid/corrupt

##### Step 2: Load Access Policies
1. Read and parse `access_policies.json`
2. Handle paginated format or direct array
3. Store for processing
4. **Error Handling**: Terminate if file path provided but invalid/corrupt

##### Step 3: Validate Prerequisites
- If both files not found/not provided: Return `$null` (script will use placeholders)
- If only one file found: Log warning and return `$null`
- If both files loaded successfully: Continue processing

##### Step 4: Policy Filtering

**Process only policies that meet ALL criteria:**
1. ✅ `policyType` == `"1"` (Access Policy type)
2. ✅ `action` == `"ALLOW"` (Allow access)
3. ✅ Has at least one condition with APP or APP_GROUP operands
4. ✅ Has at least one condition with SCIM_GROUP operands
5. ✅ Root `operator` == `"AND"` (simple policy structure)
6. ✅ No conditions have `negated` == `true`

**Skip policies that:**
- Have different policyType or action
- Have no APP/APP_GROUP targets
- Have no SCIM_GROUP grants
- Use OR operator at root level (complex logic)
- Have any negated conditions
- Are malformed or missing required fields

**Logging**: Log reason for skipping each filtered policy at DEBUG level

##### Step 5: Policy Processing

For each **valid** policy:

**Sub-step 5a: Extract Target Applications**
- Iterate through all conditions
- Find condition(s) with `objectType` == `"APP"` or `"APP_GROUP"`
- Extract all APP IDs from `rhs` field
- Extract all APP_GROUP IDs from `rhs` field

**Sub-step 5b: Expand APP_GROUPs to APPs**
- For each APP_GROUP ID:
  - Look up in **SegmentGroupMembership hashtable** (passed from Load-ApplicationSegments)
  - Get array of member APP IDs
  - Add all member APP IDs to target list
  - **Error Handling**: If APP_GROUP not found in SegmentGroupMembership, log warning and skip this APP_GROUP

**Sub-step 5c: Extract SCIM Groups**
- Iterate through all conditions
- Find condition(s) with `objectType` == `"SCIM_GROUP"`
- Extract all SCIM_GROUP IDs from `rhs` field
- Look up group names using SCIM group lookup
- **Error Handling**: If SCIM_GROUP ID not found in scim_groups.json, log warning and skip this group

**Sub-step 5d: Build Mappings**
- For each APP ID in target list:
  - For each SCIM group found:
    - Add group name to APP's access list
    - Handle merge if APP already has entries from other policies

##### Step 6: Deduplication & Aggregation

For each APP ID across all processed policies:
1. Collect all SCIM group names
2. **Deduplicate by SCIM group ID** (prevent same group appearing twice)
3. Sort alphabetically for consistent output
4. Store final array of unique group names

##### Step 7: Return Lookup Hashtable

Return hashtable with:
- **Keys**: APP ID (string)
- **Values**: Array of SCIM group names (strings)

**Example:**
```powershell
@{
    "217246660303025577" = @("Engineering-Users", "QA-Team")
    "217246660303025578" = @("Engineering-Users", "DevOps-Team", "QA-Team")
    "217246660303025612" = @("Finance-Users")
}
```

---

### Phase 3: Main Processing Loop Integration

**Modification to existing main processing loop in Transform-ZPA2EPA.ps1**

#### Current EntraGroup Assignment
```powershell
EntraGroup = "Placeholder_Replace_Me"
```

#### Enhanced EntraGroup Assignment Logic
```powershell
# Determine EntraGroup value
$entraGroupValue = "Placeholder_Replace_Me"  # Default

if ($null -ne $appToScimGroupLookup) {
    # Access policy files were provided
    $appId = $segment.id
    
    if ($appToScimGroupLookup.ContainsKey($appId)) {
        # APP has access policies
        $groupNames = $appToScimGroupLookup[$appId]
        if ($groupNames -and $groupNames.Count -gt 0) {
            $entraGroupValue = ($groupNames -join "; ")
        } else {
            $entraGroupValue = "No_Access_Policy_Found_Replace_Me"
        }
    } else {
        # APP not found in any access policy
        $entraGroupValue = "No_Access_Policy_Found_Replace_Me"
    }
}

# Use $entraGroupValue in PSCustomObject
EntraGroup = $entraGroupValue
```

---

## Output Specification

### CSV Column Behavior

#### Scenario 1: Access policy files NOT provided (current behavior)
```csv
EntraGroup
Placeholder_Replace_Me
Placeholder_Replace_Me
```

#### Scenario 2: Access policy files provided, APP has policies
```csv
EntraGroup
Engineering-Users; QA-Team
Finance-Users
DevOps-Team; Engineering-Users; QA-Team
```

#### Scenario 3: Access policy files provided, APP not in any policy
```csv
EntraGroup
No_Access_Policy_Found_Replace_Me
```

### Console Logging Output

**Add to existing Transform-ZPA2EPA.ps1 logging during Build-AppToScimGroupLookup execution:**

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
    - No SCIM_GROUP conditions: 5
    - No APP/APP_GROUP targets: 4
    - Negated conditions: 3
    - Complex OR logic at root: 1

Expanding APP_GROUP targets using segment group membership...
  Total APP targets (direct): 89
  Total APP_GROUP targets: 12
  APP_GROUPs expanded to: 47 APPs
  Total unique APPs with access policies: 112

Building APP to SCIM group lookup...
  APPs with access policies: 112
  Warnings:
    - SCIM Groups not found: 3 (IDs logged below)
    - APP_GROUPs not found in segment groups: 1

Access policy lookup built successfully
```

**Add to final summary section in Transform-ZPA2EPA.ps1:**

```
=== TRANSFORMATION SUMMARY ===
Total segments loaded: 150
Segments processed: 150
Total result records: 450
Grouped result records: 320
Conflicts detected: 5

Access Policy Integration:
  Access policy files: Provided
  APPs with assigned groups: 112 (74.7%)
  APPs without access policies: 38 (25.3%)
  APPs using placeholder: 0 (0.0%)

Output file: c:\output\20251001_123456_GSA_EnterpriseApps_All.csv
```

**If access policy files NOT provided:**

```
Access Policy Integration:
  Access policy files: Not provided
  All APPs using placeholder: 150 (100.0%)
```

---

## Function Design

### Main Function (NEW)
```powershell
function Build-AppToScimGroupLookup {
    <#
    .SYNOPSIS
        Builds a lookup table mapping APP IDs to SCIM groups with access.
    
    .PARAMETER AccessPolicyPath
        Path to ZPA Access Policies JSON file.
    
    .PARAMETER ScimGroupPath
        Path to SCIM Groups JSON file.
    
    .PARAMETER SegmentGroupMembership
        Hashtable containing APP_GROUP to APP IDs mapping (from Load-ApplicationSegments).
    
    .PARAMETER EnableDebugLogging
        Enable verbose debug logging.
    
    .OUTPUTS
        Hashtable with APP IDs as keys and arrays of SCIM group names as values.
        Returns $null if files not found or prerequisites not met.
    
    .EXAMPLE
        $lookup = Build-AppToScimGroupLookup `
            -AccessPolicyPath "c:\path\to\access_policies.json" `
            -ScimGroupPath "c:\path\to\scim_groups.json" `
            -SegmentGroupMembership $loadResult.SegmentGroupMembership `
            -EnableDebugLogging:$EnableDebugLogging
    #>
}
```

### Helper Functions (NEW - following Transform-ZPA2EPA.ps1 patterns)
- `Load-AccessPolicies` - Load and parse access policies JSON (handle paginated format)
- `Load-ScimGroups` - Load and parse SCIM groups JSON (handle paginated format)
- `Test-ValidAccessPolicy` - Validate policy meets all filtering criteria
- `Get-AppTargetsFromPolicy` - Extract APP/APP_GROUP operands from policy conditions
- `Get-ScimGroupsFromPolicy` - Extract SCIM_GROUP operands from policy conditions
- `Expand-AppGroupToApps` - Resolve APP_GROUP IDs to member APP IDs using SegmentGroupMembership hashtable

### Modified Functions (EXISTING)
- `Load-SegmentGroups` - **Add**: Build and return SegmentGroupMembership hashtable
- `Load-ApplicationSegments` - **Add**: Include SegmentGroupMembership in return value

---

## Error Handling & Logging

### Critical Errors (Terminate Execution)
- `-AccessPolicyPath` provided but file not found or unreadable
- `-ScimGroupPath` provided but file not found or unreadable
- Invalid JSON format in access_policies.json (when path provided)
- Invalid JSON format in scim_groups.json (when path provided)

### Warnings (Log and Continue with Fallback)
- Access policy files not provided → Use "Placeholder_Replace_Me" for all APPs
- Only one of the two required files found → Log warning, return $null, use placeholders
- SCIM_GROUP ID not found in scim_groups.json → Log warning, skip that group
- APP_GROUP ID not found in SegmentGroupMembership → Log warning, skip that APP_GROUP
- Malformed policy structure → Log warning at DEBUG level, skip policy
- Policy filtered out → Log reason at DEBUG level

### Information Logging
- File loading progress (INFO level)
- Policy filtering statistics (INFO level)
- APP_GROUP expansion counts (INFO level)
- Final lookup table statistics (INFO level)
- Access policy integration summary in final output (INFO level)

---

## Implementation Plan

### Phase 1: Modify Load-ApplicationSegments
1. Update `Load-SegmentGroups` to build and return `SegmentGroupMembership` hashtable
2. Update `Merge-ApplicationSegments` to pass through the hashtable
3. Update `Load-ApplicationSegments` return structure to include `SegmentGroupMembership`
4. Test that existing functionality still works

### Phase 2: Add Script Parameters
1. Add `-AccessPolicyPath` parameter with default path
2. Add `-ScimGroupPath` parameter with default path
3. Update parameter validation and help documentation

### Phase 3: Implement Build-AppToScimGroupLookup
1. Create main function `Build-AppToScimGroupLookup`
2. Implement helper functions:
   - `Load-AccessPolicies`
   - `Load-ScimGroups`
   - `Test-ValidAccessPolicy`
   - `Get-AppTargetsFromPolicy`
   - `Get-ScimGroupsFromPolicy`
   - `Expand-AppGroupToApps`
3. Add comprehensive error handling and logging
4. Test with sample data

### Phase 4: Integrate into Main Script Flow
1. Call `Build-AppToScimGroupLookup` after `Load-ApplicationSegments`
2. Store returned hashtable in `$appToScimGroupLookup` variable
3. Modify main processing loop to use lookup for `EntraGroup` field
4. Test integration with both file scenarios (provided and not provided)

### Phase 5: Update Summary Logging
1. Add access policy statistics to final summary section
2. Include counts for:
   - APPs with assigned groups
   - APPs without access policies
   - APPs using placeholders
3. Test logging output

### Phase 6: Testing & Validation
1. Test with no access policy files (backward compatibility)
2. Test with access policy files (new functionality)
3. Test with partial data (missing groups, missing APP_GROUPs)
4. Test with complex policies (multiple groups, merged policies)
5. Validate CSV output format
6. Performance testing with large datasets

---

## Example Scenarios

### Scenario 1: Direct APP Access
**Input:**
- Policy1: APP(app1) → SCIM_GROUP(group1)

**Output:**
```powershell
@{
    "app1" = @("group1")
}
```

### Scenario 2: APP_GROUP Access
**Input:**
- Policy1: APP_GROUP(appgroup1) → SCIM_GROUP(group2)
- Segment_Groups: appgroup1 contains [app1, app2, app3]

**Output:**
```powershell
@{
    "app1" = @("group2")
    "app2" = @("group2")
    "app3" = @("group2")
}
```

### Scenario 3: Multiple Policies (Merge & Deduplicate)
**Input:**
- Policy1: APP(app1) → SCIM_GROUP(group1)
- Policy2: APP_GROUP(appgroup1) → SCIM_GROUP(group2)
- Segment_Groups: appgroup1 contains [app1, app2]

**Output:**
```powershell
@{
    "app1" = @("group1", "group2")  # Merged from both policies
    "app2" = @("group2")
}
```

### Scenario 4: Multiple Groups in Same Policy
**Input:**
- Policy1: APP(app1) → SCIM_GROUP(group1, group2, group3)

**Output:**
```powershell
@{
    "app1" = @("group1", "group2", "group3")
}
```

---

## File Naming & Location

### Modified Script
`c:\Git\Migrate2GSAPublic\ZScaler\ZPA2EPA\Transform-ZPA2EPA.ps1` (existing file)

### Expected Input Files (default locations)
All files default to script directory (`$PSScriptRoot`):

- `application_segments.json` - Existing (current: `App_Segments.json`)
- `segment_groups.json` - Existing (current: parameter)
- `access_policies.json` - **NEW** (produced by Export-ZPAConfig.ps1)
- `scim_groups.json` - **NEW** (produced by Export-ZPAConfig.ps1)

**Note**: File names match the output from Export-ZPAConfig.ps1 for consistency.

### Output
- Enhanced CSV file with populated `EntraGroup` column
- Console logging with access policy statistics
- Existing log file with additional access policy processing details

---

## Success Criteria

### Backward Compatibility
1. ✅ Script runs successfully without new parameters (uses placeholders as before)
2. ✅ Existing functionality unchanged when access policy files not provided
3. ✅ CSV output format remains consistent

### New Functionality
4. ✅ Script loads access policy and SCIM group files when provided
5. ✅ Correctly filters policies based on criteria
6. ✅ Properly expands APP_GROUPs to member APPs using reused SegmentGroupMembership
7. ✅ Resolves SCIM_GROUP IDs to group names
8. ✅ Merges and deduplicates groups across multiple policies
9. ✅ Populates `EntraGroup` column with semicolon-separated group names
10. ✅ Uses "No_Access_Policy_Found_Replace_Me" when APP not in any policy

### Error Handling
11. ✅ Terminates when access policy file path provided but invalid
12. ✅ Handles missing SCIM groups gracefully (logs warning, skips group)
13. ✅ Handles missing APP_GROUPs gracefully (logs warning, skips APP_GROUP)
14. ✅ Provides comprehensive logging and statistics

### Integration Quality
15. ✅ Load-ApplicationSegments returns SegmentGroupMembership without breaking existing code
16. ✅ Build-AppToScimGroupLookup reuses SegmentGroupMembership (no duplicate file parsing)
17. ✅ Main processing loop cleanly integrates lookup logic
18. ✅ Final summary includes access policy statistics
19. ✅ Code follows existing Transform-ZPA2EPA.ps1 patterns and conventions
20. ✅ Performance remains acceptable with large datasets

