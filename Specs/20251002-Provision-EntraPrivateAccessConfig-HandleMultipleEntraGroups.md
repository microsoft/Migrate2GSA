# Specification: Handle Multiple Entra Groups in Provision-EntraPrivateAccessConfig.ps1

**Date:** October 2, 2025  
**Author:** Andres Canello  
**Script:** `Provision-EntraPrivateAccessConfig.ps1`  
**Version:** 2.0  

---

## 1. Executive Summary

This specification defines the enhancement to `Provision-EntraPrivateAccessConfig.ps1` to support multiple Entra ID groups per Enterprise Application. Currently, the script only assigns a single Entra ID group from the first segment of each application. This enhancement will allow multiple groups to be specified using semicolon-separated values in the CSV configuration file, with groups aggregated and deduplicated across all segments of an Enterprise Application.

---

## 2. Background

### 2.1 Current Behavior
- The `EntraGroup` column in the CSV contains a single group name per segment
- Only the first segment's `EntraGroup` value is used for the entire Enterprise Application
- Group assignment occurs once per application after the app is created
- Placeholder value `"Placeholder_Replace_Me"` is skipped during group assignment

### 2.2 Business Need
- Enterprise Applications often require access for multiple Entra ID groups (e.g., users, admins, support teams)
- Users need to specify multiple groups without creating duplicate application entries
- The Transform-ZPA2EPA.ps1 script generates data with the required format, however an input file might be created manually.

### 2.3 Entra ID Constraints
- In Entra ID, groups are assigned at the Enterprise Application level, not per segment
- Multiple groups can be assigned to a single Enterprise Application
- Each group assignment is independent and can succeed or fail individually

---

## 3. Functional Requirements

### 3.1 CSV Format Changes

#### 3.1.1 Column Rename
- **Old column name:** `EntraGroup`
- **New column name:** `EntraGroups`

#### 3.1.2 Value Format
- **Single group (existing behavior):**
  ```
  EntraGroups
  GSA-Portal-Users
  ```

- **Multiple groups (new behavior):**
  ```
  EntraGroups
  GSA-Portal-Users;GSA-Portal-Admins;GSA-Support-Team
  ```

- **Delimiter:** Semicolon (`;`) without spaces
- **Empty values:** Empty strings after splitting should be skipped (e.g., `"Group-A;;Group-B"` becomes `["Group-A", "Group-B"]`)

#### 3.1.3 Placeholder Handling
- **Detection pattern:** Any value containing the substring `"_Replace_Me"` should be treated as a placeholder
- **Examples of placeholders to ignore:**
  - `Placeholder_Replace_Me`
  - `EntraGroup_Replace_Me`
  - `TODO_Replace_Me`
- **Whitespace:** Empty or whitespace-only values should also be treated as placeholders

### 3.2 Group Aggregation Logic

#### 3.2.1 Aggregation Across Segments
For each Enterprise Application:
1. Iterate through ALL segments belonging to that application (not just the first segment)
2. For each segment, parse the `EntraGroups` field by splitting on semicolon (`;`)
3. Trim whitespace from each parsed group name
4. Filter out placeholder values (containing `"_Replace_Me"`) and empty strings
5. Collect all group names into a single list
6. Remove duplicates (case-insensitive comparison)
7. Sort alphabetically for consistent ordering

**Example:**
```
EnterpriseAppName: GSA-WebPortal
  Segment1 EntraGroups: "GSA-Portal-Users;GSA-Portal-Admins"
  Segment2 EntraGroups: "GSA-Portal-Admins;GSA-Support-Team"
  Segment3 EntraGroups: "GSA-Portal-Users"
  
Final groups for GSA-WebPortal: ["GSA-Portal-Admins", "GSA-Portal-Users", "GSA-Support-Team"]
```

#### 3.2.2 Edge Cases
- **All placeholders:** If all segments have placeholder values, log a warning and skip group assignment for that application
- **Empty after filtering:** If all group names are filtered out (placeholders/empty), skip group assignment
- **Single segment, single group:** Existing behavior should work unchanged
- **Single segment, multiple groups:** Should parse and assign all groups from that segment

### 3.3 Group Resolution

#### 3.3.1 Resolve-EntraGroups Function Updates
- **Current behavior:** Only resolves groups from first segment of each application
- **New behavior:** Resolve ALL unique group names found across ALL segments
- Cache all resolved group IDs in `$Global:EntraGroupCache` for later assignment

#### 3.3.2 Validation Phase
- During `Validate-ApplicationDependencies`:
  - For each application, validate that all aggregated groups have been resolved
  - If ANY group cannot be resolved, log a warning but do NOT skip the entire application
  - Track unresolved groups for later error reporting

### 3.4 Group Assignment

#### 3.4.1 Assignment Process
For each Enterprise Application:
1. After successful app creation or when app already exists
2. Retrieve the aggregated, deduplicated list of groups for that application
3. Attempt to assign EACH group sequentially
4. Track assignment results: success, already assigned, or failed
5. Log each assignment attempt with appropriate level (SUCCESS, INFO, WARN, ERROR)
6. Continue attempting remaining groups even if one fails

#### 3.4.2 Set-ApplicationGroupAssignments Function Updates
- **Function signature change:** Accept an array of group names instead of a single group name
  ```powershell
  function Set-ApplicationGroupAssignments {
      param(
          [Parameter(Mandatory=$true)]
          [string]$AppId,
          
          [Parameter(Mandatory=$true)]
          [string[]]$GroupNames
      )
  }
  ```

- **Processing logic:**
  ```
  For each group in GroupNames:
    1. Check if group is placeholder -> Skip
    2. Retrieve group ID from cache
    3. If not found -> Log warning, track failure, continue
    4. Check if already assigned -> Log info, track as already assigned, continue
    5. Attempt assignment
    6. If success -> Log success, track success
    7. If failure -> Log error, track failure, continue
  
  Return summary: total groups, successful, already assigned, failed
  ```

#### 3.4.3 Error Handling
- **Individual group failure:** Log error to console and log file, continue with remaining groups
- **Multiple group failures:** Do not list all failed groups in CSV output
- **Application provisioning status:** Application should be marked as successful even if some or all group assignments fail
- **Group not found:** Treat as warning, not error

### 3.5 Logging and Reporting

#### 3.5.1 Console/Log File Output
- **At group resolution phase:**
  ```
  [INFO] Found 5 unique Entra groups to resolve across all segments
  [SUCCESS] Resolved Entra group 'GSA-Portal-Users' to ID: abc-123-def
  [WARN] Entra group 'GSA-Invalid-Group' not found
  ```

- **At group assignment phase:**
  ```
  [INFO] Assigning 3 groups to application 'GSA-WebPortal'
  [INFO] Assigning group 'GSA-Portal-Users' to application
  [SUCCESS] Successfully assigned group 'GSA-Portal-Users' to application
  [INFO] Assigning group 'GSA-Portal-Admins' to application
  [INFO] Group 'GSA-Portal-Admins' is already assigned to application
  [INFO] Assigning group 'GSA-Support-Team' to application
  [ERROR] Failed to assign group 'GSA-Support-Team' to application: Insufficient permissions
  [WARN] Group assignment summary for 'GSA-WebPortal': 1 succeeded, 1 already assigned, 1 failed
  ```

#### 3.5.2 CSV Output (ProvisioningResult Column)
- **All groups assigned successfully:**
  ```
  ProvisioningResult: Provisioned
  ```

- **Some groups already assigned:**
  ```
  ProvisioningResult: Provisioned
  ```

- **One group failed:**
  ```
  ProvisioningResult: Provisioned (Warning: 1 group failed assignment)
  ```

- **Multiple groups failed:**
  ```
  ProvisioningResult: Provisioned (Warning: Multiple groups failed assignment, check the log)
  ```

- **All groups failed but app created:**
  ```
  ProvisioningResult: Provisioned (Warning: All groups failed assignment, check the log)
  ```

- **Application creation failed:**
  ```
  ProvisioningResult: Error: App creation failed - [error message]
  ```

### 3.6 WhatIf Mode

#### 3.6.1 Display Format
When `-WhatIf` is specified:
```
=== PROVISIONING PLAN ===
Applications to provision: 2
Total segments to create: 5

Application: GSA-WebPortal
  Segments: 3
  Connector Group: On-Premises-Connectors
  Entra Groups (3):
    - GSA-Portal-Admins
    - GSA-Portal-Users
    - GSA-Support-Team
  [WHATIF] Would create Private Access application 'GSA-WebPortal'
  [WHATIF] Would assign 3 groups to application 'GSA-WebPortal'

Application: GSA-DatabaseServices
  Segments: 2
  Connector Group: Database-Connectors
  Entra Groups (1):
    - GSA-Database-Users
  [WHATIF] Would create Private Access application 'GSA-DatabaseServices'
  [WHATIF] Would assign 1 group to application 'GSA-DatabaseServices'
```

---

## 4. Documentation Updates

### 4.1 Script Help Documentation
Update the `.SYNOPSIS`, `.DESCRIPTION`, and `.EXAMPLE` sections to reflect:
- Support for multiple groups per application
- Semicolon-separated format
- Column name change to `EntraGroups`

### 4.2 README Updates
Update `GSAProvisioning/EPA/README.md` to document:
- New `EntraGroups` column format
- How group aggregation works
- Error handling for group assignment failures
- Placeholder detection logic

### 4.3 Sample CSV File
Update `Sample-EntraPrivateAccessConfig.rename_to_csv` to:
- Rename column from `EntraGroup` to `EntraGroups`
- Include examples with multiple groups
- Show different placeholder variations

---

## 5. Success Criteria

### 5.1 Functional Success
- ✅ Script correctly parses semicolon-separated group lists
- ✅ Groups are aggregated across all segments of an application
- ✅ Duplicate groups are removed
- ✅ All valid groups are assigned to each application
- ✅ Individual group assignment failures don't stop provisioning
- ✅ Appropriate warnings/errors are logged for failed assignments
- ✅ Placeholder values are correctly identified and skipped
- ✅ Backward compatibility with single-group CSVs is maintained

### 5.2 Non-Functional Success
- ✅ No performance degradation for large CSV files
- ✅ Memory usage remains reasonable with many groups
- ✅ Log files are readable and actionable
- ✅ CSV output provides sufficient information for troubleshooting
- ✅ Code follows PowerShell best practices and existing script patterns

---

## 6. Appendix

### 11.1 Related Files
- `Provision-EntraPrivateAccessConfig.ps1` - Main script file
- `Sample-EntraPrivateAccessConfig.rename_to_csv` - Sample configuration file
- `Transform-ZPA2EPA.ps1` - Upstream script that generates CSV data
- `GSAProvisioning/EPA/README.md` - User documentation

### 6.2 References
- [Microsoft Entra PowerShell Beta Documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.entra.beta/)
- [PowerShell Best Practices](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/cmdlet-development-guidelines)

---

**End of Specification**