# Export Entra Global Secure Access Configuration - Technical Specifications

**Version:** 1.0  
**Date:** January 7, 2026  
**Purpose:** Define the backup/export process for Entra Global Secure Access (GSA) configurations to CSV files that can be used for restoration or migration using the provisioning functions.
- **Status:** Draft
- **Target Module:** Migrate2GSA
- **Function Name:** Export-EntraGlobalSecureAccessConfig
- **Author:** Franck Heilmann

---

## Overview

This specification defines how to export Global Secure Access (GSA) configurations from an existing Entra tenant into CSV files. The exported CSV files are formatted to be directly compatible with the provisioning functions (`Start-EntraInternetAccessProvisioning` and `Start-EntraPrivateAccessProvisioning`), enabling backup/restore scenarios.

**Key Concept:** Since both source and destination are Microsoft GSA, no conversion is required. This function extracts GSA configurations via Microsoft Graph API and formats them directly into the CSV structure expected by the provisioning phase.

**Supported Components:**
- **Entra Internet Access (EIA):**
  - Web Content Filtering Policies (and their rules)
  - TLS Inspection Policies (and their rules)
  - Security Profiles
  - Conditional Access Policies (linked to security profiles)
  
- **Entra Private Access (EPA):**
  - Application Segments
  - Segment Groups
  - Access Policies
  - User/Group assignments

**Output:** Timestamped CSV files in the format expected by `Start-EntraInternetAccessProvisioning` and `Start-EntraPrivateAccessProvisioning` functions.

---

## 1. Function Definition

### 1.1 Function Name
```powershell
Export-EntraGlobalSecureAccessConfig
```

### 1.2 Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-ExportInternetAccess` | Switch | No | False | Export Entra Internet Access (EIA) configurations |
| `-ExportPrivateAccess` | Switch | No | False | Export Entra Private Access (EPA) configurations |
| `-OutputPath` | String | No | Current directory | Directory where CSV files will be saved |
| `-IncludeConditionalAccessPolicies` | Switch | No | False | Include Conditional Access policies in the export (EIA only) |

### 1.3 Parameter Validation Rules

**Default behavior when no export type specified:**
```powershell
if (-not $ExportInternetAccess -and -not $ExportPrivateAccess) {
    # Default to exporting both EIA and EPA
    $ExportInternetAccess = $true
    $ExportPrivateAccess = $true
    Write-Verbose "No export type specified. Defaulting to export both Internet Access and Private Access."
}
```

**Both export types can be specified:**
- User can explicitly export both EIA and EPA using both switches
- User can export only EIA or only EPA by specifying the respective switch
- If neither switch is specified, both are exported by default
- Separate CSV files will be generated for each component

**Output Path:**
- If not specified, use current directory
- A timestamped subfolder will be created: `GSA-backup_yyyyMMdd_HHmmss/`
- Must have write permissions to create the subfolder
- Validate write permissions before starting export

### 1.4 Prerequisites
- Authenticated Microsoft Graph session with appropriate permissions
- Read permissions for:
  - `NetworkAccessPolicy.Read.All` (for EIA policies)
  - `Application.Read.All` (for EPA segments)
  - `Policy.Read.All` (for Conditional Access policies, if included)
  - `User.Read.All` and `Group.Read.All` (for user/group assignments)

---

## 2. Output Files and Naming Convention

### 2.1 Timestamp Format and Folder Structure
All output files are stored in a timestamped subfolder with separate subdirectories for each component:
```
GSA-backup_yyyyMMdd_HHmmss/
├── InternetAccess/
└── PrivateAccess/
```

Example: `GSA-backup_20260107_143022/`

**Folder Creation:**
- A new timestamped folder is created for each export operation
- Within the timestamped folder, subdirectories are created based on what is being exported:
  - `InternetAccess/` - Created when EIA configurations are exported
  - `PrivateAccess/` - Created when EPA configurations are exported
- Files within each subfolder include timestamp prefix (same timestamp as folder)
- Multiple exports on the same day create separate timestamped folders with unique timestamps

### 2.2 Entra Internet Access (EIA) Output Files

When `-ExportInternetAccess` is specified (or defaulted):

1. **Policies CSV** (REQUIRED)
   ```
   GSA-backup_yyyyMMdd_HHmmss/InternetAccess/yyyyMMdd_HHmmss_EIA_Policies.csv
   Example: GSA-backup_20260107_143022/InternetAccess/20260107_143022_EIA_Policies.csv
   ```

2. **Security Profiles CSV** (OPTIONAL - generated if security profiles exist OR if `-IncludeConditionalAccessPolicies` is specified)
   ```
   GSA-backup_yyyyMMdd_HHmmss/InternetAccess/yyyyMMdd_HHmmss_EIA_SecurityProfiles.csv
   Example: GSA-backup_20260107_143022/InternetAccess/20260107_143022_EIA_SecurityProfiles.csv
   ```

3. **Log File**
   ```
   GSA-backup_yyyyMMdd_HHmmss/InternetAccess/yyyyMMdd_HHmmss_Export-EIA.log
   Example: GSA-backup_20260107_143022/InternetAccess/20260107_143022_Export-EIA.log
   ```

### 2.3 Entra Private Access (EPA) Output Files

When `-ExportPrivateAccess` is specified (or defaulted):

1. **Private Access Configuration CSV**
   ```
   GSA-backup_yyyyMMdd_HHmmss/PrivateAccess/yyyyMMdd_HHmmss_EPA_Config.csv
   Example: GSA-backup_20260107_143022/PrivateAccess/20260107_143022_EPA_Config.csv
   ```

2. **Log File**
   ```
   GSA-backup_yyyyMMdd_HHmmss/PrivateAccess/yyyyMMdd_HHmmss_Export-EPA.log
   Example: GSA-backup_20260107_143022/PrivateAccess/20260107_143022_Export-EPA.log
   ```

### 2.4 Combined Export

When both EIA and EPA are exported (either by specifying both switches or by default), all applicable files are stored in the same timestamped backup folder.

**Example folder structure:**
```
GSA-backup_20260107_143022/
├── InternetAccess/
│   ├── 20260107_143022_EIA_Policies.csv
│   ├── 20260107_143022_EIA_SecurityProfiles.csv
│   └── 20260107_143022_Export-EIA.log
└── PrivateAccess/
    ├── 20260107_143022_EPA_Config.csv
    └── 20260107_143022_Export-EPA.log
```

---

## 3. CSV File Formats

### 3.1 EIA Policies CSV Format

**Must match the input format expected by `Start-EntraInternetAccessProvisioning` `-PoliciesCsvPath` parameter.**

**Columns:**
```
RecordType, Provision, PolicyName, PolicyDescription, PolicyAction, RuleDestination, RuleDestinationType, RuleProtocol, RulePorts
```

**RecordType Values:**
- `WebContentFilteringPolicy` - Web content filtering policy header
- `WebContentFilteringRule` - Individual rule within a web policy
- `TlsInspectionPolicy` - TLS inspection policy header
- `TlsInspectionRule` - Individual rule within a TLS policy

**Provision Field:**
- Default value: `yes` (enables immediate re-provisioning)
- Can be manually changed to `no` to skip specific items during restore

**Example:**
```csv
RecordType,Provision,PolicyName,PolicyDescription,PolicyAction,RuleDestination,RuleDestinationType,RuleProtocol,RulePorts
WebContentFilteringPolicy,yes,Corporate Web Policy,Main web filtering policy,,,,,
WebContentFilteringRule,yes,Corporate Web Policy,,block,Gambling,webCategory,,
WebContentFilteringRule,yes,Corporate Web Policy,,allow,*.contoso.com,fqdn,,
TlsInspectionPolicy,yes,TLS Inspection Policy,Decrypt specified traffic,,,,,
TlsInspectionRule,yes,TLS Inspection Policy,,decrypt,*.salesforce.com,fqdn,tcp,443
```

### 3.2 EIA Security Profiles CSV Format

**Must match the input format expected by `Start-EntraInternetAccessProvisioning` `-SecurityProfilesCsvPath` parameter.**

**Columns:**
```
RecordType, Provision, SecurityProfileName, SecurityProfileDescription, LinkedWebPolicyName, LinkedTlsPolicyName, CAPolicyName, CAPolicyState, CAIncludeUsers, CAIncludeGroups, CAExcludeUsers, CAExcludeGroups, CAGrantControlOperator, CAGrantControlBuiltInControls
```

**RecordType Values:**
- `SecurityProfile` - Security profile definition with linked policies
- `ConditionalAccessPolicy` - Conditional Access policy linked to security profile

**Provision Field:**
- Default value: `yes`
- Can be changed to `no` to skip during restore

**Example:**
```csv
RecordType,Provision,SecurityProfileName,SecurityProfileDescription,LinkedWebPolicyName,LinkedTlsPolicyName,CAPolicyName,CAPolicyState,CAIncludeUsers,CAIncludeGroups,CAExcludeUsers,CAExcludeGroups,CAGrantControlOperator,CAGrantControlBuiltInControls
SecurityProfile,yes,Corporate Profile,Primary security profile,Corporate Web Policy,TLS Inspection Policy,,,,,,,,
ConditionalAccessPolicy,yes,Corporate Profile,,,,GSA - Corporate Profile,enabled,,Corporate Users,Break Glass,,compliantDevice|domainJoinedDevice
```

### 3.3 EPA Configuration CSV Format

**Must match the input format expected by `Start-EntraPrivateAccessProvisioning`.**

**Note:** Review the existing EPA provisioning function specification (if available) or the actual function implementation to determine the exact CSV format required.

**Expected Columns (to be confirmed):**
```
RecordType, Provision, [SegmentName, SegmentDescription, SegmentGroupName, ApplicationFqdn, Ports, Protocol, AccessPolicyName, AccessPolicyAction, AssignedUsers, AssignedGroups, ...]
```

**RecordType Values (expected):**
- `SegmentGroup` - Application segment group
- `ApplicationSegment` - Application segment definition
- `AccessPolicy` - Access policy rules

---

## 4. Export Process Flow

### 4.1 High-Level Flow

```
1. Validate parameters and prerequisites
   - If neither -ExportInternetAccess nor -ExportPrivateAccess specified, default to both
2. Authenticate to Microsoft Graph (or verify existing session)
3. Generate timestamp for folder naming
4. Create timestamped backup folder: GSA-backup_yyyyMMdd_HHmmss/
5. Export requested configurations:
   a. If -ExportInternetAccess (or defaulted): Export EIA configurations
   b. If -ExportPrivateAccess (or defaulted): Export EPA configurations
6. Generate log files in the backup folder
7. Display summary and folder location
```

### 4.2 EIA Export Process (Detailed)

#### 4.2.1 Export Web Content Filtering Policies

**API Endpoint:**
```
GET https://graph.microsoft.com/beta/networkaccess/filteringPolicies
GET https://graph.microsoft.com/beta/networkaccess/filteringPolicies/{id}/policyRules
```

**Process:**
1. Get all web content filtering policies
2. For each policy:
   - Create policy record (RecordType = `WebContentFilteringPolicy`)
   - Get all rules for the policy
   - For each rule, create rule record (RecordType = `WebContentFilteringRule`)
   - Map rule properties to CSV columns:
     - Action (allow/block)
     - Destination (FQDN, IP, or web category name)
     - Destination Type (fqdn, ipAddress, webCategory)
     - Protocol (if applicable)
     - Ports (if applicable)

**Field Mapping:**
- `PolicyName` ← Policy display name
- `PolicyDescription` ← Policy description
- `RuleDestination` ← Rule destination value
- `RuleDestinationType` ← webCategory | fqdn | ipAddress | ipRange | ipSubnet
- `PolicyAction` ← allow | block
- `RuleProtocol` ← tcp | udp | icmp (if specified)
- `RulePorts` ← Port numbers (if specified)

#### 4.2.2 Export TLS Inspection Policies

**API Endpoint:**
```
GET https://graph.microsoft.com/beta/networkaccess/filteringPolicies?$filter=policyType eq 'tlsInspection'
GET https://graph.microsoft.com/beta/networkaccess/filteringPolicies/{id}/policyRules
```

**Process:**
1. Get all TLS inspection policies
2. For each policy:
   - Create policy record (RecordType = `TlsInspectionPolicy`)
   - Get all rules for the policy
   - For each rule, create rule record (RecordType = `TlsInspectionRule`)
   - Map rule properties (similar to web filtering, but action is typically "decrypt")

#### 4.2.3 Export Security Profiles

**API Endpoint:**
```
GET https://graph.microsoft.com/beta/networkaccess/filteringProfiles
```

**Process:**
1. Get all security profiles
2. For each profile:
   - Create security profile record (RecordType = `SecurityProfile`)
   - Extract linked policy names:
     - `LinkedWebPolicyName` ← Resolve policy ID to policy name
     - `LinkedTlsPolicyName` ← Resolve policy ID to policy name
   - If profile has no linked policies, still export it (may be configured later)

**Note:** Security Profiles CSV is only generated if:
- Security profiles exist in the tenant, OR
- `-IncludeConditionalAccessPolicies` is specified

#### 4.2.4 Export Conditional Access Policies (Optional)

**Only if `-IncludeConditionalAccessPolicies` is specified.**

**API Endpoint:**
```
GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies
```

**Process:**
1. Get all Conditional Access policies
2. Filter policies that reference GSA security profiles:
   - Check for session controls that reference `networkaccess`
   - Check policy description or naming conventions (if used)
3. For each relevant CA policy:
   - Create CA policy record (RecordType = `ConditionalAccessPolicy`)
   - Map CA policy properties:
     - `CAPolicyName` ← CA policy name
     - `CAPolicyState` ← enabled | disabled | enabledForReportingButNotEnforced
     - `CAIncludeUsers` ← Pipe-separated list of user UPNs
     - `CAIncludeGroups` ← Pipe-separated list of group names
     - `CAExcludeUsers` ← Pipe-separated list of user UPNs
     - `CAExcludeGroups` ← Pipe-separated list of group names
     - `CAGrantControlOperator` ← AND | OR
     - `CAGrantControlBuiltInControls` ← Pipe-separated controls
   - Link to associated security profile name

**User/Group Resolution:**
- Resolve user object IDs to UPNs
- Resolve group object IDs to display names
- Cache resolutions to avoid duplicate Graph calls

### 4.3 EPA Export Process (Detailed)

#### 4.3.1 Export Application Segment Groups

**API Endpoint:**
```
GET https://graph.microsoft.com/beta/networkaccess/connectivity/branches/{branchId}/connectivityConfiguration
```

**Process:**
1. Get all segment groups
2. For each segment group:
   - Create segment group record (RecordType = `SegmentGroup`)
   - Map properties to CSV columns

#### 4.3.2 Export Application Segments

**API Endpoint:**
```
GET https://graph.microsoft.com/beta/networkaccess/connectivity/branches
```

**Process:**
1. Get all application segments
2. For each segment:
   - Create segment record (RecordType = `ApplicationSegment`)
   - Map properties including:
     - Segment name and description
     - Associated segment group
     - FQDNs
     - Ports and protocols
     - Connector groups

#### 4.3.3 Export Access Policies

**API Endpoint:**
```
GET https://graph.microsoft.com/beta/networkaccess/forwardingPolicies
```

**Process:**
1. Get all access policies
2. For each policy:
   - Create access policy record (RecordType = `AccessPolicy`)
   - Map properties including:
     - Policy name and action
     - Associated application segments
     - User/group assignments
     - Conditions

**User/Group Resolution:**
- Resolve user object IDs to UPNs
- Resolve group object IDs to display names

---

## 5. Error Handling and Logging

### 5.1 Graph API Errors
- **Throttling:** Implement retry logic with exponential backoff
- **Permission Errors:** Log clear error message indicating missing permissions
- **Not Found:** Log warning if expected objects don't exist (e.g., no policies configured)

### 5.2 Data Validation
- **Empty Results:** If no configurations exist, still create CSV files with headers only
- **Invalid Data:** Log warnings for any unexpected data structures
- **Name Conflicts:** If duplicate names exist, preserve all (Graph IDs ensure uniqueness)

### 5.3 Log File Contents
- Timestamp of export operation
- Parameters used
- Summary of exported items (counts by type)
- Any warnings or errors encountered
- Duration of export operation
- Output file locations and sizes

### 5.4 Console Output
Display summary:
```
Export completed successfully!

Backup folder: C:\Backups\GSA-backup_20260107_143022\

Entra Internet Access (EIA):
  Exported: 3 Web Content Filtering Policies (15 rules)
  Exported: 1 TLS Inspection Policy (5 rules)
  Exported: 2 Security Profiles
  Exported: 2 Conditional Access Policies
  
  Files created in InternetAccess\:
    - 20260107_143022_EIA_Policies.csv (12 KB)
    - 20260107_143022_EIA_SecurityProfiles.csv (3 KB)
    - 20260107_143022_Export-EIA.log (8 KB)

Entra Private Access (EPA):
  Exported: 5 Application Segments
  Exported: 2 Segment Groups
  Exported: 3 Access Policies
  
  Files created in PrivateAccess\:
    - 20260107_143022_EPA_Config.csv (8 KB)
    - 20260107_143022_Export-EPA.log (5 KB)

Total duration: 12.5 seconds
```

---

## 6. Usage Examples

### 6.1 Export Both EIA and EPA (Default Behavior)
```powershell
# No switches specified - exports both by default
Export-EntraGlobalSecureAccessConfig

# Output: Creates GSA-backup_20260107_143022\ with InternetAccess\ and PrivateAccess\ subfolders
```

### 6.2 Export Only EIA Configurations
```powershell
Export-EntraGlobalSecureAccessConfig -ExportInternetAccess

# Output: Creates GSA-backup_20260107_143022\InternetAccess\ with EIA files only
```

### 6.3 Export Only EPA Configurations
```powershell
Export-EntraGlobalSecureAccessConfig -ExportPrivateAccess -OutputPath "C:\GSA-Backups"

# Output: Creates C:\GSA-Backups\GSA-backup_20260107_143022\PrivateAccess\ with EPA files only
```

### 6.4 Export Both with Custom Output Path
```powershell
Export-EntraGlobalSecureAccessConfig -ExportInternetAccess -ExportPrivateAccess -OutputPath "C:\Backups"

# Output: Creates C:\Backups\GSA-backup_20260107_143022\ with both InternetAccess\ and PrivateAccess\ subfolders
```

### 6.5 Export EIA with Conditional Access Policies
```powershell
Export-EntraGlobalSecureAccessConfig -ExportInternetAccess -IncludeConditionalAccessPolicies

# Output: Creates GSA-backup_20260107_143022\InternetAccess\ with EIA files including CA policies
```

### 6.6 Full Backup (Both with CA Policies)
```powershell
Export-EntraGlobalSecureAccessConfig `
    -IncludeConditionalAccessPolicies `
    -OutputPath "C:\GSA-Backups"

# Both EIA and EPA are exported by default with CA policies included
# Output: Creates C:\GSA-Backups\GSA-backup_20260107_143022\ with InternetAccess\ and PrivateAccess\ subfolders
```

---

## 7. Restore Process (Using Exported CSV Files)

### 7.1 Restore EIA Configurations
```powershell
# Restore web/TLS policies only
Start-EntraInternetAccessProvisioning -PoliciesCsvPath "C:\Backups\GSA-backup_20260107_143022\InternetAccess\20260107_143022_EIA_Policies.csv"

# Restore policies and security profiles with CA policies
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath "C:\Backups\GSA-backup_20260107_143022\InternetAccess\20260107_143022_EIA_Policies.csv" `
    -SecurityProfilesCsvPath "C:\Backups\GSA-backup_20260107_143022\InternetAccess\20260107_143022_EIA_SecurityProfiles.csv"
```

### 7.2 Restore EPA Configurations
```powershell
Start-EntraPrivateAccessProvisioning -ConfigCsvPath "C:\Backups\GSA-backup_20260107_143022\PrivateAccess\20260107_143022_EPA_Config.csv"
```

### 7.3 Restore Both from Same Backup Folder
```powershell
$backupFolder = "C:\Backups\GSA-backup_20260107_143022"
$timestamp = "20260107_143022"

# Restore EIA
Start-EntraInternetAccessProvisioning `
    -PoliciesCsvPath "$backupFolder\InternetAccess\${timestamp}_EIA_Policies.csv" `
    -SecurityProfilesCsvPath "$backupFolder\InternetAccess\${timestamp}_EIA_SecurityProfiles.csv"

# Restore EPA
Start-EntraPrivateAccessProvisioning -ConfigCsvPath "$backupFolder\PrivateAccess\${timestamp}_EPA_Config.csv"
```

---

## 8. Implementation Notes

### 8.1 Graph API Version Considerations
- Use `/beta` endpoint for GSA-specific resources (networkaccess namespace)
- Use `/v1.0` endpoint for Conditional Access policies (where available)
- Monitor for API changes and update accordingly

### 8.2 Performance Optimization
- Batch Graph API requests where possible
- Cache policy/user/group lookups to avoid duplicate queries
- Use parallel processing for independent operations (EIA vs EPA)

### 8.3 Testing Strategy
1. **Unit Tests:**
   - Parameter validation
   - CSV formatting
   - User/group resolution
   
2. **Integration Tests:**
   - Export from tenant with known configurations
   - Verify CSV file formats match provisioning function expectations
   - Round-trip test: Export → Restore → Verify
   
3. **Edge Cases:**
   - Empty tenant (no policies configured)
   - Large tenant (hundreds of policies)
   - Special characters in names/descriptions
   - Missing user/group assignments

### 8.4 Future Enhancements
- Add `-PolicyName` parameter to export specific policies only
- Add `-SecurityProfileName` parameter to export specific profiles
- Support for incremental/differential exports
- Export to JSON format (in addition to CSV)
- Compression of output files

---

## 9. Dependencies and Requirements

### 9.1 PowerShell Modules
- `Microsoft.Graph.Authentication` (for Graph connection)
- `Microsoft.Graph.Identity.SignIns` (for CA policies)
- Internal module functions:
  - Graph connection management
  - User/group resolution helpers
  - CSV export utilities

### 9.2 Permissions Required
- **Microsoft Graph Permissions:**
  - `NetworkAccessPolicy.Read.All`
  - `Application.Read.All`
  - `Policy.Read.All` (if exporting CA policies)
  - `User.Read.All`
  - `Group.Read.All`

### 9.3 Related Functions
- `Start-EntraInternetAccessProvisioning` - Consumes EIA CSV files
- `Start-EntraPrivateAccessProvisioning` - Consumes EPA CSV files
- Internal Graph request functions
- User/group resolution functions

---

## 10. Success Criteria

### 10.1 Functional Requirements
- ✅ Export all EIA configurations to CSV format matching provisioning input
- ✅ Export all EPA configurations to CSV format matching provisioning input
- ✅ Support selective export (EIA only, EPA only, or both)
- ✅ Generate timestamped files with consistent naming
- ✅ Provide detailed logging and summary output
- ✅ Handle errors gracefully with clear error messages

### 10.2 Quality Requirements
- ✅ Exported CSV files can be directly used with provisioning functions
- ✅ Round-trip success: Export → Edit (optional) → Provision → Verify
- ✅ No data loss during export process
- ✅ Proper handling of special characters and multi-line descriptions
- ✅ Performance: Export completes in reasonable time (< 60 seconds for typical tenant)

### 10.3 Documentation Requirements
- ✅ Complete parameter documentation with examples
- ✅ CSV format documentation
- ✅ Restore process documentation
- ✅ Error messages and troubleshooting guide

---

## 11. Open Questions and Decisions Needed

1. **EPA CSV Format Confirmation:**
   - Need to verify exact CSV format expected by `Start-EntraPrivateAccessProvisioning`
   - Confirm column names and RecordType values
   - Review EPA provisioning spec (if available)

2. **Conditional Access Policy Filtering:**
   - How to reliably identify CA policies that are GSA-related?
   - Should we export ALL CA policies or only GSA-specific ones?
   - Consider adding a naming convention requirement

3. **Large Tenant Handling:**
   - Should we implement pagination for tenants with hundreds of policies?
   - Add progress indicators for long-running exports?
   - Memory optimization for very large datasets?

4. **User/Group Assignment Format:**
   - For EPA and CA policies, how should we handle "All Users" assignments?
   - Should we export by UPN/name or by object ID?
   - How to handle deleted users/groups?

5. **API Endpoint Verification:**
   - Confirm all Graph API endpoints listed above are correct
   - Verify beta vs v1.0 availability
   - Test with actual tenant to validate endpoint responses

---

## Appendix A: Graph API Endpoints Reference

### EIA (Internet Access) Endpoints
```
GET /networkaccess/filteringPolicies
GET /networkaccess/filteringPolicies/{id}
GET /networkaccess/filteringPolicies/{id}/policyRules
GET /networkaccess/filteringProfiles
GET /networkaccess/filteringProfiles/{id}
GET /identity/conditionalAccess/policies
GET /identity/conditionalAccess/policies/{id}
```

### EPA (Private Access) Endpoints
```
GET /networkaccess/connectivity/branches
GET /networkaccess/connectivity/branches/{id}
GET /networkaccess/forwardingPolicies
GET /networkaccess/forwardingPolicies/{id}
```

### User/Group Resolution Endpoints
```
GET /users/{id}
GET /groups/{id}
```

---

## Appendix B: CSV File Structure Examples

### B.1 Sample EIA Policies CSV
```csv
RecordType,Provision,PolicyName,PolicyDescription,PolicyAction,RuleDestination,RuleDestinationType,RuleProtocol,RulePorts
WebContentFilteringPolicy,yes,Production Web Policy,Web filtering for production environment,,,,,
WebContentFilteringRule,yes,Production Web Policy,,block,Adult Content,webCategory,,
WebContentFilteringRule,yes,Production Web Policy,,block,Gambling,webCategory,,
WebContentFilteringRule,yes,Production Web Policy,,allow,*.microsoft.com,fqdn,,
WebContentFilteringRule,yes,Production Web Policy,,allow,*.office.com,fqdn,,
TlsInspectionPolicy,yes,Production TLS Policy,TLS inspection for sensitive sites,,,,,
TlsInspectionRule,yes,Production TLS Policy,,decrypt,*.salesforce.com,fqdn,tcp,443
TlsInspectionRule,yes,Production TLS Policy,,bypass,*.bank.com,fqdn,tcp,443
```

### B.2 Sample EIA Security Profiles CSV
```csv
RecordType,Provision,SecurityProfileName,SecurityProfileDescription,LinkedWebPolicyName,LinkedTlsPolicyName,CAPolicyName,CAPolicyState,CAIncludeUsers,CAIncludeGroups,CAExcludeUsers,CAExcludeGroups,CAGrantControlOperator,CAGrantControlBuiltInControls
SecurityProfile,yes,Production Profile,Primary security profile for production users,Production Web Policy,Production TLS Policy,,,,,,,,
ConditionalAccessPolicy,yes,Production Profile,,,,GSA - Production Access,enabled,,Production Users|Sales Team,admin@contoso.com,Break Glass Accounts,OR,compliantDevice|domainJoinedDevice
SecurityProfile,yes,Guest Profile,Limited access for guest users,Guest Web Policy,,,,,,,,,
ConditionalAccessPolicy,yes,Guest Profile,,,,GSA - Guest Access,enabled,,Guest Users,,,AND,compliantDevice
```


---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-07 | Initial | Initial specification draft |

---

## References

- [Start-EntraInternetAccessProvisioning Specification](./20251016-Start-EntraInternetAccessProvisioning.md)
- [Start-EntraPrivateAccessProvisioning Specification](./20251002-Provision-EntraPrivateAccessConfig-HandleMultipleEntraGroups.md)
- [Migration Workflow Documentation](../website/docs/migration-workflow.md)
- [Microsoft Graph API - Network Access](https://learn.microsoft.com/en-us/graph/api/resources/networkaccess-overview)
- [Microsoft Graph API - Conditional Access](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy)
