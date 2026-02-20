# Export Entra Private Access Configuration - Technical Specifications

**Version:** 1.0  
**Date:** February 3, 2026  
**Purpose:** Export Microsoft Entra Private Access (EPA) applications and segments to CSV format for backup, migration, or re-provisioning scenarios.  
**Status:** Draft  
**Target Module:** Migrate2GSA  
**Function Name:** Export-EntraPrivateAccessConfig  
**Author:** Franck Heilmann and Andres Canello

---

## Overview

This specification defines how to export Entra Private Access (EPA) application configurations from an existing Entra tenant into a CSV file. The exported CSV is formatted to be directly compatible with the `Start-EntraPrivateAccessProvisioning` function, enabling backup/restore and migration scenarios.

**Key Concept:** This is a direct export from Entra Private Access without transformation. The function retrieves EPA applications and their segments via Microsoft Graph API and formats them into the CSV structure expected by the provisioning function.

**Scope:**
- Exports all GSA-managed Private Access applications (filtered by tags)
- Exports all application segments for each application
- Exports connector group assignments
- Exports Entra group assignments (multiple groups supported via semicolon separation)
- Exports Entra user assignments (by UPN)
- Each segment creates one row in the CSV (multi-segment apps have multiple rows)

**Output:** Timestamped CSV file in a structured folder, matching the format expected by `Start-EntraPrivateAccessProvisioning`.

---

## 1. Function Definition

### 1.1 Function Name
```powershell
Export-EntraPrivateAccessConfig
```

### 1.2 Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-OutputPath` | String | No | Current directory | Directory where timestamped backup folder will be created |
| `-LogPath` | String | No | Auto-generated | Path for log file (defaults to output folder) |

### 1.3 Parameter Validation Rules

**OutputPath:**
- If not specified, use current directory (`$PWD`)
- Must have write permissions to create subfolder
- Validate write permissions before starting export

**LogPath:**
- If not specified, automatically placed in the timestamped backup folder
- Named: `yyyyMMdd_HHmmss_Export-EPA.log`

### 1.4 Prerequisites
- Authenticated Microsoft Graph session (via `Connect-Entra` or `Connect-MgGraph`)
- PowerShell module: `Microsoft.Graph.Authentication`
- Required permission scopes:
  - `Application.Read.All` (for Private Access applications, segments, and service principals)
  - `Directory.Read.All` (for connector groups, groups, and users)
  - `NetworkAccess.Read.All` (for Global Secure Access tenant status and network access resources)

**Note:** These are read-only scopes since this function only exports data. The provisioning function requires ReadWrite scopes.

---

## 2. Output Structure and Naming Convention

### 2.1 Folder Structure
```
GSA-backup_yyyyMMdd_HHmmss/
└── PrivateAccess/
    ├── yyyyMMdd_HHmmss_EPA_Config.csv
    └── yyyyMMdd_HHmmss_Export-EPA.log
```

**Example:**
```
GSA-backup_20260203_143022/
└── PrivateAccess/
    ├── 20260203_143022_EPA_Config.csv
    └── 20260203_143022_Export-EPA.log
```

### 2.2 Timestamp Format
- Format: `yyyyMMdd_HHmmss` (e.g., `20260203_143022`)
- Generated once at function start
- Used consistently for folder name, file names, and log entries

### 2.3 File Naming
- **Config CSV:** `{timestamp}_EPA_Config.csv`
- **Log File:** `{timestamp}_Export-EPA.log`

---

## 3. CSV File Format

### 3.1 Required Columns

The CSV must match the input format expected by `Start-EntraPrivateAccessProvisioning`:

```
EnterpriseAppName, SegmentId, destinationHost, DestinationType, Protocol, Ports, ConnectorGroup, Provision, EntraGroups, EntraUsers
```

### 3.2 Column Definitions

| Column | Description | Data Type | Example Values |
|--------|-------------|-----------|----------------|
| `EnterpriseAppName` | Display name of the Private Access application | String | `Corporate Intranet`, `HR Portal` |
| `SegmentId` | Graph ID of the application segment (optional metadata for reference/audit only; not used by provisioning function) | String (GUID) | `a1b2c3d4-e5f6-7890-abcd-ef1234567890` |
| `destinationHost` | FQDN, IP address, or IP range for the segment | String | `intranet.contoso.com`, `10.0.1.0/24` |
| `DestinationType` | Type of destination | String | `fqdn`, `ipAddress`, `ipRange`, `dnsSuffix` |
| `Protocol` | Network protocol | String | `tcp`, `udp` |
| `Ports` | Port numbers (comma-separated if multiple) | String | `443`, `80,443`, `8080-8090` |
| `ConnectorGroup` | Name of the connector group assigned to the app | String | `US-East Connectors`, `EMEA Connectors` |
| `Provision` | Flag indicating whether to provision this record | String | `no` (default for exports) |
| `EntraGroups` | Semicolon-separated list of assigned Entra group names | String | `Corporate Users`, `Sales;Marketing;HR` |
| `EntraUsers` | Semicolon-separated list of assigned user UPNs | String | `john@contoso.com`, `jane@contoso.com;bob@contoso.com` |

### 3.3 Data Population Rules

**Provision Column:**
- Always set to `no` for exported records
- Allows manual review before re-provisioning

**Missing Data:**
- If data is inaccessible or missing, leave the field blank
- Log warning for missing data but continue export
- Do not use placeholder values like "Unknown" or "N/A"

**Multiple Values:**
- Groups: Semicolon-separated (`;`) without spaces
- Users: Semicolon-separated (`;`) without spaces
- Ports: Comma-separated (`,`) without spaces

**Special Characters and CSV Escaping:**

Proper CSV escaping is critical to maintain data integrity. Apply the following rules:

1. **Fields containing commas:** Enclose entire field in double quotes
   - Input: `US-East, EMEA Connectors`
   - Output: `"US-East, EMEA Connectors"`

2. **Fields containing semicolons:** Enclose entire field in double quotes
   - Input: `Finance; HR Group`
   - Output: `"Finance; HR Group"`

3. **Fields containing double quotes:** Escape with double-quote (`""`) and enclose field in double quotes
   - Input: `Corporate "Main" Intranet`
   - Output: `"Corporate ""Main"" Intranet"`

4. **Fields containing newlines:** Replace newlines with space OR enclose field in double quotes
   - Preferred: Replace `\r\n` or `\n` with single space
   - Alternative: Enclose field in double quotes (preserves newlines)

5. **Leading/trailing spaces:** Enclose field in double quotes to preserve spaces
   - Input: ` Connector Group ` (with spaces)
   - Output: `" Connector Group "`

**PowerShell Export-Csv handles most of these automatically, but validate edge cases during testing.**

### 3.4 Row Structure

**One row per segment:**
- Applications with multiple segments generate multiple rows
- Application-level properties (name, connector group, assignments) are repeated for each segment
- Segments for the same application must have identical values for:
  - `EnterpriseAppName`
  - `ConnectorGroup`
  - `EntraGroups`
  - `EntraUsers`

**Example CSV:**
```csv
EnterpriseAppName,SegmentId,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup,Provision,EntraGroups,EntraUsers
Corporate Intranet,a1b2c3d4-e5f6-7890-abcd-ef1234567890,intranet.contoso.com,fqdn,tcp,443,US-East Connectors,no,Corporate Users;IT Department,admin@contoso.com
Corporate Intranet,b2c3d4e5-f6a7-8901-bcde-f12345678901,10.0.1.50,ipAddress,tcp,8080,US-East Connectors,no,Corporate Users;IT Department,admin@contoso.com
HR Portal,c3d4e5f6-a7b8-9012-cdef-123456789012,hr.contoso.com,fqdn,tcp,443,EMEA Connectors,no,HR Team,
```

---

## 4. Export Process Flow

### 4.1 High-Level Flow

```
1. Validate parameters (OutputPath write permissions)
2. Generate timestamp
3. Create output folder structure: GSA-backup_{timestamp}/PrivateAccess/
4. Initialize logging (set $script:LogPath)
5. Validate required PowerShell modules (Test-RequiredModules)
6. Test Graph connection with required scopes (Test-GraphConnection)
7. Validate GSA tenant onboarding status (Get-IntGSATenantStatus)
8. Retrieve all Private Access applications
9. For each application (with progress indicators):
   a. Update progress: "Processing app X of Y"
   b. Get application properties (name, connector group)
   c. Get service principal for app role assignments
   d. Get assigned groups and users
   e. Get all application segments
   f. Validate segment data quality
   g. For each segment, create CSV row with app + segment data
10. Write CSV file
11. Generate enhanced summary report with statistics
12. Display completion message with folder location
```

### 4.2 Detailed Export Steps

#### 4.2.1 Authentication and Validation

**Module Validation:**
```powershell
# Validate required PowerShell modules are installed
$requiredModules = @(
    'Microsoft.Graph.Authentication'
)
Test-RequiredModules -RequiredModules $requiredModules
```

**Graph Connection Validation:**
```powershell
# Validate Microsoft Graph authentication with required scopes
$requiredScopes = @(
    'Application.Read.All',
    'Directory.Read.All',
    'NetworkAccess.Read.All'
)
Test-GraphConnection -RequiredScopes $requiredScopes
```

**GSA Tenant Status Validation:**
```powershell
Write-LogMessage "Validating Global Secure Access tenant onboarding status..." -Level INFO -Component "Validation"
$tenantStatus = Get-IntGSATenantStatus
if ($tenantStatus.onboardingStatus -ne 'onboarded') {
    Write-LogMessage "Global Secure Access has not been activated on this tenant. Current onboarding status: $($tenantStatus.onboardingStatus). Please complete tenant onboarding before running this script." -Level ERROR -Component "Validation"
    throw "Tenant onboarding validation failed. Status: $($tenantStatus.onboardingStatus)"
}
Write-LogMessage "Global Secure Access tenant status validated: $($tenantStatus.onboardingStatus)" -Level SUCCESS -Component "Validation"
```

**Private Access Feature Validation:**
```powershell
Write-LogMessage "Validating Private Access feature is enabled..." -Level INFO -Component "Validation"
$paProfile = Get-IntNetworkAccessForwardingProfile -ProfileType 'privateAccess'
if (-not $paProfile -or $paProfile.state -ne 'enabled') {
    Write-LogMessage "Private Access is not enabled on this tenant. Current state: $($paProfile.state)" -Level ERROR -Component "Validation"
    throw "Private Access feature validation failed. Please enable Private Access before exporting."
}
Write-LogMessage "Private Access feature validated: enabled" -Level SUCCESS -Component "Validation"
```

**Connector Groups Availability Check:**
```powershell
Write-LogMessage "Checking connector groups availability..." -Level INFO -Component "Validation"
$allConnectorGroups = Get-IntApplicationProxyConnectorGroup
if (-not $allConnectorGroups -or $allConnectorGroups.Count -eq 0) {
    Write-LogMessage "No connector groups found in tenant. Exported apps will have empty ConnectorGroup field. This may cause provisioning issues in target tenant." -Level WARN -Component "Validation"
} else {
    Write-LogMessage "Found $($allConnectorGroups.Count) connector group(s) in tenant" -Level INFO -Component "Validation"
}
```

**Note:** These validation functions are internal functions that must be explicitly called within the function body. They are NOT automatically invoked by module initialization.

#### 4.2.2 Retrieve Private Access Applications

**API Call:**
- Use existing internal function: `Get-IntPrivateAccessApp`
- This function already filters by GSA tags: `PrivateAccessNonWebApplication`, `NetworkAccessManagedApplication`, `NetworkAccessQuickAccessApplication`

**Data Extracted:**
- Application Object ID (`id`)
- Application Client ID (`appId`)
- Display Name (`displayName`)
- Created DateTime (`createdDateTime`)

**Progress Indicator:**
```powershell
Write-Progress -Activity "Exporting Private Access Configuration" `
    -Status "Retrieving applications..." `
    -PercentComplete 10
```

**Error Handling:**
- If no applications found, create empty CSV with headers only
- Log warning: "No Private Access applications found in tenant"

#### 4.2.2 Get Service Principal for Each Application

**API Call:**
- Use existing internal function: `Get-IntServicePrincipal`
- Query by application client ID (appId)

**Purpose:**
- Service Principal ID required for querying app role assignments (groups/users)

**Error Handling:**
- If service principal not found, log error and leave assignments blank
- Continue with segment export

#### 4.2.3 Get Connector Group Assignment

**API Call:**
- Graph endpoint: `GET /beta/applications/{id}/onPremisesPublishing`
- Extract: `onPremisesPublishing.applicationServerGroupId`

**Resolution:**
- Use `Get-IntApplicationProxyConnectorGroup` to resolve ID to name
- Cache connector group lookups (ID → Name mapping)

**Error Handling:**
- If no connector group assigned (ID is null), leave field blank
  - Log warning: "Application '{appName}' has no connector group assigned"
- If connector group ID exists but cannot be resolved (deleted connector group):
  - Use placeholder: `[DELETED]_{connectorGroupId}`
  - Log warning: "Connector group ID {id} referenced by app '{appName}' but not found (likely deleted)"
  - Mark for review in summary report
- Continue with remaining applications on connector group errors

#### 4.2.4 Get Group Assignments

**API Call:**
- Use existing internal function: `Get-IntServicePrincipalAppRoleAssignedTo`
- Filter results where `principalType eq 'Group'`

**Resolution:**
- Extract group principal IDs
- Use `Get-IntGroup` to resolve IDs to display names
- Cache group lookups (ID → Name mapping)

**Output:**
- Join multiple group names with semicolon: `Group1;Group2;Group3`
- If no groups assigned, leave field blank

**Error Handling:**
- If group cannot be resolved (deleted group), log warning and skip it
- Continue with remaining groups

#### 4.2.5 Get User Assignments

**API Call:**
- Use existing internal function: `Get-IntServicePrincipalAppRoleAssignedTo`
- Filter results where `principalType eq 'User'`

**Resolution:**
- Extract user principal IDs
- Use `Get-IntUser` to resolve IDs to UPNs
- Cache user lookups (ID → UPN mapping)

**Output:**
- Join multiple UPNs with semicolon: `user1@contoso.com;user2@contoso.com`
- If no users assigned, leave field blank

**Error Handling:**
- If user cannot be resolved (deleted user), log warning and skip it
- Continue with remaining users

#### 4.2.6 Get Application Segments

**API Call:**
- Use existing internal function: `Get-IntPrivateAccessAppSegment`
- Retrieve all segments for the application

**Data Extracted:**
- Segment ID (`id`)
- Destination Host (`destinationHost`)
- Destination Type (`destinationType`)
- Protocol (`protocol`)
- Port ranges array (`port.destinationPort`)

**Port Processing:**
- Graph returns port ranges as objects with `destinationPort` property
- Convert to comma-separated string: `80,443` or `8080-8090`

**Segment Data Validation:**

Validate segment data quality to prevent provisioning failures:

1. **Destination Host Validation:**
   - Check `destinationHost` is not null, empty, or whitespace
   - Warn if suspicious patterns: `localhost`, `127.0.0.1`, `0.0.0.0`
   - Log ERROR and skip segment if destination is invalid

2. **Port Validation:**
   - Validate port numbers are in valid range (1-65535)
   - Check for invalid values (port 0, negative ports)
   - Validate port range format (e.g., `8080-8090`)
   - Warn if suspicious ports (e.g., port 0)
   - Convert to comma-separated string: `80,443` or `8080-8090`

3. **Destination Type vs Host Consistency:**
   - If `destinationType = 'fqdn'`, validate destination looks like FQDN (contains dot)
   - If `destinationType = 'ipAddress'`, validate destination is valid IP
   - If `destinationType = 'ipRange'`, validate CIDR notation (e.g., `/24`)
   - Log WARNING if type doesn't match format

4. **Protocol Validation:**
   - Verify protocol is `tcp` or `udp`
   - Log WARNING for unexpected protocols

**Error Handling:**
- If no segments exist, log warning and skip application
- If segment data validation fails, log ERROR with details and skip segment
- If segment data is incomplete, leave field blank
- Continue with remaining segments/applications on errors

#### 4.2.7 Build CSV Rows

**Process:**
- For each application (with progress tracking):
  - Update progress indicator:
    ```powershell
    $percentComplete = (($currentAppIndex / $totalApps) * 80) + 20  # 20-100% range
    Write-Progress -Activity "Exporting Private Access Configuration" `
        -Status "Processing application $currentAppIndex of $totalApps: $($app.displayName)" `
        -PercentComplete $percentComplete
    ```
  - Get all segments
  - Create one CSV row per segment
  - All rows for same app have identical app-level properties:
    - `EnterpriseAppName` (same)
    - `ConnectorGroup` (same)
    - `EntraGroups` (same)
    - `EntraUsers` (same)
  - Each row has unique segment properties:
    - `SegmentId` (unique)
    - `destinationHost` (unique)
    - `DestinationType` (per segment)
    - `Protocol` (per segment)
    - `Ports` (per segment)
  - `Provision` is always `no`

**Example Object Array Before CSV Export:**
```powershell
@(
    [PSCustomObject]@{
        EnterpriseAppName = "Corporate Intranet"
        SegmentId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        destinationHost = "intranet.contoso.com"
        DestinationType = "fqdn"
        Protocol = "tcp"
        Ports = "443"
        ConnectorGroup = "US-East Connectors"
        Provision = "no"
        EntraGroups = "Corporate Users;IT Department"
        EntraUsers = "admin@contoso.com"
    },
    [PSCustomObject]@{
        EnterpriseAppName = "Corporate Intranet"
        SegmentId = "b2c3d4e5-f6a7-8901-bcde-f12345678901"
        destinationHost = "10.0.1.50"
        DestinationType = "ipAddress"
        Protocol = "tcp"
        Ports = "8080"
        ConnectorGroup = "US-East Connectors"
        Provision = "no"
        EntraGroups = "Corporate Users;IT Department"
        EntraUsers = "admin@contoso.com"
    }
)
```

#### 4.2.8 Write CSV File

**Export:**
- Complete progress indicator:
  ```powershell
  Write-Progress -Activity "Exporting Private Access Configuration" `
      -Status "Writing CSV file..." `
      -PercentComplete 95
  ```
- Use `Export-Csv` cmdlet
- Parameters:
  - `-Path`: Full path to CSV file
  - `-NoTypeInformation`: Exclude type info header
  - `-Encoding UTF8`: Standard encoding

**Validation:**
- Verify file created successfully
- Log file size and row count
- Close progress indicator:
  ```powershell
  Write-Progress -Activity "Exporting Private Access Configuration" -Completed
  ```

---

## 5. Error Handling and Logging

### 5.1 Error Handling Strategy

**Continue on Errors:**
- Log errors but continue exporting remaining applications
- Leave fields blank if data cannot be retrieved
- Do not throw terminating errors for individual app failures

**Terminating Errors:**
- Graph authentication failure
- No write permissions to output folder
- CSV export failure (disk full, permissions)

### 5.2 Logging Requirements

**Use Internal Function:**
- `Write-LogMessage` (existing internal function)

**Log Levels:**
- `INFO`: Normal operations (app count, progress)
- `WARN`: Missing data, unresolved references
- `ERROR`: Failed operations, API errors
- `SUCCESS`: Completed operations
- `SUMMARY`: Final statistics

**Log Content:**
- Timestamp for each entry
- Function start/end
- Application counts
- Warnings for missing data (groups, users, connector groups)
- Warnings for deleted connector groups
- Segment validation errors with details
- API errors with details
- Export summary statistics (detailed, see section 5.3)

### 5.3 Console Output

**Progress Information:**
- Use `Write-Verbose` for detailed progress
- Use standard output for summary information
- Display completion message with folder location

**Example Completion Message:**
```
Export completed successfully!

Backup folder: C:\Backups\GSA-backup_20260203_143022\

Entra Private Access (EPA):
  Exported: 12 Applications
  Exported: 47 Segments
  
  Connector Groups:
    Unique connector groups referenced: 3
    Apps with no connector group: 2
    Deleted connector groups detected: 1
  
  Assignments:
    Apps with no user/group assignments: 1
    Total unique groups assigned: 8
    Total unique users assigned: 15
  
  Segment Statistics:
    Average segments per app: 3.9
    App with most segments: Corporate Intranet (12 segments)
    Apps with no segments: 0
  
  Performance:
    Graph API calls made: 127
    Cached lookups used: 89
    Total duration: 8.2 seconds
  
  Warnings: 3 (see log file for details)
  Errors: 0
  
Files created in PrivateAccess\:
  - 20260203_143022_EPA_Config.csv (15 KB)
  - 20260203_143022_Export-EPA.log (8 KB)
```

---

## 6. Usage Examples

### 6.1 Basic Export (Default Location)
```powershell
Export-EntraPrivateAccessConfig
```
Creates output in current directory: `.\GSA-backup_20260203_143022\PrivateAccess\`

### 6.2 Export to Custom Location
```powershell
Export-EntraPrivateAccessConfig -OutputPath "C:\GSA-Backups"
```
Creates output in: `C:\GSA-Backups\GSA-backup_20260203_143022\PrivateAccess\`

### 6.3 Export with Custom Log Path
```powershell
Export-EntraPrivateAccessConfig -OutputPath "C:\Backups" -LogPath "C:\Logs\EPA-Export.log"
```
Custom log location outside the backup folder.

---

## 7. Restore Process

### 7.1 Using Exported CSV with Provisioning Function

**Before Provisioning:**
1. Review CSV file
2. Update `Provision` column: Change `no` to `yes` for records to provision
3. Optionally modify group/user assignments
4. Ensure connector groups exist in target tenant

**Provision Command:**
```powershell
Start-EntraPrivateAccessProvisioning `
    -ProvisioningConfigPath "C:\Backups\GSA-backup_20260203_143022\PrivateAccess\20260203_143022_EPA_Config.csv"
```

### 7.2 Selective Restore

**Edit CSV to provision only specific apps:**
1. Set `Provision=yes` for desired applications
2. Keep `Provision=no` for apps to skip
3. Run provisioning function

**Example: Restore only HR applications**
- Filter CSV rows where `EnterpriseAppName` contains "HR"
- Set `Provision=yes` for those rows
- Run provisioning function

---

## 8. Implementation Considerations

### 8.1 Performance Optimization

**Caching:**
- Cache connector group lookups (ID → Name)
- Cache Entra group lookups (ID → Name)
- Cache Entra user lookups (ID → UPN)
- Reduces redundant Graph API calls

**Parallel Processing:**
- Not required for initial implementation
- Process applications sequentially
- Future enhancement: Parallel processing for large tenants

**Rate Limiting:**
- Implement retry logic with exponential backoff
- Use `Invoke-InternalGraphRequest` which should handle this

### 8.2 Testing Strategy

**Unit Tests:**
- Parameter validation
- CSV formatting
- Timestamp generation
- Error handling for missing data

**Integration Tests:**
- Export from test tenant with known configuration
- Verify CSV format matches provisioning expectations
- Round-trip test: Export → Provision → Export → Compare

**Edge Cases:**
- Tenant with no Private Access apps
- Apps with no segments
- Apps with no connector group assigned
- Apps with no group/user assignments
- Apps with many segments (50+)
- Deleted groups/users still in assignments
- Special characters in app names

### 8.3 Dependencies

**Required Internal Functions (Existing):**
- `Get-IntPrivateAccessApp`
- `Get-IntPrivateAccessAppSegment`
- `Get-IntServicePrincipal`
- `Get-IntServicePrincipalAppRoleAssignedTo`
- `Get-IntApplicationProxyConnectorGroup`
- `Get-IntGroup`
- `Get-IntUser`
- `Write-LogMessage`
- `Invoke-InternalGraphRequest`
- `Test-GraphConnection` (optional, for validation)

**PowerShell Modules:**
- `Microsoft.Graph.Authentication` (for Graph session)

---

## 9. Success Criteria

### 9.1 Functional Requirements
- ✅ Validate required modules (Microsoft.Graph.Authentication)
- ✅ Validate Graph connection with read-only scopes (Application.Read.All, Directory.Read.All, NetworkAccess.Read.All)
- ✅ Validate GSA tenant onboarding status before export
- ✅ Export all GSA-managed Private Access applications
- ✅ Export all segments for each application
- ✅ Export connector group assignments (resolved to names)
- ✅ Export Entra group assignments (resolved to names, semicolon-separated)
- ✅ Export Entra user assignments (resolved to UPNs, semicolon-separated)
- ✅ Generate CSV matching `Start-EntraPrivateAccessProvisioning` input format
- ✅ Create timestamped backup folder structure
- ✅ Generate comprehensive log file
- ✅ Handle errors gracefully with clear messages
- ✅ Continue export when individual apps fail

### 9.2 Quality Requirements
- ✅ Exported CSV can be directly used with provisioning function
- ✅ Round-trip success: Export → Provision → Verify (in test tenant)
- ✅ No data loss during export
- ✅ Proper CSV escaping for special characters
- ✅ Performance: Export completes in reasonable time (< 60 seconds for typical tenant)
- ✅ Clear error messages for missing permissions or API failures

### 9.3 Documentation Requirements
- ✅ Complete function documentation (comment-based help)
- ✅ Parameter descriptions with examples
- ✅ CSV format documentation
- ✅ Restore process examples
- ✅ Error handling guide

---

## 10. Internal Functions Assessment

### 10.1 Validation Functions (Must Be Explicitly Called)

**Important:** These internal functions exist but are NOT automatically invoked. They must be explicitly called within the function body.

| Function | Location | Purpose | Usage Pattern |
|----------|----------|---------|---------------|
| `Test-RequiredModules` | `internal/functions/` | Validates required modules are installed | Called at function start with module array |
| `Test-GraphConnection` | `internal/functions/` | Validates Graph authentication and scopes | Called after module validation with scope array |
| `Get-IntGSATenantStatus` | `internal/functions/` | Gets GSA tenant onboarding status | Called to verify tenant is onboarded |
| `Write-LogMessage` | `internal/functions/` | Unified logging function | Used throughout for all logging |

**Example from Start-EntraPrivateAccessProvisioning:**
```powershell
# Inside the function body (after parameter setup):
$requiredModules = @('Microsoft.Graph.Authentication')
Test-RequiredModules -RequiredModules $requiredModules

$requiredScopes = @(
    'NetworkAccessPolicy.ReadWrite.All',
    'Application.ReadWrite.All',
    'NetworkAccess.ReadWrite.All'
)
Test-GraphConnection -RequiredScopes $requiredScopes

Write-LogMessage "Validating Global Secure Access tenant onboarding status..." -Level INFO -Component "Validation"
$tenantStatus = Get-IntGSATenantStatus
if ($tenantStatus.onboardingStatus -ne 'onboarded') {
    throw "Tenant not onboarded"
}
```

### 10.2 Data Retrieval Functions (No Changes Required)

The following internal functions exist and can be used as-is:

| Function | Location | Purpose |
|----------|----------|---------|
| `Get-IntPrivateAccessApp` | `internal/functions/` | Retrieve Private Access apps (already filters by GSA tags) |
| `Get-IntPrivateAccessAppSegment` | `internal/functions/EPA/` | Retrieve app segments |
| `Get-IntServicePrincipal` | `internal/functions/` | Get service principal by appId |
| `Get-IntServicePrincipalAppRoleAssignedTo` | `internal/functions/` | Get app role assignments (groups/users) |
| `Get-IntApplicationProxyConnectorGroup` | `internal/functions/` | Get connector groups (for name resolution) |
| `Get-IntGroup` | `internal/functions/` | Resolve group ID to name |
| `Get-IntUser` | `internal/functions/` | Resolve user ID to UPN |
| `Invoke-InternalGraphRequest` | `internal/functions/` | Graph API wrapper with error handling |

**Assessment:** `Get-IntPrivateAccessApp` does not require updates. It already filters by the correct GSA tags.

### 10.3 Functions That May Need Enhancement

#### Get-IntApplicationProxyConnectorGroup
**Current Status:** Exists  
**Possible Enhancement Needed:** Verify it supports:
- Retrieving all connector groups (for caching)
- Retrieving single connector group by ID (for name resolution)

**Recommended Test:**
```powershell
# Test if function supports retrieving by ID
Get-IntApplicationProxyConnectorGroup -ConnectorGroupId "12345678-1234-1234-1234-123456789012"

# Test if it returns all connector groups when no parameters provided
Get-IntApplicationProxyConnectorGroup
```

**If enhancement needed:**
- Add parameter set for retrieving by ID
- Ensure it returns name property for ID-to-name mapping

### 10.4 New Internal Functions Required

#### Function: Get-IntApplicationOnPremisesPublishing
**Status:** MISSING - Needs to be created  
**Purpose:** Retrieve application proxy settings including connector group assignment  
**Location:** `internal/functions/Get-IntApplicationOnPremisesPublishing.ps1`

**Specification:**
```powershell
<#
.SYNOPSIS
    Retrieves onPremisesPublishing configuration for an application.

.DESCRIPTION
    Gets the application proxy (onPremisesPublishing) configuration for a specified 
    Private Access application, including connector group assignment.

.PARAMETER ApplicationId
    The object ID of the application.

.OUTPUTS
    Returns onPremisesPublishing configuration object with properties:
    - applicationServerGroupId (connector group ID)
    - externalUrl
    - internalUrl
    - isStateClaimEnabled
    - alternateUrl

.EXAMPLE
    $publishing = Get-IntApplicationOnPremisesPublishing -ApplicationId "a1b2c3d4..."
    $connectorGroupId = $publishing.applicationServerGroupId
#>
```

**Graph API Endpoint:**
```
GET https://graph.microsoft.com/beta/applications/{id}/onPremisesPublishing
```

**Error Handling:**
- Return $null if application has no onPremisesPublishing configuration
- Log warning if API call fails
- Do not throw terminating error

---

## 11. Implementation Phases

### Phase 1: Scaffolding and Validation
1. Implement parameter validation (OutputPath)
2. Generate timestamp
3. Create output folder structure
4. Initialize logging ($script:LogPath setup)
5. Call `Test-RequiredModules` with 'Microsoft.Graph.Authentication'
6. Call `Test-GraphConnection` with read-only scopes (Application.Read.All, Directory.Read.All, NetworkAccess.Read.All)
7. Call `Get-IntGSATenantStatus` and validate onboarding

### Phase 2: Core Export Functionality
1. Retrieve Private Access applications using `Get-IntPrivateAccessApp`
2. Retrieve segments for each application
3. Build basic CSV structure
4. Export to file

### Phase 3: Connector Group Integration
1. Create `Get-IntApplicationOnPremisesPublishing` internal function
2. Integrate connector group retrieval
3. Implement connector group ID-to-name resolution
4. Add caching for connector group lookups

### Phase 4: Group and User Assignments
1. Retrieve service principals for applications
2. Get app role assignments (groups and users)
3. Implement group ID-to-name resolution with caching
4. Implement user ID-to-UPN resolution with caching
5. Format as semicolon-separated values

### Phase 5: Error Handling and Polish
1. Implement comprehensive error handling
2. Add logging for all operations
3. Create summary report
4. Handle edge cases (missing data, deleted groups/users)
5. Add progress indicators (Write-Verbose)

### Phase 6: Testing and Documentation
1. Unit tests for core functions
2. Integration tests with test tenant
3. Round-trip testing (export → provision)
4. Comment-based help
5. Update module documentation

---

## 12. Open Questions and Decisions

### 12.1 Resolved by User

✅ **Export Scope:** Export all Private Access apps (no filtering)  
✅ **Group Assignments:** Export actual group assignments (semicolon-separated)  
✅ **User Assignments:** Export actual user assignments by UPN  
✅ **Provision Default:** Set to `no` by default  
✅ **Error Handling:** Continue on errors, leave fields blank  
✅ **Segment Representation:** One row per segment  
✅ **SegmentId:** Use Graph segment ID  
✅ **WhatIf Support:** Not needed for export (read-only operation)  
✅ **Force Parameter:** Not needed (no confirmations for export)  
✅ **Logging:** Use Write-LogMessage internal function  
✅ **Function Name:** Export-EntraPrivateAccessConfig  
✅ **Output Structure:** Match Export-EntraGlobalSecureAccessConfig pattern  
✅ **Connector Group:** Export connector group name  
✅ **App Filter:** Use existing Get-IntPrivateAccessApp filter (GSA tags)  
✅ **Module Validation:** Call Test-RequiredModules explicitly within function for Microsoft.Graph.Authentication  
✅ **Graph Connection:** Call Test-GraphConnection with read-only scopes (Application.Read.All, Directory.Read.All, NetworkAccess.Read.All)  
✅ **Tenant Validation:** Call Get-IntGSATenantStatus and verify onboarding before export

### 12.2 Pending Verification

⚠️ **Connector Group Retrieval:**
- Verify `Get-IntApplicationProxyConnectorGroup` supports retrieval by ID
- Test ID-to-name resolution capability
- Confirm caching strategy

⚠️ **Port Format:**
- Confirm Graph API response format for port ranges
- Verify conversion to comma-separated string format
- Test with various port configurations (single, multiple, ranges)

⚠️ **Segment Properties:**
- Validate all segment properties available from Graph API
- Confirm destinationType values (fqdn, ipAddress, ipRange, dnsSuffix)
- Test with various segment configurations

⚠️ **Service Principal Retrieval:**
- Verify `Get-IntServicePrincipal` can query by appId (not just by servicePrincipalId)
- Confirm return format
- Test error handling for apps without service principals

---

## 13. Appendix

### 13.1 Graph API Endpoints Reference

**Private Access Applications:**
```
GET /beta/applications?$filter=tags/Any(x: x eq 'PrivateAccessNonWebApplication') or tags/Any(x: x eq 'NetworkAccessManagedApplication') or tags/Any(x: x eq 'NetworkAccessQuickAccessApplication')
```

**Application Segments:**
```
GET /beta/applications/{applicationId}/onPremisesPublishing/segmentsConfiguration/microsoft.graph.ipSegmentConfiguration/applicationSegments
```

**On-Premises Publishing (Connector Group):**
```
GET /beta/applications/{applicationId}/onPremisesPublishing
```

**Service Principal:**
```
GET /beta/servicePrincipals?$filter=appId eq '{appId}'
```

**App Role Assignments:**
```
GET /beta/servicePrincipals/{servicePrincipalId}/appRoleAssignedTo
```

**Connector Groups:**
```
GET /beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups
GET /beta/onPremisesPublishingProfiles/applicationProxy/connectorGroups/{id}
```

**Group Resolution:**
```
GET /beta/groups/{groupId}
```

**User Resolution:**
```
GET /beta/users/{userId}
```

### 13.2 Sample CSV Output

**Scenario:** Two applications, first with 2 segments, second with 1 segment

```csv
EnterpriseAppName,SegmentId,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup,Provision,EntraGroups,EntraUsers
Corporate Intranet,7d8e9fa1-2b3c-4d5e-6f7a-8b9c0d1e2f3a,intranet.contoso.com,fqdn,tcp,443,US-East Connectors,no,Corporate Users;IT Department,admin@contoso.com;it-admin@contoso.com
Corporate Intranet,8e9fa1b2-3c4d-5e6f-7a8b-9c0d1e2f3a4b,10.0.1.0/24,ipRange,tcp,8080,US-East Connectors,no,Corporate Users;IT Department,admin@contoso.com;it-admin@contoso.com
HR Portal,9fa1b2c3-4d5e-6f7a-8b9c-0d1e2f3a4b5c,hr.contoso.com,fqdn,tcp,443,EMEA Connectors,no,HR Team,hr-manager@contoso.com
Finance App,1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d,finance.internal,dnsSuffix,tcp,443,US-West Connectors,no,Finance Department;Accounting,finance@contoso.com
Sales Dashboard,2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e,192.168.1.50,ipAddress,tcp,80,US-East Connectors,no,Sales Team;Sales Managers,
```

---


## References

- [Start-EntraPrivateAccessProvisioning Function](../Migrate2GSA/functions/GSA/Start-EntraPrivateAccessProvisioning.ps1)
- [Export-EntraGlobalSecureAccessConfig Specification](./20260107-Export-EntraGlobalSecureAccessConfig.md)
- [Microsoft Graph API - Applications](https://learn.microsoft.com/en-us/graph/api/resources/application)
- [Microsoft Graph API - Application Proxy](https://learn.microsoft.com/en-us/graph/api/resources/onpremisespublishing)
