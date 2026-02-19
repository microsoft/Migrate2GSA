# Specification: Quick Access App Support in Start-EntraPrivateAccessProvisioning

**Date:** February 19, 2026  
**Author:** Andres Canello  
**Script:** `Start-EntraPrivateAccessProvisioning.ps1`  
**Version:** 3.0  

---

## 1. Executive Summary

This specification defines the enhancement to `Start-EntraPrivateAccessProvisioning.ps1` to support provisioning segments into the **Quick Access** application in addition to regular Private Access Enterprise Applications. The Quick Access app is a special application type in Microsoft Entra Private Access that supports DNS suffix segments and serves as a broad access gateway during VPN-to-Zero-Trust migrations.

The input CSV will include a new `isQuickAccess` column to indicate which rows target the Quick Access app. The script will discover an existing Quick Access app in the tenant or create a new one, then add segments (including the new `dnsSuffix` destination type) to it.

---

## 2. Background

### 2.1 Current Behavior
- The script creates regular Private Access Enterprise Applications (tagged `PrivateAccessNonWebApplication`)
- Each application is created via template `8adf8e6e-67b2-4cf2-a259-e3dc5476c621` with `applicationType = "nonwebapp"`
- All segments require `destinationHost`, `Protocol`, `Ports`, and `DestinationType`
- `DestinationType` supports: `ipAddress`, `ipRangeCidr`, `ipRange`, `FQDN`

### 2.2 Quick Access App Characteristics
Based on tenant inspection, the Quick Access app differs from regular Private Access apps:

| Property | Regular Private Access App | Quick Access App |
|----------|---------------------------|------------------|
| `applicationType` | `nonwebapp` | `quickaccessapp` |
| `isDnsResolutionEnabled` | `false` | `true` only if dnsSuffix segments exist |
| `isAccessibleViaZTNAClient` | `true` | `true` |
| Tag | `PrivateAccessNonWebApplication` | `NetworkAccessQuickAccessApplication` |
| DNS suffix segments | Not supported | Supported |
| Typical count per tenant | Many | One (transition tool) |

### 2.3 DNS Suffix Segments
DNS suffix segments enable **Private DNS** resolution for internal domains via the Quick Access app. Unlike regular segments, DNS suffix segments:
- Have `destinationType = "dnsSuffix"`
- Have **no ports** (`ports: []`, `port: 0`)
- Have **no protocol** (`protocol: "0"`)
- Only require a `destinationHost` value (e.g., `contoso.local`, `corp.internal`)

Example from tenant:
```json
{
  "destinationHost": "contoso.local",
  "destinationType": "dnsSuffix",
  "port": 0,
  "ports": [],
  "protocol": "0",
  "action": "tunnel"
}
```

### 2.4 Quick Access App API Details
- **Discovery:** `GET /beta/applications?$filter=tags/Any(x: x eq 'NetworkAccessQuickAccessApplication')`
- **Creation:** Same template instantiation as regular apps (`POST /beta/applicationTemplates/8adf8e6e-67b2-4cf2-a259-e3dc5476c621/instantiate`), but configured with `applicationType = "quickaccessapp"` and `isDnsResolutionEnabled = true`
- **Segments API:** Same endpoint as regular apps: `POST /beta/applications/{id}/onPremisesPublishing/segmentsConfiguration/microsoft.graph.ipSegmentConfiguration/applicationSegments/`
- **Connector Groups:** Same assignment mechanism as regular apps

### 2.5 Business Need
Organizations migrating from VPN solutions often need to provision Quick Access as a transitional step before per-app segmentation. Supporting Quick Access provisioning alongside per-app provisioning enables a complete migration workflow.

---

## 3. Functional Requirements

### 3.1 CSV Format Changes

#### 3.1.1 New Column: `isQuickAccess`
- **Column name:** `isQuickAccess`
- **Valid values:** `yes`, `no`, empty/blank (treated as `no`)
- **Case-insensitive:** `Yes`, `YES`, `yes` all valid
- **Default:** `no` (backward compatible — existing CSVs without this column work unchanged)
- **Backward Compatibility:** If the `isQuickAccess` column is missing from the CSV, all rows are treated as regular Private Access apps (existing behavior preserved)

#### 3.1.2 EnterpriseAppName for Quick Access Rows
- All rows with `isQuickAccess=yes` should have the **same `EnterpriseAppName`** value
- This name is used as the Quick Access app display name **only when creating a new Quick Access app**
- If a Quick Access app already exists in the tenant, the `EnterpriseAppName` value is ignored (the existing app is reused regardless of its display name)
- **Validation:** If `isQuickAccess=yes` rows have different `EnterpriseAppName` values, log a WARNING and use the `EnterpriseAppName` from the first row

#### 3.1.3 DNSSuffix Destination Type
- `DestinationType` column now supports: `ipAddress`, `ipRangeCidr`, `ipRange`, `FQDN`, `dnsSuffix`
- `dnsSuffix` is only valid for Quick Access rows (`isQuickAccess=yes`)
  - **Validation:** If a row has `DestinationType=dnsSuffix` but `isQuickAccess` is not `yes`, log an ERROR and skip the row
- For `dnsSuffix` segments, `Ports` and `Protocol` columns should be **empty/blank**
  - Validation is relaxed — these fields are not required for `dnsSuffix` segments
  - If `Ports` or `Protocol` are populated for `dnsSuffix` segments, log a WARNING and ignore the values

#### 3.1.4 Quick Access Segments with Ports
- Quick Access apps also support regular segment types (`ipAddress`, `FQDN`, `ipRangeCidr`, `ipRange`) with full port/protocol specifications
- Rows with `isQuickAccess=yes` and a non-`dnsSuffix` DestinationType are processed normally (ports/protocol required)

#### 3.1.5 Sample CSV with Quick Access
```csv
SegmentId,OriginalAppName,EnterpriseAppName,destinationHost,DestinationType,Protocol,Ports,SegmentGroup,ServerGroups,EntraGroups,EntraUsers,ConnectorGroup,Conflict,ConflictingEnterpriseApp,Provision,isQuickAccess
SEG-000001,DatabaseServices,GSA-DatabaseServices,db.contoso.local,FQDN,TCP,1433,DB-Group,DB-Servers,DB-Users,,My-Connectors,No,,Yes,no
SEG-000002,DatabaseServices,GSA-DatabaseServices,10.101.100.10,ipAddress,TCP,1433,DB-Group,DB-Servers,DB-Users,,My-Connectors,No,,Yes,no
SEG-QA-001,QuickAccess,GSA-QuickAccess,contoso.local,dnsSuffix,,,,,,QA-Users,,QA-Connectors,No,,Yes,yes
SEG-QA-002,QuickAccess,GSA-QuickAccess,corp.internal,dnsSuffix,,,,,,QA-Users,,QA-Connectors,No,,Yes,yes
SEG-QA-003,QuickAccess,GSA-QuickAccess,10.0.0.0/8,ipRangeCidr,TCP,443,,,,QA-Users,,QA-Connectors,No,,Yes,yes
```

### 3.2 Quick Access App Discovery and Creation

#### 3.2.1 Discovery Logic
1. Query the tenant for existing Quick Access app(s) using tag filter:
   ```
   GET /beta/applications?$count=true&$filter=tags/Any(x: x eq 'NetworkAccessQuickAccessApplication')&$select=displayName,appId,id,tags,createdDateTime
   ```
2. If found: Reuse the existing app (use its `id` and `appId`)
   - If multiple Quick Access apps exist (unlikely), select the most recent by `createdDateTime`
   - Log INFO: "Found existing Quick Access application: '{name}' (ID: {id})"
3. If not found: Create a new Quick Access app (see 3.2.2)

#### 3.2.2 Creation Logic
1. Instantiate from same template: `POST /beta/applicationTemplates/8adf8e6e-67b2-4cf2-a259-e3dc5476c621/instantiate` with the `EnterpriseAppName` from CSV
2. Configure as Quick Access app:
   ```json
   PATCH /beta/applications/{id}/
   {
     "onPremisesPublishing": {
       "applicationType": "quickaccessapp",
       "isAccessibleViaZTNAClient": true,
       "isDnsResolutionEnabled": <true if any dnsSuffix segments exist, false otherwise>
     }
   }
   ```
   - `isDnsResolutionEnabled` is set to `$true` **only** if at least one `isQuickAccess=yes` row has `DestinationType=dnsSuffix`
   - If all Quick Access segments are regular types (IP, FQDN, CIDR) with no DNS suffixes, set to `$false`
3. Assign connector group (same as regular apps)
4. Log SUCCESS: "Created Quick Access application: '{name}' (ID: {id})"

#### 3.2.3 Connector Group Assignment
- For newly created Quick Access apps: Assign the connector group from the CSV `ConnectorGroup` column (first non-empty value from `isQuickAccess=yes` rows)
- For existing Quick Access apps: **Do not reassign** the connector group (it's already configured)
  - Log INFO: "Using existing connector group assignment for Quick Access application"

### 3.3 Segment Provisioning for Quick Access

#### 3.3.1 DNSSuffix Segments
- Pass to `New-IntPrivateAccessAppSegment` with:
  - `DestinationType = "dnsSuffix"`
  - `DestinationHost = <dns suffix value>` (e.g., `contoso.local`)
  - No `Ports` parameter
  - No `Protocol` parameter
- The existing `New-IntPrivateAccessAppSegment` already handles `dnsSuffix` correctly (builds body without ports/protocol)

#### 3.3.2 Regular Segments on Quick Access
- IP, FQDN, CIDR segments on the Quick Access app are processed identically to regular Private Access app segments
- Full port/protocol validation applies

#### 3.3.3 Duplicate Detection
- Same duplicate detection logic applies as regular segments (catch `Invalid_AppSegments_Duplicate` error)
- For `dnsSuffix` segments, the duplicate is detected by `destinationHost` alone (no ports to match)

### 3.4 Group Assignments for Quick Access
- Group assignment works identically to regular Enterprise Applications
- Groups are aggregated from all `isQuickAccess=yes` segments, deduplicated, and assigned to the Quick Access app's service principal
- The same `EntraGroups` column and `Set-ApplicationGroupAssignments` function are used

### 3.5 Provisioning Flow Changes

#### 3.5.1 App Grouping
The existing flow groups by `EnterpriseAppName`. Quick Access rows are grouped along with regular apps but processed differently:

1. **Separate Quick Access rows** from regular rows during the main provisioning loop
2. **Process Quick Access app first** (before regular apps):
   - Discover or create the Quick Access app
   - Add all Quick Access segments
   - Assign groups
3. **Process regular apps** as before

#### 3.5.2 Processing Order
```
1. Import and validate configuration (including isQuickAccess column)
2. Separate Quick Access rows from regular app rows
3. Resolve connector groups (both QA and regular)
4. Resolve Entra groups (both QA and regular)
5. Validate dependencies
6. --- Quick Access provisioning ---
   a. Discover existing QA app or create new one
   b. Assign connector group (if new app)
   c. Create segments (dnsSuffix + regular types)
   d. Assign groups
7. --- Regular app provisioning (existing flow) ---
   a. For each app group:
      - Create or get app
      - Create segments
      - Assign groups
8. Export results
9. Show summary
```

### 3.6 WhatIf Mode
When `-WhatIf` is specified, the Quick Access section shows:
```
=== QUICK ACCESS APPLICATION ===
Quick Access App: GSA-QuickAccess
  Status: Exists in tenant (ID: a5db2b91-...)
  DNS Suffix Segments: 2
    - contoso.local (dnsSuffix)
    - corp.internal (dnsSuffix)
  Regular Segments: 1
    - 10.0.0.0/8 (ipRangeCidr, TCP:443)
  Entra Groups (1):
    - QA-Users
  [WHATIF] Would add 3 segments to existing Quick Access application
  [WHATIF] Would assign 1 group to Quick Access application
```

Or if the Quick Access app doesn't exist:
```
=== QUICK ACCESS APPLICATION ===
Quick Access App: GSA-QuickAccess (NEW)
  Connector Group: QA-Connectors
  DNS Suffix Segments: 2
    - contoso.local (dnsSuffix)
    - corp.internal (dnsSuffix)
  Regular Segments: 1
    - 10.0.0.0/8 (ipRangeCidr, TCP:443)
  Entra Groups (1):
    - QA-Users
  [WHATIF] Would create Quick Access application 'GSA-QuickAccess'
  [WHATIF] Would add 3 segments to Quick Access application
  [WHATIF] Would assign 1 group to Quick Access application
```

### 3.7 Logging and Reporting

#### 3.7.1 Console/Log File Output
```
[INFO] Found 3 Quick Access segments and 5 regular segments in configuration
[INFO] Discovering existing Quick Access application in tenant...
[SUCCESS] Found existing Quick Access application: 'QA2' (ID: a5db2b91-5115-4ba0-841e-c2498c642596)
[INFO] Processing 3 Quick Access segments...
[INFO] Creating DNS suffix segment: contoso.local
[SUCCESS] Successfully created DNS suffix segment: contoso.local
[INFO] Creating DNS suffix segment: corp.internal
[SUCCESS] Successfully created DNS suffix segment: corp.internal
[INFO] Creating application segment: 10.0.0.0/8
[SUCCESS] Successfully created application segment: 10.0.0.0/8
[INFO] Assigning 1 group to Quick Access application
[SUCCESS] Group assignment completed: 1 succeeded, 0 already assigned, 0 failed
```

#### 3.7.2 CSV Output (ProvisioningResult Column)
- Quick Access segments follow the same result patterns as regular segments:
  - `Provisioned` — Segment created successfully
  - `AlreadyExists` — Segment already exists on the Quick Access app
  - `AddedToExisting` — Segment added to existing Quick Access app
  - `Error: <message>` — Segment creation failed
  - `Skipped: Quick Access app creation failed - <error>` — App-level failure

#### 3.7.3 Execution Summary Enhancement
Add Quick Access statistics to the execution summary:
```
=== EXECUTION SUMMARY ===
Quick Access Application: Existing (QA2)
Quick Access Segments: 3 created, 0 failed
Quick Access Groups: 1 assigned

Regular Applications: 2 created, 0 failed
Regular Segments: 5 created, 0 failed
...
```

---

## 4. Internal Function Changes

### 4.0 Backward Compatibility Requirement (Critical)

All internal function changes **MUST** be purely additive and backward compatible:
- Only **new optional parameters** (switches with default `$false`, optional strings with defaults) may be added
- **No changes** to existing parameter types, names, positions, or validation
- **No changes** to existing return types or output structure
- **No changes** to default behavior when new parameters are omitted
- Existing callers must continue to work without any modification:
  - `Start-EntraPrivateAccessProvisioning.ps1` calls `New-IntPrivateAccessApp`, `Get-IntPrivateAccessApp`, `New-IntPrivateAccessAppSegment`
  - `Export-EntraPrivateAccessConfig.ps1` calls `Get-IntPrivateAccessApp`, `Get-IntPrivateAccessAppSegment`

### 4.1 New-IntPrivateAccessApp (Modify)

**Location:** `internal/functions/EPA/New-IntPrivateAccessApp.ps1`

**Change:** Add support for creating Quick Access apps via new **optional** parameters. When omitted, existing behavior is unchanged.

#### New Optional Parameters
```powershell
[Parameter(Mandatory = $false)]
[switch]$QuickAccess,

[Parameter(Mandatory = $false)]
[switch]$EnableDnsResolution
```

**Backward compatibility:** Both parameters default to `$false`. When omitted, the function behaves exactly as before (creates a `nonwebapp` with `isAccessibleViaZTNAClient = $true`).

#### Modified Behavior
When `-QuickAccess` is specified:
- After template instantiation, PATCH with `applicationType = "quickaccessapp"` instead of `"nonwebapp"`
- Set `isDnsResolutionEnabled` based on `-EnableDnsResolution` switch

When `-QuickAccess` is **not** specified (default):
- Existing behavior is completely unchanged

```powershell
if ($QuickAccess) {
    $bodyJson = @{
        "onPremisesPublishing" = @{
            "applicationType"           = "quickaccessapp"
            "isAccessibleViaZTNAClient" = $true
            "isDnsResolutionEnabled"    = [bool]$EnableDnsResolution
        }
    } | ConvertTo-Json -Depth 99 -Compress
} else {
    # Existing behavior — no changes
    $bodyJson = @{
        "onPremisesPublishing" = @{
            "applicationType"           = "nonwebapp"
            "isAccessibleViaZTNAClient" = $true
        }
    } | ConvertTo-Json -Depth 99 -Compress
}
```

### 4.2 Get-IntPrivateAccessApp (Modify)

The existing function already queries for Quick Access apps via the tag `NetworkAccessQuickAccessApplication` in the `AllPrivateAccessApps` parameter set, but returns all Private Access apps together. Fetching all apps and filtering client-side is inefficient.

**Change:** Add a new **optional** `-QuickAccessOnly` switch parameter that uses a server-side Graph API filter to return only Quick Access apps.

**Backward compatibility:** The new parameter is an optional switch defaulting to `$false`. When omitted, the function behaves exactly as before. `Export-EntraPrivateAccessConfig.ps1` and all other existing callers are unaffected.

#### New Optional Parameter
```powershell
[Parameter(Mandatory = $False, ParameterSetName = 'QuickAccessApp')]
[switch]$QuickAccessOnly
```

#### New Parameter Set Implementation
```powershell
"QuickAccessApp" {
    $response = Invoke-InternalGraphRequest -Method GET -OutputType PSObject `
        -Uri "https://graph.microsoft.com/beta/applications?`$count=true&`$select=displayName,appId,id,tags,createdDateTime&`$filter=tags/Any(x: x eq 'NetworkAccessQuickAccessApplication')"
    $response
    break
}
```

#### Usage in Provisioning Script
```powershell
# Efficient server-side filtered lookup
$existingApp = Get-IntPrivateAccessApp -QuickAccessOnly
```

### 4.3 New-IntPrivateAccessAppSegment (No Changes Needed)

The existing function already supports `dnsSuffix` as a `DestinationType` and correctly builds the request body without ports/protocol for DNS suffix segments. No changes required.

**Backward compatibility:** Function signature, parameters, validation, and return type are all unchanged.

### 4.4 New-ApplicationSegments (Modify)

**Location:** Inside `Start-EntraPrivateAccessProvisioning.ps1`

**Change:** Relax validation for `dnsSuffix` segments — skip port/protocol requirement.

#### Current Validation (line ~818)
```powershell
if (-not $SegmentConfig.destinationHost -or -not $SegmentConfig.Protocol -or -not $SegmentConfig.Ports) {
    throw "Invalid segment configuration: missing required fields"
}
```

#### Modified Validation
```powershell
$isDnsSuffix = $SegmentConfig.DestinationType -eq 'dnsSuffix'

if (-not $SegmentConfig.destinationHost) {
    throw "Invalid segment configuration: missing destinationHost"
}

if (-not $isDnsSuffix -and (-not $SegmentConfig.Protocol -or -not $SegmentConfig.Ports)) {
    throw "Invalid segment configuration: missing Protocol or Ports (required for non-dnsSuffix segments)"
}
```

#### Modified Segment Creation
For `dnsSuffix` segments, call `New-IntPrivateAccessAppSegment` without `Ports` and `Protocol`:
```powershell
if ($isDnsSuffix) {
    $segmentParams = @{
        ApplicationId   = $AppId
        DestinationHost = $SegmentConfig.destinationHost
        DestinationType = 'dnsSuffix'
        ErrorAction     = 'Stop'
    }
} else {
    $segmentParams = @{
        ApplicationId   = $AppId
        DestinationHost = $SegmentConfig.destinationHost
        DestinationType = $SegmentConfig.DestinationType
        Protocol        = $protocolArray
        Ports           = $portArray
        ErrorAction     = 'Stop'
    }
}
```

### 4.5 Import-ProvisioningConfig (Modify)

**Location:** Inside `Start-EntraPrivateAccessProvisioning.ps1`

**Changes:**

#### 4.5.1 Optional Column Handling
- `isQuickAccess` is **not a required column** for backward compatibility
- If the column exists, validate values (`yes`, `no`, empty)
- If the column doesn't exist, add it with default value `no` to all rows

```powershell
# After loading CSV, check for isQuickAccess column
if ('isQuickAccess' -notin $actualColumns) {
    Write-LogMessage "isQuickAccess column not found in CSV. Treating all rows as regular Private Access apps." -Level INFO -Component "Config"
    foreach ($row in $configData) {
        $row | Add-Member -NotePropertyName 'isQuickAccess' -NotePropertyValue 'no' -Force
    }
}
```

#### 4.5.2 Validation
- Validate `isQuickAccess` values are `yes`, `no`, or empty (case-insensitive)
- Normalize values to lowercase
- Validate that `dnsSuffix` DestinationType is only used with `isQuickAccess=yes`
- Validate that all `isQuickAccess=yes` rows have the same `EnterpriseAppName` (WARN if not, use first row's value)

### 4.6 New-PrivateAccessApplication (Modify)

**Location:** Inside `Start-EntraPrivateAccessProvisioning.ps1`

**Change:** Add Quick Access app discovery and creation support.

#### New Parameter
```powershell
[Parameter(Mandatory=$false)]
[switch]$QuickAccess
```

#### Modified Logic
When `-QuickAccess` is specified:
1. **Discovery phase:** Search for existing Quick Access app using server-side filter
   ```powershell
   if ($QuickAccess) {
       $existingApp = Get-IntPrivateAccessApp -QuickAccessOnly
   } else {
       $existingApp = Get-IntPrivateAccessApp -ApplicationName $AppName
   }
   ```
2. **Reuse phase:** If found, return the existing app (don't skip segments — always add segments to QA app)
   - Override `$SkipExisting` behavior for Quick Access apps — always add segments
3. **Creation phase:** If not found, create using `New-IntPrivateAccessApp -QuickAccess -EnableDnsResolution:$hasDnsSuffixSegments -ApplicationName $AppName -ConnectorGroupId $connectorGroupId`
   - `$hasDnsSuffixSegments` is determined by checking if any `isQuickAccess=yes` row has `DestinationType=dnsSuffix`
4. **Connector group:** Only assign connector group when creating a new Quick Access app

### 4.7 Test-ApplicationDependencies (Modify)

**Location:** Inside `Start-EntraPrivateAccessProvisioning.ps1`

**Change:** Adjust dependency validation for Quick Access apps.

- Quick Access rows: Connector group validation is **optional** when an existing Quick Access app is found (the connector group is already assigned)
- Quick Access rows: `dnsSuffix` segments do not require port/protocol validation
- Regular rows: No changes to existing validation

### 4.8 Show-ProvisioningPlan (Modify)

**Location:** Inside `Start-EntraPrivateAccessProvisioning.ps1`

**Change:** Add Quick Access section to the provisioning plan display.

- Separate Quick Access segments from regular segments in the plan
- Show DNS suffix segments distinctly
- Show whether the Quick Access app exists or will be created

### 4.9 Invoke-ProvisioningProcess (Modify)

**Location:** Inside `Start-EntraPrivateAccessProvisioning.ps1`

**Change:** Add Quick Access processing before regular app processing.

```powershell
# Separate Quick Access rows from regular rows
$quickAccessRows = $validConfigData | Where-Object { $_.isQuickAccess -eq 'yes' }
$regularRows = $validConfigData | Where-Object { $_.isQuickAccess -ne 'yes' }

# Process Quick Access app first (if any QA rows exist)
if ($quickAccessRows.Count -gt 0) {
    # ... Quick Access provisioning logic ...
}

# Process regular apps (existing flow)
if ($regularRows.Count -gt 0) {
    $appGroups = $regularRows | Group-Object -Property EnterpriseAppName
    # ... existing app provisioning loop ...
}
```

### 4.10 Show-ExecutionSummary (Modify)

**Location:** Inside `Start-EntraPrivateAccessProvisioning.ps1`

**Change:** Add Quick Access statistics to the summary.

New tracking fields in `$Global:ProvisioningStats`:
```powershell
$Global:ProvisioningStats = @{
    # ... existing fields ...
    QuickAccessApp = $null          # "Created", "Existing", "Failed", or $null (no QA rows)
    QuickAccessSegments = 0
    QuickAccessFailedSegments = 0
    QuickAccessDnsSuffixSegments = 0
}
```

---

## 5. Edge Cases and Error Handling

### 5.1 No Quick Access App in Tenant, No QA Rows in CSV
- No impact — existing behavior preserved

### 5.2 Quick Access App Exists, No QA Rows in CSV
- No impact — Quick Access app is not touched

### 5.3 Multiple Quick Access Apps in Tenant
- Select the most recent by `createdDateTime`
- Log WARNING: "Multiple Quick Access applications found in tenant ({count}). Using most recent: '{name}'"

### 5.4 Quick Access App Creation Fails
- Mark all `isQuickAccess=yes` rows as failed
- Continue with regular app provisioning
- Do not stop the entire provisioning process

### 5.5 DNSSuffix Segment on Regular (Non-Quick Access) App
- **Validation error:** Log ERROR and skip the row
- Mark row: `"Error: dnsSuffix DestinationType is only supported for Quick Access applications (set isQuickAccess=yes)"`

### 5.6 Quick Access Rows with Different EnterpriseAppName Values
- Log WARNING with details
- Use the `EnterpriseAppName` from the first `isQuickAccess=yes` row
- All QA segments are still combined into a single Quick Access app

### 5.7 Empty Ports/Protocol on Non-DNSSuffix Segments
- Existing behavior: Validation error, skip the row
- No change for non-`dnsSuffix` segments

### 5.8 SkipExistingApps Parameter and Quick Access
- `SkipExistingApps` does **not** apply to Quick Access apps
- Quick Access apps are always processed (segments added) even if the app already exists
- Rationale: Quick Access is a shared app where segments are continuously added; skipping it would prevent adding new segments

---

## 6. Documentation Updates

### 6.1 Script Help Documentation
Update `.SYNOPSIS`, `.DESCRIPTION`, and `.EXAMPLE` sections to document:
- Quick Access app support via `isQuickAccess` column
- `dnsSuffix` segment type
- Quick Access app discovery and creation behavior

### 6.2 Sample CSV File
Update `Sample-EntraPrivateAccessConfig.rename_to_csv` to:
- Add `isQuickAccess` column to all rows (value `no` for existing rows)
- Add example Quick Access rows with `dnsSuffix` and regular segment types
- Show mixed CSV with both regular and Quick Access segments

---

## 7. Success Criteria

### 7.1 Functional Success
- ✅ Script discovers existing Quick Access app by tag
- ✅ Script creates new Quick Access app when none exists (with correct `applicationType` and `isDnsResolutionEnabled` set only when dnsSuffix segments are present)
- ✅ `EnterpriseAppName` from CSV is used as display name for new Quick Access apps
- ✅ DNS suffix segments are created without ports/protocol
- ✅ Regular segments (IP, FQDN, CIDR) on Quick Access app work with full port/protocol
- ✅ Group assignments work for Quick Access app
- ✅ Connector group is assigned only when creating a new Quick Access app
- ✅ `SkipExistingApps` does not apply to Quick Access apps
- ✅ Backward compatibility: CSVs without `isQuickAccess` column work unchanged
- ✅ WhatIf mode shows Quick Access plan details
- ✅ Execution summary includes Quick Access statistics
- ✅ Duplicate segment detection works for DNS suffix segments

### 7.2 Non-Functional Success
- ✅ No performance degradation for CSVs without Quick Access rows
- ✅ Clear, actionable logging for Quick Access operations
- ✅ Consistent error handling patterns with existing code
- ✅ Code follows PowerShell best practices and existing script patterns
- ✅ No breaking changes to internal functions — all changes are additive optional parameters
- ✅ `Export-EntraPrivateAccessConfig.ps1` and other callers of internal functions continue to work without modification

---

## 8. Appendix

### 8.1 Related Files
- `Start-EntraPrivateAccessProvisioning.ps1` — Main provisioning function
- `internal/functions/EPA/New-IntPrivateAccessApp.ps1` — App creation (additive optional parameters only)
- `internal/functions/EPA/New-IntPrivateAccessAppSegment.ps1` — Segment creation (no changes)
- `internal/functions/EPA/Get-IntPrivateAccessApp.ps1` — App discovery (additive optional parameter only)
- `internal/functions/EPA/Get-IntPrivateAccessAppSegment.ps1` — Segment retrieval (no changes)
- `Sample-EntraPrivateAccessConfig.rename_to_csv` — Sample CSV (needs update)

### 8.2 Graph API Endpoints Used
| Operation | Method | Endpoint |
|-----------|--------|----------|
| Discover Quick Access app | GET | `/beta/applications?$filter=tags/Any(x: x eq 'NetworkAccessQuickAccessApplication')` |
| Instantiate app template | POST | `/beta/applicationTemplates/8adf8e6e-67b2-4cf2-a259-e3dc5476c621/instantiate` |
| Configure as Quick Access | PATCH | `/beta/applications/{id}/` |
| Create segment | POST | `/beta/applications/{id}/onPremisesPublishing/segmentsConfiguration/microsoft.graph.ipSegmentConfiguration/applicationSegments/` |
| Assign connector group | PUT | `/beta/applications/{id}/connectorGroup/$ref` |

### 8.3 Quick Access App Configuration Payload (Creation)
```json
{
  "onPremisesPublishing": {
    "applicationType": "quickaccessapp",
    "isAccessibleViaZTNAClient": true,
    "isDnsResolutionEnabled": true   // only true when dnsSuffix segments exist
  }
}
```

### 8.4 DNS Suffix Segment Payload
```json
{
  "destinationHost": "contoso.local",
  "destinationType": "dnsSuffix"
}
```

### 8.5 References
- [Configure Quick Access for Global Secure Access](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-quick-access)
- [Configure per-app access](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-configure-per-app-access)
- [Private DNS for Microsoft Entra Private Access](https://learn.microsoft.com/en-us/entra/global-secure-access/concept-private-name-resolution)
- [Microsoft Entra PowerShell Beta Documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.entra.beta/)

---

**End of Specification**
