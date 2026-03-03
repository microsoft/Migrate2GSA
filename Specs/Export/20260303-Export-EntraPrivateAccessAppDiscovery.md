# Export Entra Private Access App Discovery - Technical Specifications

**Version:** 1.1  
**Date:** March 4, 2026  
**Purpose:** Export Microsoft Entra Private Access App Discovery data to CSV format compatible with `Start-EntraPrivateAccessProvisioning`, enabling discovered segments to be reviewed and provisioned as proper Private Access applications.  
**Status:** Draft  
**Target Module:** Migrate2GSA  
**Function Name:** Export-EntraPrivateAccessAppDiscovery  
**Author:** Andres Canello

---

## Overview

This specification defines how to export App Discovery data from Microsoft Entra Private Access into a CSV file. App Discovery captures network traffic observed flowing through the Global Secure Access client, revealing destination hosts and ports that users are actively accessing. This data is invaluable for identifying resources that should be published as formal Private Access applications.

**Key Concept:** App Discovery returns discovered *segments* (FQDN/IP + port + protocol combinations) along with usage metrics. This function exports them into the CSV format expected by `Start-EntraPrivateAccessProvisioning`, so that an administrator can review, group segments into applications, assign connector groups and Entra groups, and then provision the applications.

**Primary Use Case - Quick Access to Named Apps:** The most valuable scenario is exporting `quickAccess` discovered segments. These represent traffic flowing through the Quick Access application (a catch-all) that should ideally be converted into dedicated named Private Access applications for better governance, segmentation, and access control.

**Scope:**
- Exports discovered application segments from the App Discovery report via Graph API
- Retrieves the list of users who accessed each discovered segment and populates the `EntraUsers` column
- Resolves the originating application ID and display name for each segment by querying traffic logs (controlled by `-ResolveAppNames`)
- Supports filtering by `accessType` (`quickAccess`, `appAccess`, or all)
- Supports configurable date range for the discovery window
- Maps discovered segment data to provisioning CSV columns
- Includes additional columns with discovery metrics (user count, device count, transaction count, bytes)
- Each discovered segment creates one row in the CSV
- Generates placeholder values for fields that require manual configuration (EnterpriseAppName, ConnectorGroup, EntraGroups)

**Output:** Timestamped CSV file in a structured folder, matching the format expected by `Start-EntraPrivateAccessProvisioning` with additional App Discovery metric columns.

---

## 1. Function Definition

### 1.1 Function Name
```powershell
Export-EntraPrivateAccessAppDiscovery
```

### 1.2 Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-OutputPath` | String | No | Current directory | Directory where timestamped backup folder will be created |
| `-DaysBack` | Int | No | `30` | Number of days back from today for the discovery report window |
| `-AccessTypeFilter` | String | No | `quickAccess` | Filter by access type: `quickAccess`, `appAccess`, or `all` |
| `-Top` | Int | No | `500` | Maximum number of records to return from the API (ordered by userCount descending) |
| `-ResolveAppNames` | Bool | No | `$true` | Resolve application ID and display name from traffic logs for each segment. When `$false`, `OriginalAppId` and `OriginalAppName` columns are still present but `OriginalAppId` is blank and `OriginalAppName` falls back to `Discovered-{host}` |
| `-LogPath` | String | No | Auto-generated | Path for log file (defaults to output folder) |

### 1.3 Parameter Validation Rules

**OutputPath:**
- If not specified, use current directory (`$PWD`)
- Must have write permissions to create subfolder
- Validate write permissions before starting export

**DaysBack:**
- Must be a positive integer between 1 and 180
- Used to compute `startDateTime` and `endDateTime` for the Graph API call
- `endDateTime` = current UTC time
- `startDateTime` = current UTC time minus `DaysBack` days

**AccessTypeFilter:**
- `ValidateSet`: `quickAccess`, `appAccess`, `all`
- Default: `quickAccess` (the primary use case)
- When `all`: omit the `accessType` filter from the API query to return both `quickAccess` and `appAccess` segments

**Top:**
- Must be a positive integer between 1 and 5000
- Passed as `$top` query parameter to the API
- Results are ordered by `userCount desc` (most-used segments first)

**ResolveAppNames:**
- Default: `$true`
- When `$true`: queries traffic logs (`/beta/networkAccess/logs/traffic`) per segment to obtain `applicationSnapshot.appId`, then batch-resolves each unique `appId` to a display name via `/beta/servicePrincipals`
- When `$false`: skips all traffic log and service principal queries; `OriginalAppId` is empty and `OriginalAppName` defaults to `Discovered-{host}`
- Adds `Application.Read.All` to the required scopes when enabled

**LogPath:**
- If not specified, automatically placed in the timestamped backup folder
- Named: `yyyyMMdd_HHmmss_Export-EPA-Discovery.log`

### 1.4 Prerequisites
- Authenticated Microsoft Graph session (via `Connect-Entra` or `Connect-MgGraph`)
- PowerShell module: `Microsoft.Graph.Authentication`
- Required permission scopes:
  - `NetworkAccess.Read.All` (for App Discovery segment report, traffic logs, and tenant status)
  - `NetworkAccessPolicy.Read.All` (for the `userReport` endpoint that retrieves per-segment user lists)
  - `Application.Read.All` (for resolving `appId` to display name via `servicePrincipals` — only required when `-ResolveAppNames` is `$true`)

**Note:** The first two scopes are always required and validated upfront via `Test-GraphConnection`. `Application.Read.All` is added to the validation when `-ResolveAppNames` is `$true`. The function will not proceed if any required scope is missing. The `userReport` endpoint requires `NetworkAccessPolicy.Read.All` (delegated only — application permissions are not supported for this endpoint).

---

## 2. Graph API Details

### 2.1 Endpoint

```
GET /beta/networkaccess/reports/getDiscoveredApplicationSegmentReport(startDateTime={startDateTime},endDateTime={endDateTime})
```

**Query Parameters:**
- `$filter`: `lastAccessDateTime ge {startDateTime} and lastAccessDateTime lt {endDateTime}` (and optionally `and accessType eq '{accessType}'`)
- `$orderby`: `userCount desc`
- `$top`: `{top}`

**Full URL example (quickAccess filter):**
```
/beta/networkaccess/reports/getDiscoveredApplicationSegmentReport(startDateTime=2026-02-01T00:00:00Z,endDateTime=2026-03-03T00:00:00Z)?$filter=lastAccessDateTime ge 2026-02-01T00:00:00Z and lastAccessDateTime lt 2026-03-03T00:00:00Z and accessType eq 'quickAccess'&$orderby=userCount desc&$top=500
```

**Full URL example (all access types):**
```
/beta/networkaccess/reports/getDiscoveredApplicationSegmentReport(startDateTime=2026-02-01T00:00:00Z,endDateTime=2026-03-03T00:00:00Z)?$filter=lastAccessDateTime ge 2026-02-01T00:00:00Z and lastAccessDateTime lt 2026-03-03T00:00:00Z&$orderby=userCount desc&$top=500
```

### 2.2 Response Entity: `discoveredApplicationSegmentReport`

The API returns a collection of `microsoft.graph.networkaccess.discoveredApplicationSegmentReport` objects:

| Property | Type | Nullable | Description |
|----------|------|----------|-------------|
| `discoveredApplicationSegmentId` | String | No | Unique identifier (base64-encoded composite of FQDN/IP + port + protocol) |
| `fqdn` | String | Yes | FQDN of the discovered destination (null if IP-based) |
| `ip` | String | Yes | IP address of the discovered destination (null if FQDN-based) |
| `port` | Int32 | No | Port number |
| `transportProtocol` | String | No | Transport protocol: `tcp` or `udp` |
| `accessType` | String | Yes | How the traffic was accessed: `quickAccess`, `privateAccess`, `appAccess` |
| `firstAccessDateTime` | DateTime | No | When this segment was first observed |
| `lastAccessDateTime` | DateTime | No | When this segment was last observed |
| `transactionCount` | Int32 | No | Total number of transactions |
| `userCount` | Int32 | No | Number of unique users |
| `deviceCount` | Int32 | No | Number of unique devices |
| `totalBytesSent` | Int64 | No | Total bytes sent |
| `totalBytesReceived` | Int64 | No | Total bytes received |

### 2.3 User Report Endpoint (Per-Segment User List)

For each discovered segment, the function calls the `userReport` endpoint to retrieve the list of users who accessed that segment. The resulting UPNs are written to the `EntraUsers` column.

**Endpoint:**
```
GET /beta/networkaccess/reports/userReport(startDateTime={startDateTime},endDateTime={endDateTime},discoveredApplicationSegmentId='{segmentId}')?$orderby=lastAccessDateTime desc&$top=50
```

**Required Scope:** `NetworkAccessPolicy.Read.All` (delegated only — application permissions not supported)

**Response Entity:** `microsoft.graph.networkaccess.user`

| Property | Type | Description |
|----------|------|-------------|
| `userId` | String | Entra user object ID |
| `userPrincipalName` | String | UPN of the user |
| `displayName` | String | Display name of the user |
| `firstAccessDateTime` | DateTime | When this user first accessed the segment |
| `lastAccessDateTime` | DateTime | When this user last accessed the segment |
| `transactionCount` | Int64 | Transaction count for this user |
| `totalBytesSent` | Int64 | Bytes sent by this user |
| `totalBytesReceived` | Int64 | Bytes received by this user |
| `trafficType` | String | Traffic type |
| `userType` | String | Type of user |

**Usage:**
- Called once per discovered segment (using the `discoveredApplicationSegmentId` from the segment report)
- The `userPrincipalName` values are collected and joined with semicolons for the `EntraUsers` column
- This call is the main source of per-call overhead; for N segments, N additional API calls are made

**Error Handling:**
- If the `userReport` call fails for a specific segment due to a transient error (timeout, 500, throttling), log a warning and leave `EntraUsers` blank for that segment
- Continue processing remaining segments on transient per-segment failures
- The required scope `NetworkAccessPolicy.Read.All` is validated upfront by `Test-GraphConnection` — a 403 at runtime is unexpected and should be logged as an error

### 2.4 Pagination

The segment report API may support `@odata.nextLink` pagination if more results exist than the `$top` value. Both helper functions use `Invoke-InternalGraphRequest` internally, which handles pagination automatically. However, since this is a function-style endpoint (not a standard collection), test pagination behavior during implementation and handle it explicitly in the helpers if needed.

The `userReport` endpoint uses `$top=50` per segment. If a segment has more than 50 users, pagination may be needed. For typical tenants this is unlikely; log a warning if the response contains `@odata.nextLink`.

### 2.5 Internal Helper Functions

Both Graph API calls are encapsulated in dedicated internal helper functions following the existing `Get-Int*` pattern. These helpers own URI construction, filtering, collection unwrapping, and return PSObjects — the calling function never builds raw URIs or calls `Invoke-InternalGraphRequest` directly.

#### 2.5.1 `Get-IntDiscoveredApplicationSegmentReport`

**File:** `Migrate2GSA/internal/functions/Get-IntDiscoveredApplicationSegmentReport.ps1`

**Purpose:** Retrieves discovered application segments from the App Discovery report.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-StartDateTime` | DateTime | Yes | — | Start of the discovery window (UTC) |
| `-EndDateTime` | DateTime | Yes | — | End of the discovery window (UTC) |
| `-AccessTypeFilter` | String | No | `$null` | Filter by access type: `quickAccess`, `appAccess`, or `$null` for all |
| `-Top` | Int | No | `500` | Maximum number of records (`$top`) |

**Behavior:**
1. Formats `StartDateTime` and `EndDateTime` to ISO 8601 with `Z` suffix
2. Builds the function-style URI: `/beta/networkaccess/reports/getDiscoveredApplicationSegmentReport(startDateTime=…,endDateTime=…)`
3. Builds `$filter` with `lastAccessDateTime` range; appends `accessType eq '{value}'` when `-AccessTypeFilter` is provided
4. Appends `$orderby=userCount desc` and `$top={Top}`
5. Calls `Invoke-InternalGraphRequest -Method GET -OutputType PSObject -Uri $uri`
6. Unwraps `.value` from collection response
7. Returns the array of PSObjects (or `$null` if empty)

**Pseudocode:**
```powershell
function Get-IntDiscoveredApplicationSegmentReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [datetime]$StartDateTime,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDateTime,

        [Parameter(Mandatory = $false)]
        [ValidateSet('quickAccess', 'appAccess')]
        [string]$AccessTypeFilter,

        [Parameter(Mandatory = $false)]
        [int]$Top = 500
    )

    process {
        try {
            $startStr = $StartDateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            $endStr = $EndDateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

            $baseUri = "/beta/networkaccess/reports/getDiscoveredApplicationSegmentReport(startDateTime=$startStr,endDateTime=$endStr)"

            # Build OData filter
            $filter = "lastAccessDateTime ge $startStr and lastAccessDateTime lt $endStr"
            if ($AccessTypeFilter) {
                $filter += " and accessType eq '$AccessTypeFilter'"
            }

            $uri = "$baseUri`?`$filter=$filter&`$orderby=userCount desc&`$top=$Top"

            $response = Invoke-InternalGraphRequest -Method GET -OutputType PSObject -Uri $uri

            if (-not $response) {
                return $null
            }

            # Unwrap collection
            if ($response.PSObject.Properties.Name -contains 'value') {
                $segments = $response.value
                if ($segments -and $segments.Count -gt 0) {
                    return $segments
                }
                return $null
            }

            return $response
        }
        catch {
            Write-Error "Failed to retrieve discovered application segment report: $_"
            throw
        }
    }
}
```

**Error Handling:**
- Throws on API failure (5xx, 403, network error) — caller handles terminating errors
- Returns `$null` on empty results

---

#### 2.5.2 `Get-IntDiscoveredApplicationSegmentUserReport`

**File:** `Migrate2GSA/internal/functions/Get-IntDiscoveredApplicationSegmentUserReport.ps1`

**Purpose:** Retrieves the list of users who accessed a specific discovered application segment.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-StartDateTime` | DateTime | Yes | — | Start of the discovery window (UTC) |
| `-EndDateTime` | DateTime | Yes | — | End of the discovery window (UTC) |
| `-DiscoveredApplicationSegmentId` | String | Yes | — | The segment ID from `Get-IntDiscoveredApplicationSegmentReport` |
| `-Top` | Int | No | `50` | Maximum number of user records (`$top`) |

**Behavior:**
1. Formats `StartDateTime` and `EndDateTime` to ISO 8601 with `Z` suffix
2. Builds the function-style URI: `/beta/networkaccess/reports/userReport(startDateTime=…,endDateTime=…,discoveredApplicationSegmentId='…')`
3. Appends `$orderby=lastAccessDateTime desc` and `$top={Top}`
4. Calls `Invoke-InternalGraphRequest -Method GET -OutputType PSObject -Uri $uri`
5. Unwraps `.value` from collection response
6. Returns the array of user PSObjects (or `$null` if empty)

**Pseudocode:**
```powershell
function Get-IntDiscoveredApplicationSegmentUserReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [datetime]$StartDateTime,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDateTime,

        [Parameter(Mandatory = $true)]
        [string]$DiscoveredApplicationSegmentId,

        [Parameter(Mandatory = $false)]
        [int]$Top = 50
    )

    process {
        try {
            $startStr = $StartDateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            $endStr = $EndDateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

            $uri = "/beta/networkaccess/reports/userReport(startDateTime=$startStr,endDateTime=$endStr,discoveredApplicationSegmentId='$DiscoveredApplicationSegmentId')?`$orderby=lastAccessDateTime desc&`$top=$Top"

            $response = Invoke-InternalGraphRequest -Method GET -OutputType PSObject -Uri $uri

            if (-not $response) {
                return $null
            }

            # Unwrap collection
            if ($response.PSObject.Properties.Name -contains 'value') {
                $users = $response.value
                if ($users -and $users.Count -gt 0) {
                    return $users
                }
                return $null
            }

            return $response
        }
        catch {
            Write-Error "Failed to retrieve user report for segment '$DiscoveredApplicationSegmentId': $_"
            throw
        }
    }
}
```

**Error Handling:**
- Throws on API failure — the caller (`Export-EntraPrivateAccessAppDiscovery`) catches transient per-segment errors
- Returns `$null` on empty results (segment with no users)

### 2.6 Traffic Log Endpoint (App ID Resolution)

The discovery report does not include the application ID (`appId`) that the traffic was routed through. To resolve this, the function queries the traffic logs for a matching entry per segment. This is controlled by the `-ResolveAppNames` parameter (default: `$true`).

**Endpoint:**
```
GET /beta/networkAccess/logs/traffic?$filter=trafficType eq 'private' and destinationFQDN eq '{fqdn}' and destinationPort eq {port} and createdDateTime ge {startDateTime} and createdDateTime le {endDateTime}&$select=applicationSnapshot&$orderby=createdDateTime desc&$top=1
```

For IP-based segments, use `destinationIp eq '{ip}'` instead of `destinationFQDN eq '{fqdn}'`.

**Required Scope:** `NetworkAccess.Read.All` (already required for the segment report)

**Response Property Used:** `applicationSnapshot.appId` — the GUID of the enterprise application registration the traffic was routed through.

**Usage:**
- Called once per discovered segment with `$top=1` for efficiency (only one matching traffic log entry is needed to obtain the `appId`)
- Uses the same date range (`DaysBack`) as the discovery report to keep the time window consistent
- The `appId` values are collected into a segment-to-appId mapping hashtable

### 2.7 Service Principal Endpoint (App Name Resolution)

After collecting unique `appId` values from the traffic logs, the function resolves each to a display name.

**Endpoint:**
```
GET /beta/servicePrincipals?$filter=appId eq '{appId}'&$select=appId,displayName&$top=1
```

**Required Scope:** `Application.Read.All`

**Response Properties Used:** `displayName` — the display name of the enterprise app.

**Usage:**
- Called once per unique `appId` (not per segment — multiple segments may share the same app)
- The resolved display names are written to the `OriginalAppName` column
- The `appId` GUID is written to the `OriginalAppId` column

**Error Handling:**
- If the traffic log query fails for a segment, log a warning and leave `OriginalAppId` empty; `OriginalAppName` falls back to `Discovered-{host}`
- If the service principal query fails for an `appId`, log a warning and leave `OriginalAppName` as `Discovered-{host}` but still populate `OriginalAppId`

---

## 3. Output Structure and Naming Convention

### 3.1 Folder Structure
```
GSA-backup_yyyyMMdd_HHmmss/
└── PrivateAccess/
    ├── yyyyMMdd_HHmmss_EPA_AppDiscovery.csv
    └── yyyyMMdd_HHmmss_Export-EPA-Discovery.log
```

**Example:**
```
GSA-backup_20260303_143022/
└── PrivateAccess/
    ├── 20260303_143022_EPA_AppDiscovery.csv
    └── 20260303_143022_Export-EPA-Discovery.log
```

### 3.2 Timestamp Format
- Format: `yyyyMMdd_HHmmss` (e.g., `20260303_143022`)
- Generated once at function start
- Used consistently for folder name, file names, and log entries

### 3.3 File Naming
- **Discovery CSV:** `{timestamp}_EPA_AppDiscovery.csv`
- **Log File:** `{timestamp}_Export-EPA-Discovery.log`

---

## 4. CSV File Format

### 4.1 Column Layout

The CSV includes all columns required by `Start-EntraPrivateAccessProvisioning` plus additional App Discovery metric columns. The provisioning-required columns come first, followed by discovery-specific columns.

**Provisioning-compatible columns (required by Start-EntraPrivateAccessProvisioning):**
```
SegmentId, OriginalAppId, OriginalAppName, EnterpriseAppName, destinationHost, DestinationType, Protocol, Ports, EntraGroups, EntraUsers, ConnectorGroup, Conflict, ConflictingEnterpriseApp, Provision, isQuickAccess
```

**Additional App Discovery metric columns:**
```
DiscoveryAccessType, FirstAccessDateTime, LastAccessDateTime, TransactionCount, UserCount, DeviceCount, TotalBytesSent, TotalBytesReceived, DiscoveredApplicationSegmentId
```

### 4.2 Column Definitions — Provisioning Columns

| Column | Source | Description |
|--------|--------|-------------|
| `SegmentId` | Auto-generated | Sequential ID: `SEG-D-000001`, `SEG-D-000002`, etc. The `D` prefix distinguishes discovery-sourced segments from other sources |
| `OriginalAppId` | Traffic logs | Application ID (GUID) from `applicationSnapshot.appId` in traffic logs. Populated when `-ResolveAppNames` is `$true` and a matching traffic log entry is found. Empty otherwise |
| `OriginalAppName` | Traffic logs / Generated | When app is resolved: enterprise app display name from `servicePrincipals` (e.g., `SRV1 SMB`, `DC RDP`). Fallback: `Discovered-{fqdn}` or `Discovered-{ip}` |
| `EnterpriseAppName` | Placeholder | `Placeholder_Review_Me` — must be manually replaced with the desired application name before provisioning |
| `destinationHost` | `fqdn` or `ip` | The discovered FQDN (if available) or IP address |
| `DestinationType` | Derived | `FQDN` if `fqdn` is non-null; `ipAddress` if `ip` is non-null |
| `Protocol` | `transportProtocol` | `TCP` or `UDP` (uppercased to match provisioning convention) |
| `Ports` | `port` | Port number as string |
| `EntraGroups` | Placeholder | `Placeholder_Replace_Me` — must be set before provisioning |
| `EntraUsers` | `userReport` API | Semicolon-separated UPNs of users who accessed this segment during the discovery window. Retrieved via the `userReport` endpoint per segment. Left blank if user resolution fails or returns no users |
| `ConnectorGroup` | Placeholder | `Placeholder_Replace_Me` — must be set before provisioning |
| `Conflict` | `No` | Always `No` for discovery exports |
| `ConflictingEnterpriseApp` | Empty | Left blank |
| `Provision` | `No` | Always `No` — requires manual review before provisioning |
| `isQuickAccess` | Derived from `accessType` | `yes` if `accessType` is `quickAccess`; `no` otherwise |

### 4.3 Column Definitions — App Discovery Metric Columns

| Column | Source | Description |
|--------|--------|-------------|
| `DiscoveryAccessType` | `accessType` | Original access type value: `quickAccess`, `appAccess`, `privateAccess` |
| `FirstAccessDateTime` | `firstAccessDateTime` | ISO 8601 timestamp of first observed access |
| `LastAccessDateTime` | `lastAccessDateTime` | ISO 8601 timestamp of last observed access |
| `TransactionCount` | `transactionCount` | Number of transactions observed |
| `UserCount` | `userCount` | Number of unique users |
| `DeviceCount` | `deviceCount` | Number of unique devices |
| `TotalBytesSent` | `totalBytesSent` | Total bytes sent |
| `TotalBytesReceived` | `totalBytesReceived` | Total bytes received |
| `DiscoveredApplicationSegmentId` | `discoveredApplicationSegmentId` | Original Graph API segment identifier (base64-encoded) |

### 4.4 Data Mapping Rules

**destinationHost:**
- If `fqdn` is non-null and non-empty: use `fqdn`
- Else if `ip` is non-null and non-empty: use `ip`
- Else: log error, skip record

**DestinationType:**
- If `fqdn` is non-null: `FQDN`
- Else if `ip` is non-null: `ipAddress`

**Protocol:**
- Convert `transportProtocol` to uppercase: `tcp` → `TCP`, `udp` → `UDP`

**Ports:**
- Convert integer `port` to string

**isQuickAccess:**
- `accessType` == `quickAccess` → `yes`
- Any other value → `no`

**EntraUsers:**
- For each segment, call `userReport` with the segment's `discoveredApplicationSegmentId`
- Collect all `userPrincipalName` values from the response
- Join with semicolons: `user1@contoso.com;user2@contoso.com`
- If the API call fails or returns no users, leave blank

**OriginalAppId:**
- When `-ResolveAppNames` is `$true`: resolved from `applicationSnapshot.appId` in traffic logs
- When `-ResolveAppNames` is `$false` or no matching traffic log entry: empty string

**OriginalAppName:**
- When `-ResolveAppNames` is `$true` and app resolved: display name from `servicePrincipals` (e.g., `SRV1 SMB`, `DC RDP`, `QA3`)
- Fallback (no match or `-ResolveAppNames $false`): `Discovered-{fqdn}` or `Discovered-{ip}`

### 4.5 Row Structure

**One row per discovered segment:**
- Each unique combination of FQDN/IP + port + protocol is one row
- The same FQDN may appear multiple times with different ports

**Example CSV:**
```csv
SegmentId,OriginalAppId,OriginalAppName,EnterpriseAppName,destinationHost,DestinationType,Protocol,Ports,EntraGroups,EntraUsers,ConnectorGroup,Conflict,ConflictingEnterpriseApp,Provision,isQuickAccess,DiscoveryAccessType,FirstAccessDateTime,LastAccessDateTime,TransactionCount,UserCount,DeviceCount,TotalBytesSent,TotalBytesReceived,DiscoveredApplicationSegmentId
SEG-D-000001,7e4bebb9-fbdd-4166-8a02-0bc2687d6b89,QA3,Placeholder_Review_Me,fed-dc1.fed.canello.net,FQDN,UDP,389,Placeholder_Replace_Me,acanello@canello.net,Placeholder_Replace_Me,No,,No,yes,quickAccess,2026-03-02T23:31:09Z,2026-03-03T00:09:34Z,32,1,1,5247,5676,eyJGcWRuIjoiZmVkLWRjMS5mZWQuY2FuZWxsby5uZXQiLCJJcCI6bnVsbCwiUG9ydCI6Mzg5LCJUcmFuc3BvcnRQcm90b2NvbCI6MTd9
SEG-D-000002,,Discovered-10.1.1.10,Placeholder_Review_Me,10.1.1.10,ipAddress,TCP,445,Placeholder_Replace_Me,acanello@canello.net,Placeholder_Replace_Me,No,,No,yes,quickAccess,2026-03-03T00:03:26Z,2026-03-03T00:03:26Z,1,1,1,3987,3991,eyJGcWRuIjpudWxsLCJJcCI6IjEwLjEuMS4xMCIsIlBvcnQiOjQ0NSwiVHJhbnNwb3J0UHJvdG9jb2wiOjZ9
```

### 4.6 Post-Export Workflow

After exporting, the administrator should:

1. **Review** the CSV and App Discovery metrics (UserCount, TransactionCount, etc.) to prioritize which segments to publish
2. **Group segments into applications** by editing the `EnterpriseAppName` column — segments sharing the same `EnterpriseAppName` will become segments of the same Private Access application
3. **Set ConnectorGroup** to the appropriate connector group name in the target tenant
4. **Set EntraGroups** to the security groups that should be granted access (semicolon-separated)
5. **Review EntraUsers** — the discovered users are pre-populated; adjust as needed for the target application
6. **Set Provision=Yes** for rows that should be provisioned
7. **Review isQuickAccess** — change to `no` if segments should become standalone named apps rather than remain in Quick Access
7. Run `Start-EntraPrivateAccessProvisioning` with the edited CSV

---

## 5. Export Process Flow

### 5.1 High-Level Flow

```
1. Validate parameters (OutputPath write permissions, DaysBack range)
2. Generate timestamp
3. Create output folder structure: GSA-backup_{timestamp}/PrivateAccess/
4. Initialize logging (set $script:LogPath)
5. Validate required PowerShell modules (Test-RequiredModules)
6. Test Graph connection with required scopes (Test-GraphConnection)
7. Validate GSA tenant onboarding status (Get-IntGSATenantStatus)
8. Compute date range from DaysBack
9. Call Get-IntDiscoveredApplicationSegmentReport to retrieve discovered segments
10. For each discovered segment, call Get-IntDiscoveredApplicationSegmentUserReport to retrieve user UPNs
11. Validate and transform each record into CSV row (including EntraUsers)
13. Write CSV file
13. Generate summary report with statistics
14. Display completion message with folder location
```

### 5.2 Detailed Export Steps

#### 5.2.1 Authentication and Validation

**Module Validation:**
```powershell
$requiredModules = @('Microsoft.Graph.Authentication')
Test-RequiredModules -RequiredModules $requiredModules
```

**Graph Connection Validation:**
```powershell
$requiredScopes = @(
    'NetworkAccess.Read.All',
    'NetworkAccessPolicy.Read.All'
)
if ($ResolveAppNames) {
    $requiredScopes += 'Application.Read.All'
}
Test-GraphConnection -RequiredScopes $requiredScopes
```

**GSA Tenant Status Validation:**
```powershell
Write-LogMessage "Validating Global Secure Access tenant onboarding status..." -Level INFO -Component "Validation"
$tenantStatus = Get-IntGSATenantStatus
if ($tenantStatus.onboardingStatus -ne 'onboarded') {
    Write-LogMessage "Global Secure Access has not been activated on this tenant. Current onboarding status: $($tenantStatus.onboardingStatus)." -Level ERROR -Component "Validation"
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

#### 5.2.2 Compute Date Range

```powershell
$endDateTime = (Get-Date).ToUniversalTime()
$startDateTime = $endDateTime.AddDays(-$DaysBack)

# Format for Graph API (ISO 8601 with Z suffix)
$startDateTimeStr = $startDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$endDateTimeStr = $endDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

Write-LogMessage "Discovery date range: $startDateTimeStr to $endDateTimeStr ($DaysBack days)" -Level INFO -Component "Discovery"
```

#### 5.2.3 Retrieve Discovered Segments

```powershell
Write-LogMessage "Retrieving discovered application segments..." -Level INFO -Component "Discovery"

$accessTypeParam = @{}
if ($AccessTypeFilter -ne 'all') {
    $accessTypeParam['AccessTypeFilter'] = $AccessTypeFilter
}

$response = Get-IntDiscoveredApplicationSegmentReport `
    -StartDateTime $startDateTime `
    -EndDateTime $endDateTime `
    -Top $Top `
    @accessTypeParam
```

**Error Handling:**
- If helper returns `$null`, create CSV with headers only and log info message
- If helper throws (API error, 5xx), log error details and re-throw as terminating error
- Scope validation is handled upfront by `Test-GraphConnection`

#### 5.2.4 Retrieve Users Per Segment

For each discovered segment, call `Get-IntDiscoveredApplicationSegmentUserReport` to get the list of users who accessed it:

```powershell
$totalSegments = $response.Count
$currentSegmentIndex = 0
$failedUserReportCount = 0

# Build a hashtable mapping discoveredApplicationSegmentId -> semicolon-separated UPNs
$segmentUserMap = @{}

foreach ($segment in $response) {
    $currentSegmentIndex++
    $segmentId = $segment.discoveredApplicationSegmentId
    
    Write-Progress -Activity "Retrieving users per segment" `
        -Status "Segment $currentSegmentIndex of $totalSegments" `
        -PercentComplete (($currentSegmentIndex / $totalSegments) * 100)
    
    try {
        $userResponse = Get-IntDiscoveredApplicationSegmentUserReport `
            -StartDateTime $startDateTime `
            -EndDateTime $endDateTime `
            -DiscoveredApplicationSegmentId $segmentId
        
        if ($userResponse -and $userResponse.Count -gt 0) {
            $upnList = ($userResponse | Where-Object { $_.userPrincipalName } | 
                        Select-Object -ExpandProperty userPrincipalName -Unique) -join ';'
            $segmentUserMap[$segmentId] = $upnList
        } else {
            $segmentUserMap[$segmentId] = ""
        }
    }
    catch {
        $failedUserReportCount++
        Write-LogMessage "Failed to retrieve users for segment $currentSegmentIndex ($segmentId): $_" -Level WARN -Component "UserReport"
        $segmentUserMap[$segmentId] = ""
    }
}

Write-Progress -Activity "Retrieving users per segment" -Completed

if ($failedUserReportCount -gt 0) {
    Write-LogMessage "User resolution failed for $failedUserReportCount of $totalSegments segments. Those segments will have empty EntraUsers." -Level WARN -Component "UserReport"
} else {
    Write-LogMessage "Successfully retrieved user data for $totalSegments segments" -Level SUCCESS -Component "UserReport"
}
```

#### 5.2.5 Transform Records to CSV Rows

```powershell
$csvRows = @()
$recordIndex = 0

foreach ($segment in $response) {
    $recordIndex++
    
    # Determine destination host and type
    $destinationHost = $null
    $destinationType = $null
    
    if (-not [string]::IsNullOrWhiteSpace($segment.fqdn)) {
        $destinationHost = $segment.fqdn
        $destinationType = 'FQDN'
    }
    elseif (-not [string]::IsNullOrWhiteSpace($segment.ip)) {
        $destinationHost = $segment.ip
        $destinationType = 'ipAddress'
    }
    else {
        Write-LogMessage "Skipping record $recordIndex: both fqdn and ip are null" -Level WARN -Component "Transform"
        continue
    }
    
    # Resolve original app ID and name from traffic logs
    $segmentId = $segment.discoveredApplicationSegmentId
    $originalAppId = ""
    $originalAppName = "Discovered-$destinationHost"
    
    if ($segmentAppIdMap.ContainsKey($segmentId)) {
        $originalAppId = $segmentAppIdMap[$segmentId]
        $resolvedName = $appIdNameMap[$originalAppId]
        if (-not [string]::IsNullOrWhiteSpace($resolvedName)) {
            $originalAppName = $resolvedName
        }
    }
    
    # Determine isQuickAccess
    $isQuickAccess = if ($segment.accessType -eq 'quickAccess') { 'yes' } else { 'no' }
    
    # Get users for this segment from the pre-fetched map
    $entraUsers = $segmentUserMap[$segment.discoveredApplicationSegmentId]
    if (-not $entraUsers) { $entraUsers = "" }
    
    # Build CSV row
    $row = [PSCustomObject]@{
        SegmentId                       = "SEG-D-{0:D6}" -f $recordIndex
        OriginalAppId                   = $originalAppId
        OriginalAppName                 = $originalAppName
        EnterpriseAppName               = "Placeholder_Review_Me"
        destinationHost                 = $destinationHost
        DestinationType                 = $destinationType
        Protocol                        = $segment.transportProtocol.ToUpper()
        Ports                           = [string]$segment.port
        EntraGroups                     = "Placeholder_Replace_Me"
        EntraUsers                      = $entraUsers
        ConnectorGroup                  = "Placeholder_Replace_Me"
        Conflict                        = "No"
        ConflictingEnterpriseApp        = ""
        Provision                       = "No"
        isQuickAccess                   = $isQuickAccess
        DiscoveryAccessType             = $segment.accessType
        FirstAccessDateTime             = $segment.firstAccessDateTime
        LastAccessDateTime              = $segment.lastAccessDateTime
        TransactionCount                = $segment.transactionCount
        UserCount                       = $segment.userCount
        DeviceCount                     = $segment.deviceCount
        TotalBytesSent                  = $segment.totalBytesSent
        TotalBytesReceived              = $segment.totalBytesReceived
        DiscoveredApplicationSegmentId  = $segment.discoveredApplicationSegmentId
    }
    
    $csvRows += $row
}
```

#### 5.2.6 Write CSV File

```powershell
if ($csvRows.Count -gt 0) {
    $csvRows | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8
    Write-LogMessage "Exported $($csvRows.Count) discovered segments to: $csvFilePath" -Level SUCCESS -Component "Export"
} else {
    # Write headers-only CSV
    [PSCustomObject]@{
        SegmentId = $null; OriginalAppId = $null; OriginalAppName = $null
        EnterpriseAppName = $null
        destinationHost = $null; DestinationType = $null; Protocol = $null
        Ports = $null
        EntraGroups = $null; EntraUsers = $null; ConnectorGroup = $null
        Conflict = $null; ConflictingEnterpriseApp = $null; Provision = $null
        isQuickAccess = $null; DiscoveryAccessType = $null
        FirstAccessDateTime = $null; LastAccessDateTime = $null
        TransactionCount = $null; UserCount = $null; DeviceCount = $null
        TotalBytesSent = $null; TotalBytesReceived = $null
        DiscoveredApplicationSegmentId = $null
    } | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8
    # Remove the data row (keep only headers)
    $headerLine = (Get-Content -Path $csvFilePath -First 1)
    Set-Content -Path $csvFilePath -Value $headerLine -Encoding UTF8
    Write-LogMessage "No discovered segments found. Created empty CSV with headers only." -Level WARN -Component "Export"
}
```

---

## 6. Error Handling and Logging

### 6.1 Error Handling Strategy

**Terminating Errors:**
- Graph authentication failure
- Insufficient permission scopes (both `NetworkAccess.Read.All` and `NetworkAccessPolicy.Read.All` are validated upfront via `Test-GraphConnection`)
- Tenant not onboarded to GSA
- Private Access not enabled
- No write permissions to output folder
- CSV export failure (disk full, permissions)
- Graph API returns server error (5xx)

**Non-Terminating (Log and Continue):**
- Individual records with both `fqdn` and `ip` null (skip record)
- Unexpected `transportProtocol` values (log warning, include as-is)
- Empty result set (create headers-only CSV)
- `userReport` call fails for a specific segment due to transient error (leave `EntraUsers` blank for that segment, continue with remaining segments)

### 6.2 Logging Requirements

**Use Internal Function:**
- `Write-LogMessage` (existing internal function)

**Log Levels:**
- `INFO`: Normal operations (parameters, date range, API call, row count)
- `WARN`: Skipped records, empty results
- `ERROR`: API failures, validation failures
- `SUCCESS`: Completed operations
- `SUMMARY`: Final statistics

### 6.3 Console Output — Summary Report

```
Export completed successfully!

Backup folder: C:\Backups\GSA-backup_20260303_143022\

Entra Private Access App Discovery:
  Discovery Window: 2026-02-01 to 2026-03-03 (30 days)
  Access Type Filter: quickAccess

  Discovered Segments: 8
    By Access Type:
      quickAccess: 3
      appAccess: 5
    By Destination Type:
      FQDN: 6
      IP Address: 2
    By Protocol:
      TCP: 6
      UDP: 2

  Usage Metrics (across all segments):
    Total Unique Users: 1
    Total Unique Devices: 1
    Total Transactions: 44
    Total Bytes Sent: 32,448
    Total Bytes Received: 27,408

  User Resolution:
    Segments with users resolved: 8
    Segments with user resolution failed: 0
    Total unique UPNs collected: 1

  App Name Resolution:
    Segments with app ID resolved: 8
    Segments with app resolution failed: 0
    Unique applications resolved: 4

  Top 5 Destinations by User Count:
    1. fed-dc1.fed.canello.net:389/udp (1 users, 32 txns)
    2. intranet.fed.canello.net:80/tcp (1 users, 4 txns)
    3. fed-srv1.fed.canello.net:445/tcp (1 users, 5 txns)
    4. fed-dc1.fed.canello.net:3389/tcp (1 users, 1 txns)
    5. 10.1.1.10:445/tcp (1 users, 1 txns)

  Records Skipped: 0
  Warnings: 0

  Next Steps:
    1. Review the CSV and edit EnterpriseAppName to group segments into apps
    2. Replace Placeholder_Replace_Me in ConnectorGroup and EntraGroups columns
    3. Review EntraUsers (pre-populated from discovery data) and adjust as needed
    4. Set Provision=Yes for rows to provision
    5. Run: Start-EntraPrivateAccessProvisioning -ProvisioningConfigPath "<csvPath>"

Files created in PrivateAccess\:
  - 20260303_143022_EPA_AppDiscovery.csv (4 KB)
  - 20260303_143022_Export-EPA-Discovery.log (3 KB)
```

---

## 7. Usage Examples

### 7.1 Basic Export (Default: Last 30 Days, Quick Access Only)
```powershell
Export-EntraPrivateAccessAppDiscovery
```
Exports `quickAccess` discovered segments from the last 30 days to `.\GSA-backup_{timestamp}\PrivateAccess\`

### 7.2 Export All Access Types
```powershell
Export-EntraPrivateAccessAppDiscovery -AccessTypeFilter all
```
Exports both `quickAccess` and `appAccess` discovered segments.

### 7.3 Custom Date Range and Output
```powershell
Export-EntraPrivateAccessAppDiscovery -DaysBack 90 -OutputPath "C:\GSA-Backups"
```
Exports last 90 days of discovery data to a custom location.

### 7.4 Export with Higher Limit
```powershell
Export-EntraPrivateAccessAppDiscovery -Top 2000 -AccessTypeFilter all
```
Retrieves up to 2000 discovered segments.

### 7.5 End-to-End Workflow: Discovery to Provisioning
```powershell
# Step 1: Export App Discovery data
Export-EntraPrivateAccessAppDiscovery -DaysBack 30

# Step 2: Review and edit the CSV
#   - Group segments into applications by setting EnterpriseAppName
#   - Set ConnectorGroup and EntraGroups
#   - Set Provision=Yes for rows to provision

# Step 3: Provision the applications
Start-EntraPrivateAccessProvisioning `
    -ProvisioningConfigPath ".\GSA-backup_20260303_143022\PrivateAccess\20260303_143022_EPA_AppDiscovery.csv"
```

---

## 8. Implementation Considerations

### 8.1 Performance

**API Call Pattern:**
- The discovery segment report is retrieved via `Get-IntDiscoveredApplicationSegmentReport` (single API call with `$top` limiting results)
- For each discovered segment, `Get-IntDiscoveredApplicationSegmentUserReport` makes one API call to retrieve user UPNs
- Total API calls: 1 (segment report) + N (user reports) + N (traffic log queries, when `-ResolveAppNames`) + M (service principal queries, one per unique `appId`)
- Pagination handling via `Invoke-InternalGraphRequest` (used internally by both helpers) if response exceeds `$top`
- Traffic log queries use `$top=1` and `-DisablePagination` for efficiency

**Expected Performance:**
- Segment report: < 5 seconds
- User resolution: ~1-2 seconds per segment (N segments = N API calls)
- App ID resolution: ~1-2 seconds per segment (N traffic log queries) + ~1 second per unique app (M service principal queries)
- For 50 segments with 10 unique apps: ~120-200 seconds total
- Progress indicator shown during user resolution phase
- If `NetworkAccessPolicy.Read.All` scope is missing, `Test-GraphConnection` will fail the export upfront before any API calls are made

### 8.2 API Considerations

**Function-Style Endpoint:**
- This is a Graph function endpoint (uses parentheses syntax), not a standard collection endpoint
- The `startDateTime` and `endDateTime` are function parameters, not query parameters
- The `$filter`, `$orderby`, and `$top` are standard OData query parameters applied to the function result

**Pagination:**
- The API may or may not support `@odata.nextLink` for this function endpoint
- If pagination is not supported, the `$top` parameter is the only way to control result count
- Test pagination behavior inside both helper functions during implementation
- If pagination is not supported natively, document the `$top` limit as the maximum retrievable count per call

**Date Format:**
- The API expects ISO 8601 format with `Z` suffix for UTC: `2026-03-03T00:18:49.586Z`
- Both function parameters (`startDateTime`, `endDateTime`) and filter values use the same format

### 8.3 Testing Strategy

**Unit Tests:**
- Parameter validation (DaysBack range, AccessTypeFilter values)
- Date computation logic
- Record transformation (FQDN vs IP, protocol casing, isQuickAccess derivation)
- Edge cases: null fqdn and ip, unexpected protocol values

**Integration Tests:**
- Export from test tenant with known App Discovery data
- Verify CSV format matches provisioning expectations
- Load exported CSV into `Start-EntraPrivateAccessProvisioning` with `-WhatIf`
- Test with different AccessTypeFilter values

**Edge Cases:**
- No App Discovery data in tenant (verify headers-only CSV)
- All segments are FQDN-based (no IP segments)
- All segments are IP-based (no FQDN segments)
- Very large result sets (> 1000 segments — many userReport calls)
- Segments with port 0 or unusual protocols
- Transient API error on individual `userReport` call (leave EntraUsers blank for that segment)
- Traffic log returns no matching entry for a segment (OriginalAppId empty, OriginalAppName falls back)
- Service principal not found for a resolved appId (OriginalAppId populated, OriginalAppName falls back)
- `-ResolveAppNames $false` (columns present but OriginalAppId blank, OriginalAppName = Discovered-{host})
- Segment with many users (> 50 — test pagination on userReport)
- Users deleted between access time and export time (UPN may be stale)

### 8.4 Dependencies

**Required Internal Functions (Existing):**
- `Invoke-InternalGraphRequest` — Graph API wrapper with throttling/retry logic
- `Write-LogMessage` — Logging utility
- `Test-RequiredModules` — Module validation
- `Test-GraphConnection` — Graph authentication validation
- `Get-IntGSATenantStatus` — Tenant onboarding check
- `Get-IntNetworkAccessForwardingProfile` — Private Access feature check

**New Internal Functions (Defined in Section 2.5):**
- `Get-IntDiscoveredApplicationSegmentReport` — Retrieves discovered application segments from the App Discovery report. Encapsulates URI construction, OData filtering, and collection unwrapping. Returns PSObjects.
- `Get-IntDiscoveredApplicationSegmentUserReport` — Retrieves per-segment user list from the userReport endpoint. Encapsulates URI construction and collection unwrapping. Returns user PSObjects.

Both new helpers call `Invoke-InternalGraphRequest` internally — the export function never builds raw Graph URIs.

**PowerShell Modules:**
- `Microsoft.Graph.Authentication` (for Graph session)

---

## 9. Success Criteria

### 9.1 Functional Requirements
- [ ] Validate required modules (`Microsoft.Graph.Authentication`)
- [ ] Validate Graph connection with `NetworkAccess.Read.All` and `NetworkAccessPolicy.Read.All` scopes
- [ ] Validate GSA tenant onboarding status
- [ ] Validate Private Access feature is enabled
- [ ] Compute date range from `DaysBack` parameter
- [ ] Build correct Graph API URL with function parameters and OData query
- [ ] Retrieve discovered segments via Graph API
- [ ] Transform API response to provisioning-compatible CSV format
- [ ] Include App Discovery metric columns alongside provisioning columns
- [ ] Generate sequential `SegmentId` values with `SEG-D-` prefix
- [ ] Correctly derive `destinationHost`, `DestinationType`, `Protocol`, `isQuickAccess`
- [ ] Populate `EntraUsers` from `userReport` API per segment (semicolon-separated UPNs)
- [ ] Resolve `OriginalAppId` from traffic logs and `OriginalAppName` from service principals (when `-ResolveAppNames`)
- [ ] Gracefully handle traffic log and service principal resolution failures without failing the export
- [ ] Gracefully handle `userReport` failures (missing scope, API errors) without failing the export
- [ ] Set appropriate placeholder values for `EnterpriseAppName`, `ConnectorGroup`, `EntraGroups`
- [ ] Create timestamped backup folder structure
- [ ] Write CSV file with `Export-Csv`
- [ ] Generate comprehensive log file
- [ ] Display summary report with usage statistics
- [ ] Handle empty results gracefully (headers-only CSV)
- [ ] Handle records with null FQDN and null IP (skip with warning)

### 9.2 Quality Requirements
- [ ] Exported CSV can be loaded by `Start-EntraPrivateAccessProvisioning` (after editing placeholders)
- [ ] CSV columns match sample CSV column order and naming
- [ ] Additional metric columns do not interfere with provisioning (extra columns are ignored by `Start-EntraPrivateAccessProvisioning`)
- [ ] No data loss during export
- [ ] Proper CSV escaping for special characters
- [ ] Performance: Export completes in reasonable time (< 15 seconds without user resolution, proportional to segment count with user resolution)

### 9.3 Documentation Requirements
- [ ] Complete function documentation (comment-based help with Synopsis, Description, Parameters, Examples)
- [ ] Parameter descriptions with validation ranges
- [ ] Post-export workflow documentation
- [ ] End-to-end usage example (discovery → edit → provision)

---

## 10. Implementation Phases

### Phase 1: Scaffolding and Validation
1. Create function skeleton with parameters and `[CmdletBinding()]`
2. Implement parameter validation (`ValidateRange`, `ValidateSet`)
3. Create output folder structure with timestamp
4. Initialize logging
5. Call `Test-RequiredModules`, `Test-GraphConnection`, `Get-IntGSATenantStatus`
6. Validate Private Access is enabled

### Phase 2: Core Export
1. Compute date range from `DaysBack`
2. Implement `Get-IntDiscoveredApplicationSegmentReport` helper
3. Call helper to retrieve discovered segments
4. Handle empty results (headers-only CSV)

### Phase 3: User Resolution
1. Implement `Get-IntDiscoveredApplicationSegmentUserReport` helper
2. For each discovered segment, call helper with `discoveredApplicationSegmentId`
2. Collect `userPrincipalName` values and join with semicolons
3. Build segment-to-users mapping hashtable
4. Handle transient per-segment `userReport` failures gracefully (log warning, leave `EntraUsers` blank for that segment)
5. Show progress indicator during user resolution

### Phase 3.5: App Name Resolution (ResolveAppNames)
1. For each segment, query `/beta/networkAccess/logs/traffic` with FQDN/IP + port + date range + `$top=1` to obtain `applicationSnapshot.appId`
2. Build segment-to-appId mapping hashtable
3. Collect unique `appId` values and batch-resolve via `/beta/servicePrincipals` to get display names
4. Build appId-to-displayName mapping hashtable
5. Handle transient per-segment traffic log failures gracefully (log warning, leave `OriginalAppId` empty)
6. Handle service principal resolution failures gracefully (log warning, keep `OriginalAppId` but leave `OriginalAppName` as fallback)
7. Show progress indicator during resolution

### Phase 4: Data Transformation
1. Transform API response records to CSV rows
2. Map `fqdn`/`ip` → `destinationHost` + `DestinationType`
3. Generate sequential `SegmentId` values
4. Populate `OriginalAppId` and `OriginalAppName` from app resolution maps (or fallback values)
5. Populate `EntraUsers` from segment-to-users map
6. Set placeholder values for provisioning columns
7. Include App Discovery metric columns

### Phase 5: Output and Reporting
1. Write CSV using `Export-Csv`
2. Build summary statistics (segments by type, protocol, top destinations)
3. Display completion message with next steps
4. Close logging

### Phase 6: Testing and Polish
1. Test with live tenant data
2. Verify CSV compatibility with `Start-EntraPrivateAccessProvisioning -WhatIf`
3. Test edge cases (empty results, IP-only segments, large datasets)
4. Finalize comment-based help

---

## 11. Appendix

### 11.1 Graph API Reference

**App Discovery Segment Report:**
```
GET /beta/networkaccess/reports/getDiscoveredApplicationSegmentReport(startDateTime={startDateTime},endDateTime={endDateTime})?$filter=...&$orderby=userCount desc&$top=500
```
**Required Scope:** `NetworkAccess.Read.All`  
**OData Type:** `microsoft.graph.networkaccess.discoveredApplicationSegmentReport`

**Traffic Log (app ID resolution, per segment):**
```
GET /beta/networkAccess/logs/traffic?$filter=trafficType eq 'private' and destinationFQDN eq '{fqdn}' and destinationPort eq {port} and createdDateTime ge {startDateTime} and createdDateTime le {endDateTime}&$select=applicationSnapshot&$orderby=createdDateTime desc&$top=1
```
**Required Scope:** `NetworkAccess.Read.All`  
**Key Property:** `applicationSnapshot.appId`

**Service Principal (app name resolution, per unique appId):**
```
GET /beta/servicePrincipals?$filter=appId eq '{appId}'&$select=appId,displayName&$top=1
```
**Required Scope:** `Application.Read.All`  
**Key Property:** `displayName`

**User Report (per segment):**
```
GET /beta/networkaccess/reports/userReport(startDateTime={startDateTime},endDateTime={endDateTime},discoveredApplicationSegmentId='{segmentId}')?$orderby=lastAccessDateTime desc&$top=50
```
**Required Scope:** `NetworkAccessPolicy.Read.All` (delegated only)  
**OData Type:** `microsoft.graph.networkaccess.user`  
**Key Properties:** `userPrincipalName`, `userId`, `displayName`, `lastAccessDateTime`, `transactionCount`

**Usage Profiling (informational — NOT used by this function):**
```
GET /beta/networkaccess/reports/usageProfiling(startDateTime={startDateTime},endDateTime={endDateTime},aggregatedBy='users',discoveredApplicationSegmentId='{segmentId}')
```
**Note:** This endpoint returns a time-series summary (daily user counts), not individual user identities. It is NOT used by this export function. Documented here for reference only.

### 11.2 Sample Tenant Response (March 3, 2026)

The following data was retrieved from the tenant during spec exploration:

```json
{
  "@odata.context": "https://graph.microsoft.com/beta/$metadata#Collection(microsoft.graph.networkaccess.discoveredApplicationSegmentReport)",
  "value": [
    {
      "discoveredApplicationSegmentId": "eyJGcWRu...",
      "fqdn": "fed-dc1.fed.canello.net",
      "ip": null,
      "port": 389,
      "transportProtocol": "udp",
      "accessType": "quickAccess",
      "firstAccessDateTime": "2026-03-02T23:31:09Z",
      "lastAccessDateTime": "2026-03-03T00:09:34Z",
      "transactionCount": 32,
      "userCount": 1,
      "deviceCount": 1,
      "totalBytesSent": 5247,
      "totalBytesReceived": 5676
    },
    {
      "discoveredApplicationSegmentId": "eyJGcWRu...",
      "fqdn": null,
      "ip": "10.1.1.10",
      "port": 445,
      "transportProtocol": "tcp",
      "accessType": "quickAccess",
      "firstAccessDateTime": "2026-03-03T00:03:26Z",
      "lastAccessDateTime": "2026-03-03T00:03:26Z",
      "transactionCount": 1,
      "userCount": 1,
      "deviceCount": 1,
      "totalBytesSent": 3987,
      "totalBytesReceived": 3991
    },
    {
      "discoveredApplicationSegmentId": "eyJGcWRu...",
      "fqdn": "fed-dc1.fed.canello.net",
      "ip": null,
      "port": 3389,
      "transportProtocol": "tcp",
      "accessType": "appAccess",
      "firstAccessDateTime": "2026-03-02T23:37:00Z",
      "lastAccessDateTime": "2026-03-02T23:37:00Z",
      "transactionCount": 1,
      "userCount": 1,
      "deviceCount": 1,
      "totalBytesSent": 1661,
      "totalBytesReceived": 1460
    },
    {
      "discoveredApplicationSegmentId": "eyJGcWRu...",
      "fqdn": "intranet.fed.canello.net",
      "ip": null,
      "port": 80,
      "transportProtocol": "tcp",
      "accessType": "appAccess",
      "firstAccessDateTime": "2026-03-02T23:31:47Z",
      "lastAccessDateTime": "2026-03-02T23:32:03Z",
      "transactionCount": 4,
      "userCount": 1,
      "deviceCount": 1,
      "totalBytesSent": 15922,
      "totalBytesReceived": 1900
    },
    {
      "discoveredApplicationSegmentId": "eyJGcWRu...",
      "fqdn": "fed-dc1.fed.canello.net",
      "ip": null,
      "port": 445,
      "transportProtocol": "tcp",
      "accessType": "appAccess",
      "firstAccessDateTime": "2026-03-02T23:32:01Z",
      "lastAccessDateTime": "2026-03-02T23:32:46Z",
      "transactionCount": 2,
      "userCount": 1,
      "deviceCount": 1,
      "totalBytesSent": 1544,
      "totalBytesReceived": 1481
    },
    {
      "discoveredApplicationSegmentId": "eyJGcWRu...",
      "fqdn": "fed-srv1.fed.canello.net",
      "ip": null,
      "port": 445,
      "transportProtocol": "tcp",
      "accessType": "appAccess",
      "firstAccessDateTime": "2026-03-02T23:32:06Z",
      "lastAccessDateTime": "2026-03-03T00:03:39Z",
      "transactionCount": 5,
      "userCount": 1,
      "deviceCount": 1,
      "totalBytesSent": 3526,
      "totalBytesReceived": 2637
    },
    {
      "discoveredApplicationSegmentId": "eyJGcWRu...",
      "fqdn": "fed-dc1.fed.canello.net",
      "ip": null,
      "port": 443,
      "transportProtocol": "udp",
      "accessType": "quickAccess",
      "firstAccessDateTime": "2026-03-02T23:32:55Z",
      "lastAccessDateTime": "2026-03-02T23:37:35Z",
      "transactionCount": 2,
      "userCount": 1,
      "deviceCount": 1,
      "totalBytesSent": 0,
      "totalBytesReceived": 9760
    },
    {
      "discoveredApplicationSegmentId": "eyJGcWRu...",
      "fqdn": "intranet.fed.canello.net",
      "ip": null,
      "port": 443,
      "transportProtocol": "tcp",
      "accessType": "appAccess",
      "firstAccessDateTime": "2026-03-02T23:31:43Z",
      "lastAccessDateTime": "2026-03-02T23:31:43Z",
      "transactionCount": 2,
      "userCount": 1,
      "deviceCount": 1,
      "totalBytesSent": 4078,
      "totalBytesReceived": 4740
    }
  ]
}
```

### 11.3 accessType Values

| Value | Description | Primary Use Case |
|-------|-------------|------------------|
| `quickAccess` | Traffic flowing through the Quick Access (catch-all) application | **Primary target** — segments that should be promoted to named Private Access apps |
| `appAccess` | Traffic flowing through a defined Private Access application | Useful for auditing existing app coverage and identifying missing segments |
| `privateAccess` | Other private access traffic | May indicate traffic not yet categorized |

### 11.4 Relationship to Existing Export Functions

| Function | Purpose | Data Source |
|----------|---------|-------------|
| `Export-EntraPrivateAccessConfig` | Exports existing PA app definitions and segments | Graph: `/beta/applications` (configured apps) |
| **`Export-EntraPrivateAccessAppDiscovery`** | **Exports discovered traffic patterns** | **Graph: `/beta/networkaccess/reports/getDiscoveredApplicationSegmentReport`** |

The two functions are complementary:
- `Export-EntraPrivateAccessConfig` exports **what is configured** (existing apps and segments)
- `Export-EntraPrivateAccessAppDiscovery` exports **what is observed** (actual traffic patterns)

Used together, administrators can compare configured apps vs. observed traffic to identify gaps in Private Access coverage.

---

## References

- [Start-EntraPrivateAccessProvisioning Function](../../Migrate2GSA/functions/GSA/Start-EntraPrivateAccessProvisioning.ps1)
- [Export-EntraPrivateAccessConfig Specification](./20260203-Export-EntraPrivateAccessConfig.md)
- [Sample EPA Provisioning CSV](../../Samples/Sample-EntraPrivateAccessConfig.rename_to_csv)
- [Microsoft Graph API — Network Access Reports](https://learn.microsoft.com/en-us/graph/api/resources/networkaccess-reports-overview)
