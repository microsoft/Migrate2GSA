# Specification: Convert-NPA2EPA Function

**Date**: October 30, 2025  
**Author**: Andres Canello  
**Status**: Draft  
**Version**: 1.0

---

## 1. Overview

### 1.1 Purpose
The `Convert-NPA2EPA` function converts Netskope Private Access (NPA) configuration to Microsoft Entra Private Access (EPA) format. It processes private applications and access policies from Netskope exports and generates a CSV file compatible with the `Start-EntraPrivateAccessProvisioning` function.

### 1.2 Code Reuse Requirement
**⚠️ IMPORTANT: This function MUST reuse significant portions of code from `Convert-ZPA2EPA.ps1` (#file:Convert-ZPA2EPA.ps1)**

The implementation should leverage the existing, tested codebase including:
- **All conflict detection logic** and data structures (`$ipRangeToProtocolToPorts`, `$hostToProtocolToPorts`, `$dnsSuffixes`)
- **Helper functions** for IP/CIDR processing, range overlap detection, destination type detection
- **Logging infrastructure** (`Write-LogMessage` with INFO, WARN, ERROR, SUCCESS, DEBUG, SUMMARY levels)
- **Progress reporting** (`Write-ProgressUpdate` with ETA calculation)
- **CSV export** functionality with UTF-8 BOM encoding
- **Overall code structure** and processing flow patterns

See Section 11.1 for the complete list of functions to reuse from `Convert-ZPA2EPA.ps1`.

### 1.3 Scope
- **Input**: Netskope NPA configuration exports (JSON format)
  - `private_apps.json` - Private application definitions with hosts, protocols, and ports
  - `npa_policies.json` - Access policies with user and group assignments
- **Output**: CSV file with GSA Enterprise Application configuration
- **Features**: 
  - Conflict detection for overlapping IP ranges, FQDNs, protocols, and ports
  - User and group access mapping
  - Filtering capabilities (include/exclude patterns)
  - Policy validation and filtering

### 1.4 Key Differences from ZPA Conversion
| Aspect | ZPA (Convert-ZPA2EPA) | NPA (Convert-NPA2EPA) |
|--------|----------------------|----------------------|
| **App Definition** | Application Segments | Private Apps |
| **Grouping** | Segment Groups | None (flat structure) |
| **Protocols** | Per-segment definition | Array in private app |
| **Policy Model** | Complex (AND/OR operators, negation) | Simple (allow/deny only) |
| **Group Format** | SCIM group IDs | X500 paths (AD format) |
| **User Format** | SCIM user IDs | Email addresses (UPNs) |

---

## 2. Input File Structures

### 2.1 Private Apps JSON Structure

```json
{
  "data": {
    "private_apps": [
      {
        "app_id": 123,
        "app_name": "[Finance Portal]",
        "host": "finance.fabrikam.com,fin-app.fabrikam.com,10.50.100.10/32",
        "protocols": [
          {
            "id": 456,
            "port": "443",
            "transport": "tcp",
            "created_at": "2024-01-15T10:30:00.000Z",
            "updated_at": "2024-01-15T10:30:00.000Z",
            "service_id": 123
          },
          {
            "id": 457,
            "port": "8443",
            "transport": "tcp",
            "created_at": "2024-01-15T10:30:00.000Z",
            "updated_at": "2024-01-15T10:30:00.000Z",
            "service_id": 123
          }
        ],
        "policies": [
          "[NPA] Finance Users"
        ],
        "service_publisher_assignments": [
          {
            "publisher_id": 1,
            "publisher_name": "PUBLISHER01",
            "primary": null,
            "service_id": 123,
            "reachability": null
          }
        ],
        "clientless_access": false,
        "use_publisher_dns": true,
        "trust_self_signed_certs": false
      }
    ]
  },
  "status": "success",
  "total": 1
}
```

**Key Fields**:
- `app_name`: Application name (may include brackets `[...]`)
- `host`: Comma-separated list of FQDNs, IP addresses, or CIDR ranges
- `protocols[]`: Array of protocol objects
  - `port`: Port number (string)
  - `transport`: Protocol type (`tcp`, `udp`)
- `policies[]`: Array of policy names that reference this app

### 2.2 NPA Policies JSON Structure

```json
[
  {
    "rule_id": "42",
    "rule_name": "[NPA] Finance Users",
    "enabled": "1",
    "policy_type": "private-app",
    "modify_by": "admin@fabrikam.com",
    "modify_time": "2024-08-15 14:30:00",
    "modify_type": "Edited",
    "rule_data": {
      "policy_type": "private-app",
      "json_version": 3,
      "version": 2,
      "access_method": ["Client"],
      "match_criteria_action": {
        "action_name": "allow"
      },
      "privateApps": [
        "[Finance Portal]"
      ],
      "userType": "user",
      "userGroups": [
        "fabrikam.com/Groups/Application Security/Finance/APP Finance Users",
        "fabrikam.com/Groups/Security/Finance Admins"
      ],
      "userGroupObjects": [
        {
          "id": "2947",
          "name": "fabrikam.com/Groups/Application Security/Finance/APP Finance Users",
          "disabled": ""
        },
        {
          "id": "2948",
          "name": "fabrikam.com/Groups/Security/Finance Admins",
          "disabled": ""
        }
      ],
      "users": [
        "john.smith@fabrikam.com",
        "jane.doe@fabrikam.com"
      ],
      "external_dlp": false,
      "show_dlp_profile_action_table": false
    }
  }
]
```

**Key Fields**:
- `enabled`: "1" = enabled, "0" = disabled
- `rule_data.match_criteria_action.action_name`: "allow" or "deny"
- `rule_data.privateApps[]`: Private app names referenced by this policy
- `rule_data.userGroups[]`: X500 paths to AD groups
- `rule_data.users[]`: User email addresses (UPNs)

---

## 3. Transformation Logic

### 3.1 Private App to Enterprise Application Mapping

#### 3.1.1 Application Name Processing
- **Strip brackets**: `[Finance Portal]` → `Finance Portal`
- **Clean whitespace**: Trim leading/trailing spaces
- **Prefix `GSA-`**: Ensure output names start with `GSA-`; do not duplicate the prefix if it already exists
- **Validation**: Ensure unique application names

#### 3.1.2 Host to Segment Expansion
Each comma-separated host becomes a separate segment:

**Input**:
```json
"host": "finance.fabrikam.com,fin-app.fabrikam.com,10.50.100.10/32"
```

**Output**: 3 base segments (before protocol multiplication)

#### 3.1.3 Protocol and Port Processing

**Rule**: Combine ports only when transport protocol is the same.

**Example 1 - Same Transport (Combine Ports)**:
```json
"protocols": [
  {"port": "80", "transport": "tcp"},
  {"port": "443", "transport": "tcp"}
]
```
**Result**: Single segment per host with ports `"80,443"`

**Example 2 - Different Transport (Separate Segments)**:
```json
"protocols": [
  {"port": "80", "transport": "udp"},
  {"port": "443", "transport": "tcp"}
]
```
**Result**: Two segments per host:
- Segment 1: `udp/80`
- Segment 2: `tcp/443`

**Example 3 - Mixed Transports (Group by Transport)**:
```json
"protocols": [
  {"port": "53", "transport": "udp"},
  {"port": "53", "transport": "tcp"},
  {"port": "443", "transport": "tcp"}
]
```
**Result**: Two segments per host:
- Segment 1: `udp/53`
- Segment 2: `tcp/53,443`

#### 3.1.4 Segment ID Generation
Format: `{AppName}-Segment-{###}`

**Example**:
- `Finance Portal-Segment-001`
- `Finance Portal-Segment-002`
- `Finance Portal-Segment-003`

Sequential numbering per application, zero-padded to 3 digits.

#### 3.1.5 Destination Type Detection

| Input Format | DestinationType | Detection Logic |
|-------------|-----------------|-----------------|
| `finance.fabrikam.com` | `fqdn` | Contains letters and dots, no `/` |
| `*.fabrikam.com` | `fqdn` | Wildcard domain |
| `10.50.100.10` | `ipAddress` | Dotted decimal, no `/` |
| `10.50.100.0/24` | `ipRangeCidr` | Contains `/` with prefix length |
| `10.50.100.10/32` | `ipRangeCidr` | Single IP in CIDR notation |

### 3.2 Policy to Access Assignment Mapping

#### 3.2.1 Policy Filtering Rules
Skip policies if:
1. `enabled` = "0" (disabled)
2. `rule_data.match_criteria_action.action_name` = "deny"
3. `rule_data.privateApps[]` is empty or missing
4. `rule_data` is missing required fields

Process only policies where:
- `enabled` = "1"
- `action_name` = "allow"

#### 3.2.2 User Group Parsing
Extract group name from X500 path (last segment after final `/`):

**Input**:
```
fabrikam.com/Groups/Application Security/Finance/APP Finance Users
```

**Parsing Logic**:
1. Split by `/`
2. Take last element
3. Trim whitespace

**Output**:
```
APP Finance Users
```

**Edge Cases**:
- Empty string → Skip
- Single segment (no `/`) → Use as-is
- Trailing `/` → Handle gracefully

#### 3.2.3 User Processing
Keep email addresses as-is (UPN format):

**Input**:
```json
"users": [
  "john.smith@fabrikam.com",
  "jane.doe@fabrikam.com"
]
```

**Output** (semicolon-separated):
```
john.smith@fabrikam.com;jane.doe@fabrikam.com
```

#### 3.2.4 Access Aggregation
For each private app:
1. Find all policies that reference it (match `privateApps[]`)
2. Aggregate all `userGroups` from matching policies
3. Aggregate all `users` from matching policies
4. Deduplicate (case-insensitive for groups, case-sensitive for users)
5. Assign to all segments of that application

**Example**:
- Policy 1: Groups = ["Finance Users"], Users = ["john@fabrikam.com"]
- Policy 2: Groups = ["Finance Admins"], Users = ["jane@fabrikam.com", "john@fabrikam.com"]
- **Result**: Groups = "Finance Users;Finance Admins", Users = "john@fabrikam.com;jane@fabrikam.com"

### 3.3 Apps with No Valid Policies
Private apps fall into the following categories:

#### 3.3.1 Apps Not Referenced in Any Valid Policy
Private apps with empty `policies[]` array, not referenced in any policy, or only referenced in disabled/deny policies:
- **Include** in output
- **EntraGroups**: Empty
- **EntraUsers**: Empty
- **Provision**: No
- **Notes**: "App excluded from provisioning - no policy references found"

**Rationale**: Apps not referenced in any valid (enabled "allow") policy cannot be accessed by any users in the source system, so they should not be provisioned in the target system. Administrators can review the Notes field, assign appropriate access, and change Provision to "Yes" if needed.

#### 3.3.2 Apps Referenced in Policies with Empty User/Group Assignments
Private apps referenced in enabled "allow" policies that have empty `userGroups` and `users` arrays:
- **Include** in output
- **EntraGroups**: Empty
- **EntraUsers**: Empty  
- **Provision**: Yes
- **Notes**: Empty

**Rationale**: In Netskope, empty user/group arrays in an enabled "allow" policy means **all users** can access the application. These apps should be provisioned. The empty EntraGroups/EntraUsers fields indicate that administrators should manually assign appropriate Entra ID groups/users during or after provisioning, as "all users" access is not directly translatable to Entra Private Access.

### 3.4 Apps with Empty Protocols Array
Private apps with `protocols[]` = `[]`:
- **Log warning**: "Private app '{AppName}' has no protocols defined. Skipping."
- **Skip entirely** (do not include in output)
- **Increment skipped app counter**

---

## 4. Conflict Detection

### 4.1 Overview
**Reuse the conflict detection implementation from `Convert-ZPA2EPA.ps1` (#file:Convert-ZPA2EPA.ps1):**
- IP range overlaps with same protocol/port
- FQDN exact matches with same protocol/port
- Wildcard domain overlaps with same protocol/port

**Implementation Note:** Copy the conflict detection code directly from `Convert-ZPA2EPA.ps1` including the data structures and helper functions (`Convert-CIDRToRange`, `Convert-IPToInteger`, `Test-IntervalOverlap`, `Test-PortRangeOverlap`).

### 4.2 Detection Algorithm
**Note:** These data structures and algorithms are already implemented in `Convert-ZPA2EPA.ps1` and should be reused as-is.

#### 4.2.1 Data Structures
```powershell
$ipRangeToProtocolToPorts = @{}      # IP ranges -> protocols -> ports -> app info
$hostToProtocolToPorts = @{}         # FQDNs -> protocols -> ports -> app info
$dnsSuffixes = @{}                   # Wildcard domains -> protocols -> ports -> app info
```

#### 4.2.2 IP Range Conflict Detection
1. Convert CIDR to integer range (start/end)
2. For each existing range with same protocol/port:
   - Check if ranges overlap: `max(start1, start2) <= min(end1, end2)`
3. If overlap found:
   - Set `Conflict` = "Yes"
   - Set `ConflictingEnterpriseApp` = conflicting segment's SegmentId

#### 4.2.3 FQDN Conflict Detection
1. Exact match: `host1 == host2` with same protocol/port
2. Wildcard match: 
   - `*.fabrikam.com` conflicts with `app.fabrikam.com`
   - `*.fabrikam.com` conflicts with `*.fabrikam.com`

#### 4.2.4 Conflict Resolution Recommendations
Add to output log:
```
CONFLICT: Application 'Finance Portal' segment 'finance.fabrikam.com:443' 
         conflicts with 'HR Portal' segment 'finance.fabrikam.com:443'
         Recommendation: Use different ports or consolidate applications
```

---

## 5. Output Format

### 5.1 CSV Structure

**Columns** (in order):
1. `EnterpriseAppName` - Application name (brackets stripped, forced `GSA-` prefix)
2. `SegmentId` - Unique segment identifier
3. `destinationHost` - FQDN, IP, or CIDR
4. `DestinationType` - `fqdn`, `ipAddress`, or `ipRangeCidr`
5. `Protocol` - `tcp` or `udp`
6. `Ports` - Comma-separated port list (e.g., "443" or "80,443")
7. `ConnectorGroup` - Always `Placeholder_Replace_Me`
8. `Provision` - `Yes` or `No` (No if no valid policies or conflicts detected)
9. `Notes` - Explanation for Provision=No (empty if Provision=Yes)
10. `EntraGroups` - Semicolon-separated group names (parsed from X500)
11. `EntraUsers` - Semicolon-separated user emails
12. `Conflict` - `Yes` or `No`
13. `ConflictingEnterpriseApp` - SegmentId of conflicting segment (if any)

### 5.2 Example Output

#### Example 1: Simple App with Mixed Protocols
**Input** (Private App):
```json
{
  "app_name": "[HR Portal]",
  "host": "hr.fabrikam.com,hrapp.fabrikam.com",
  "protocols": [
    {"port": "80", "transport": "tcp"},
    {"port": "443", "transport": "tcp"}
  ],
  "policies": ["[NPA] HR Users"]
}
```

**Input** (Policy):
```json
{
  "rule_name": "[NPA] HR Users",
  "enabled": "1",
  "rule_data": {
    "action_name": "allow",
    "privateApps": ["[HR Portal]"],
    "userGroups": ["fabrikam.com/Groups/HR/HR Users"],
    "users": ["alice@fabrikam.com"]
  }
}
```

**Output CSV**:
```csv
EnterpriseAppName,SegmentId,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup,Provision,Notes,EntraGroups,EntraUsers,Conflict,ConflictingEnterpriseApp
GSA-HR Portal,HR Portal-Segment-001,hr.fabrikam.com,fqdn,tcp,"80,443",Placeholder_Replace_Me,Yes,,HR Users,alice@fabrikam.com,No,
GSA-HR Portal,HR Portal-Segment-002,hrapp.fabrikam.com,fqdn,tcp,"80,443",Placeholder_Replace_Me,Yes,,HR Users,alice@fabrikam.com,No,
```

#### Example 2: Mixed IP/FQDN with Different Transports
**Input** (Private App):
```json
{
  "app_name": "[Database Server]",
  "host": "10.50.10.100/32,db.fabrikam.com",
  "protocols": [
    {"port": "1433", "transport": "tcp"},
    {"port": "1434", "transport": "udp"}
  ],
  "policies": ["[NPA] Database Access"]
}
```

**Input** (Policy):
```json
{
  "rule_name": "[NPA] Database Access",
  "enabled": "1",
  "rule_data": {
    "action_name": "allow",
    "privateApps": ["[Database Server]"],
    "userGroups": [
      "fabrikam.com/IT/Database Admins",
      "fabrikam.com/IT/Database Developers"
    ],
    "users": []
  }
}
```

**Output CSV**:
```csv
EnterpriseAppName,SegmentId,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup,Provision,Notes,EntraGroups,EntraUsers,Conflict,ConflictingEnterpriseApp
GSA-Database Server,Database Server-Segment-001,10.50.10.100/32,ipRangeCidr,tcp,1433,Placeholder_Replace_Me,Yes,,"Database Admins;Database Developers",,No,
GSA-Database Server,Database Server-Segment-002,10.50.10.100/32,ipRangeCidr,udp,1434,Placeholder_Replace_Me,Yes,,"Database Admins;Database Developers",,No,
GSA-Database Server,Database Server-Segment-003,db.fabrikam.com,fqdn,tcp,1433,Placeholder_Replace_Me,Yes,,"Database Admins;Database Developers",,No,
GSA-Database Server,Database Server-Segment-004,db.fabrikam.com,fqdn,udp,1434,Placeholder_Replace_Me,Yes,,"Database Admins;Database Developers",,No,
```

#### Example 3: Wildcard Domains (No Policy References)
**Input** (Private App):
```json
{
  "app_name": "[Unused Legacy DNS]",
  "host": "*._legacy.fabrikam.com",
  "protocols": [{"port": "53", "transport": "tcp"}],
  "policies": []
}
```

**Output CSV**:
```csv
EnterpriseAppName,SegmentId,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup,Provision,Notes,EntraGroups,EntraUsers,Conflict,ConflictingEnterpriseApp
GSA-Unused Legacy DNS,Unused Legacy DNS-Segment-001,*._legacy.fabrikam.com,fqdn,tcp,53,Placeholder_Replace_Me,No,App excluded from provisioning - no policy references found,,,No,
```

#### Example 4: Multiple Policies Aggregation
**Input** (Private App):
```json
{
  "app_name": "[Engineering Tools]",
  "host": "eng.fabrikam.com",
  "protocols": [{"port": "443", "transport": "tcp"}],
  "policies": ["[NPA] Engineers", "[NPA] Engineering Managers"]
}
```

**Input** (Policies):
```json
[
  {
    "rule_name": "[NPA] Engineers",
    "enabled": "1",
    "rule_data": {
      "action_name": "allow",
      "privateApps": ["[Engineering Tools]"],
      "userGroups": ["fabrikam.com/Engineering/Engineers"],
      "users": ["bob@fabrikam.com", "carol@fabrikam.com"]
    }
  },
  {
    "rule_name": "[NPA] Engineering Managers",
    "enabled": "1",
    "rule_data": {
      "action_name": "allow",
      "privateApps": ["[Engineering Tools]"],
      "userGroups": ["fabrikam.com/Engineering/Managers"],
      "users": ["carol@fabrikam.com", "dave@fabrikam.com"]
    }
  }
]
```

**Output CSV**:
```csv
EnterpriseAppName,SegmentId,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup,Provision,Notes,EntraGroups,EntraUsers,Conflict,ConflictingEnterpriseApp
GSA-Engineering Tools,Engineering Tools-Segment-001,eng.fabrikam.com,fqdn,tcp,443,Placeholder_Replace_Me,Yes,,"Engineers;Managers","bob@fabrikam.com;carol@fabrikam.com;dave@fabrikam.com",No,
```

**Note**: Users deduplicated (carol appears in both policies but only once in output)

#### Example 5: App Referenced in Policy with Empty User/Group Assignments (All Users)
**Input** (Private App):
```json
{
  "app_name": "[Public Portal]",
  "host": "portal.fabrikam.com",
  "protocols": [{"port": "443", "transport": "tcp"}],
  "policies": ["[NPA] All Users Portal"]
}
```

**Input** (Policy):
```json
{
  "rule_name": "[NPA] All Users Portal",
  "enabled": "1",
  "rule_data": {
    "action_name": "allow",
    "privateApps": ["[Public Portal]"],
    "userGroups": [],
    "users": []
  }
}
```

**Output CSV**:
```csv
EnterpriseAppName,SegmentId,destinationHost,DestinationType,Protocol,Ports,ConnectorGroup,Provision,Notes,EntraGroups,EntraUsers,Conflict,ConflictingEnterpriseApp
GSA-Public Portal,Public Portal-Segment-001,portal.fabrikam.com,fqdn,tcp,443,Placeholder_Replace_Me,Yes,,,,No,
```

**Note**: Empty EntraGroups/EntraUsers means "all users" in Netskope. Administrator should assign appropriate Entra ID groups during provisioning.

---

## 6. Function Parameters

### 6.1 Parameter Definitions

```powershell
function Convert-NPA2EPA {
    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Path to NPA Private Apps JSON export")]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$PrivateAppsPath,
        
        [Parameter(Mandatory = $false, HelpMessage = "Path to NPA Policies JSON export")]
        [ValidateScript({
            if ([string]::IsNullOrEmpty($_)) { return $true }
            if (Test-Path $_ -PathType Leaf) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$PoliciesPath,
        
        [Parameter(Mandatory = $false, HelpMessage = "Base directory for output files")]
        [ValidateScript({Test-Path $_ -PathType Container})]
        [string]$OutputBasePath = $PWD,
        
        [Parameter(HelpMessage = "Specific app name for exact match processing")]
        [string]$TargetAppName,
        
        [Parameter(HelpMessage = "Wildcard pattern for app name matching")]
        [string]$AppNamePattern,
        
        [Parameter(HelpMessage = "Comma-separated list of app names to skip (exact match)")]
        [string]$SkipAppName,
        
        [Parameter(HelpMessage = "Comma-separated list of wildcard patterns for app names to skip")]
        [string]$SkipAppNamePattern,
        
        [Parameter(HelpMessage = "Enable verbose debug logging")]
        [switch]$EnableDebugLogging,
        
        [Parameter(HelpMessage = "Return results to pipeline (suppresses automatic console output)")]
        [switch]$PassThru
    )
}
```

### 6.2 Parameter Usage Examples

#### Example 1: Basic Conversion
```powershell
Convert-NPA2EPA `
    -PrivateAppsPath "C:\Export\private_apps.json" `
    -PoliciesPath "C:\Export\npa_policies.json" `
    -OutputBasePath "C:\Output"
```

#### Example 2: Convert Specific App
```powershell
Convert-NPA2EPA `
    -PrivateAppsPath ".\private_apps.json" `
    -PoliciesPath ".\npa_policies.json" `
    -TargetAppName "Finance Portal"
```

#### Example 3: Pattern Matching
```powershell
Convert-NPA2EPA `
    -PrivateAppsPath ".\private_apps.json" `
    -AppNamePattern "HR*" `
    -SkipAppName "Test,Development"
```

#### Example 4: Pipeline Integration
```powershell
$results = Convert-NPA2EPA `
    -PrivateAppsPath ".\private_apps.json" `
    -PoliciesPath ".\npa_policies.json" `
    -PassThru

$results | Where-Object { $_.Conflict -eq "Yes" } | 
    Export-Csv ".\conflicts.csv" -NoTypeInformation
```

---

## 7. Processing Flow

### 7.1 High-Level Flow
```
1. Load Private Apps JSON
   ↓
2. Load NPA Policies JSON (if provided)
   ↓
3. Parse and validate policies
   ↓
4. Build app-to-access lookup (policy aggregation)
   ↓
5. Filter private apps (include/exclude patterns)
   ↓
6. For each private app:
   ├─ Parse hosts (comma-separated)
   ├─ Parse protocols (group by transport)
   ├─ Generate segments (host × protocol combinations)
   ├─ Detect conflicts
   ├─ Assign access (from policy lookup)
   └─ Add to results
   ↓
7. Group and deduplicate results
   ↓
8. Export to CSV
   ↓
9. Display summary statistics
```

### 7.2 Detailed Processing Steps

#### Step 1: Load Private Apps
```powershell
# Load JSON file
$privateAppsJson = Get-Content -Path $PrivateAppsPath -Raw -Encoding UTF8
$privateAppsData = $privateAppsJson | ConvertFrom-Json

# Handle different JSON structures
if ($privateAppsData.PSObject.Properties.Name -contains 'data') {
    $privateApps = $privateAppsData.data.private_apps
} elseif ($privateAppsData -is [array]) {
    $privateApps = $privateAppsData
} else {
    throw "Unexpected JSON structure in private apps file"
}

Write-LogMessage -Message "Loaded $($privateApps.Count) private apps" -Level INFO -Component 'Main'
```

#### Step 2: Load NPA Policies
```powershell
if (-not [string]::IsNullOrEmpty($PoliciesPath)) {
    $policiesJson = Get-Content -Path $PoliciesPath -Raw -Encoding UTF8
    $policies = $policiesJson | ConvertFrom-Json
    
    # Filter to enabled "allow" policies only
    $validPolicies = $policies | Where-Object {
        $_.enabled -eq "1" -and
        $_.rule_data.match_criteria_action.action_name -eq "allow"
    }
    
    Write-LogMessage -Message "Loaded $($validPolicies.Count) valid policies (filtered from $($policies.Count) total)" -Level INFO -Component 'Policies'
}
```

#### Step 3: Build App-to-Access Lookup
```powershell
function Build-AppToAccessLookup {
    param([array]$Policies)
    
    $lookup = @{}
    
    foreach ($policy in $Policies) {
        $privateApps = $policy.rule_data.privateApps
        $groups = $policy.rule_data.userGroups | ForEach-Object {
            # Parse X500 path: take last segment after /
            ($_ -split '/')[-1].Trim()
        }
        $users = $policy.rule_data.users
        
        foreach ($appName in $privateApps) {
            # Strip brackets for matching
            $cleanAppName = $appName -replace '^\[|\]$', ''
            
            if (-not $lookup.ContainsKey($cleanAppName)) {
                $lookup[$cleanAppName] = @{
                    Groups = @()
                    Users = @()
                }
            }
            
            $lookup[$cleanAppName].Groups += $groups
            $lookup[$cleanAppName].Users += $users
        }
    }
    
    # Deduplicate
    foreach ($appName in $lookup.Keys) {
        $lookup[$appName].Groups = @($lookup[$appName].Groups | Select-Object -Unique)
        $lookup[$appName].Users = @($lookup[$appName].Users | Select-Object -Unique)
    }
    
    return $lookup
}
```

#### Step 4: Process Each Private App
```powershell
foreach ($app in $filteredApps) {
    # Update progress
    Write-ProgressUpdate -Current $currentAppIndex -Total $filteredApps.Count -Activity "Converting NPA applications to EPA" -Status "Processing app: $($app.app_name)" -StartTime $startTime
    $currentAppIndex++
    
    # Clean app name (strip brackets)
    $appName = $app.app_name -replace '^\[|\]$', ''

    # Force GSA- prefix without duplicating existing prefixes
    $enterpriseAppName = if ($appName -like 'GSA-*') { $appName } else { "GSA-$appName" }
    
    # Skip if no protocols
    if ($null -eq $app.protocols -or $app.protocols.Count -eq 0) {
        Write-LogMessage -Message "Private app '$appName' has no protocols defined. Skipping." -Level WARN -Component 'ProcessApp'
        $skippedCount++
        continue
    }
    
    # Parse hosts
    $hosts = $app.host -split ',' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrEmpty($_) }
    
    # Group protocols by transport
    $protocolGroups = $app.protocols | Group-Object -Property transport
    
    # Generate segments
    $segmentCounter = 1
    foreach ($host in $hosts) {
        $destType = Get-DestinationType -Destination $host
        
        foreach ($protocolGroup in $protocolGroups) {
            $transport = $protocolGroup.Name
            $ports = ($protocolGroup.Group | Select-Object -ExpandProperty port) -join ','
            
            $segment = [PSCustomObject]@{
              EnterpriseAppName = $enterpriseAppName
                SegmentId = "$appName-Segment-{0:D3}" -f $segmentCounter
                destinationHost = $host
                DestinationType = $destType
                Protocol = $transport
                Ports = $ports
                ConnectorGroup = "Placeholder_Replace_Me"
                Provision = "Yes"
                EntraGroups = $aggregatedGroups
                EntraUsers = $aggregatedUsers
                Conflict = "No"
                ConflictingEnterpriseApp = ""
            }
            
            # Detect conflicts (update Conflict and ConflictingEnterpriseApp)
            Test-SegmentConflicts -Segment $segment -ExistingSegments $allResults
            
            $allResults += $segment
            $segmentCounter++
        }
    }
}
```

#### Step 5: Export Results
```powershell
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFileName = "${timestamp}_GSA_EnterpriseApps_NPA.csv"
$outputFilePath = Join-Path $OutputBasePath $outputFileName

$allResults | Export-Csv -Path $outputFilePath -NoTypeInformation -Encoding utf8BOM

Write-LogMessage -Message "Results exported to: $outputFilePath" -Level SUCCESS -Component 'Export'
```

---

## 8. Error Handling and Validation

### 8.1 Input Validation
- **File existence**: Validate paths before loading
- **JSON format**: Handle parse errors gracefully
- **Required fields**: Check for missing required properties
- **Data types**: Validate field types match expectations

### 8.2 Processing Validation
- **Empty hosts**: Skip apps with no hosts defined
- **Empty protocols**: Warn and skip apps with no protocols
- **Invalid CIDR**: Validate CIDR notation format
- **Invalid ports**: Validate port numbers (1-65535)

### 8.3 Warning Conditions
Log warnings for:
- Apps with no policies (no access assigned)
- Disabled policies referencing apps
- Policies with "deny" action
- Invalid group paths (cannot parse)
- Duplicate app names
- Empty user/group arrays in policies

### 8.4 Error Conditions
Throw errors for:
- Input file not found
- Invalid JSON format
- Unexpected JSON structure
- No valid apps to process after filtering
- Write failures during export

---

## 9. Logging and Statistics

### 9.1 Logging Requirements
**All console and log file output must use `Write-LogMessage`:**
- Use `-Level INFO` for general operational messages
- Use `-Level WARN` for warning conditions (e.g., apps without protocols, missing policies)
- Use `-Level ERROR` for error conditions
- Use `-Level SUCCESS` for completion messages
- Use `-Level DEBUG` for detailed diagnostic information (only shown when `-EnableDebugLogging` is specified)
- Use `-Level SUMMARY` for summary statistics at completion
- Include `-Component` parameter to identify the operation context (e.g., 'Main', 'Policies', 'ProcessApp', 'Export', 'Conflicts')
- Log file name must reuse the export timestamp and follow the pattern `${timestamp}_Convert-NPA2EPA.log` under `OutputBasePath`

**Progress updates must use `Write-ProgressUpdate`:**
- Update progress bar during app processing loop
- Include `-Activity`, `-Status`, `-Current`, `-Total`, and `-StartTime` parameters
- Progress bar automatically calculates and displays ETA

### 9.2 Summary Statistics
Display at completion using `Write-LogMessage -Level SUMMARY`:
```
=== CONVERSION SUMMARY ===
Total private apps loaded: 45
Apps processed: 42
Apps skipped (no protocols): 3
Total segments generated: 156
Conflicts detected: 2

=== POLICY INTEGRATION SUMMARY ===
Total policies loaded: 30
Valid policies processed: 28
Policies skipped (disabled/deny/invalid): 2
Apps with policy assignments: 38
Apps without policy references: 4
Total unique groups: 15
Total unique users: 34

Output file: 20251030_143022_GSA_EnterpriseApps_NPA.csv
```

### 9.3 Conflict Report
For each conflict detected, use `Write-LogMessage -Level WARN -Component 'Conflicts'`:
```
CONFLICT DETECTED:
  Application: Finance Portal
  Segment: finance.fabrikam.com:tcp/443
  Conflicts with: HR Portal (finance.fabrikam.com:tcp/443)
  Recommendation: Use different ports, consolidate applications, or use unique FQDNs
```

### 9.4 Policy Integration Report
Use `Write-LogMessage -Level SUMMARY -Component 'Policies'`:
```
=== POLICY INTEGRATION SUMMARY ===
Total policies loaded: 30
Valid policies processed: 28
Policies skipped (disabled): 1
Policies skipped (deny action): 1
Apps with policy assignments: 40
Apps without policy assignments: 2
Total unique groups: 15
Total unique users: 34
```

---

## 10. Next Steps After Conversion

### 10.1 Manual Review
1. **Review CSV file** for accuracy
2. **Review apps with Provision=No**:
   - Check the `Notes` column for reason
   - If app should be provisioned, assign appropriate EntraGroups/EntraUsers and set Provision=Yes
3. **Replace placeholders**:
   - `ConnectorGroup`: Set appropriate connector group names
4. **Review conflicts**: Resolve any detected conflicts
5. **Validate access assignments**: Ensure EntraGroups and EntraUsers are correct

### 10.2 Entra Group Mapping
- NPA groups are parsed from X500 paths (AD format)
- Ensure corresponding groups exist in Entra ID
- Group names may need adjustment if AD/Entra names differ

### 10.3 Import to GSA
Use the generated CSV with `Start-EntraPrivateAccessProvisioning`:
```powershell
Start-EntraPrivateAccessProvisioning `
    -ProvisioningConfigPath ".\20251030_143022_GSA_EnterpriseApps_NPA.csv" `
    -Force
```

---

## 11. Implementation Notes

### 11.1 Code Reuse from Convert-ZPA2EPA (#file:Convert-ZPA2EPA.ps1)
**⚠️ CRITICAL: The following functions and code blocks MUST be copied from `Convert-ZPA2EPA.ps1`:**

#### 11.1.1 Helper Functions to Reuse (Copy Directly)
- `Convert-CIDRToRange` - IP range conversion (lines ~227-261 in Convert-ZPA2EPA.ps1)
- `Convert-IPToInteger` - IP to integer conversion (lines ~263-293 in Convert-ZPA2EPA.ps1)
- `Test-IntervalOverlap` - Range overlap detection (lines ~295-311 in Convert-ZPA2EPA.ps1)
- `Test-PortRangeOverlap` - Port range overlap detection (lines ~313-338 in Convert-ZPA2EPA.ps1)
- `Get-DestinationType` - Destination type detection (lines ~340-356 in Convert-ZPA2EPA.ps1)
- `Clear-Domain` - Domain string cleaning (lines ~358-372 in Convert-ZPA2EPA.ps1)
- `Write-LogMessage` - Unified console and file logging (supports INFO, WARN, ERROR, SUCCESS, DEBUG, SUMMARY levels)
- `Write-ProgressUpdate` - Progress bar with ETA calculation

#### 11.1.2 Code Blocks to Reuse (Adapt as Needed)
- **Conflict Detection Loop** - The entire conflict detection logic from the main processing phase
- **Data Structure Initialization** - The hashtables for tracking IP ranges, hosts, and DNS suffixes (`$ipRangeToProtocolToPorts`, `$hostToProtocolToPorts`, `$dnsSuffixes`)
- **Result Grouping and Deduplication** - The grouping logic at the end of processing (lines ~1820-1850)
- **CSV Export** - The export logic with UTF-8 BOM encoding (lines ~1854-1863)
- **Summary Statistics** - The final summary output format and calculations (lines ~1866-1926)

### 11.2 New Helper Functions Required
```powershell
function Parse-GroupNameFromX500 {
    param([string]$X500Path)
    # Extract last segment after final /
    ($X500Path -split '/')[-1].Trim()
}

function Group-ProtocolsByTransport {
    param([array]$Protocols)
    # Group protocols by transport, combine ports
    $Protocols | Group-Object -Property transport
}

function Test-ValidNPAPolicy {
    param([object]$Policy)
    # Validate policy has required fields and is enabled "allow"
    $Policy.enabled -eq "1" -and
    $Policy.rule_data.match_criteria_action.action_name -eq "allow"
}

function Get-AccessFromPolicies {
    param([array]$Policies, [string]$AppName)
    # Aggregate users and groups from all policies for an app
}
```

### 11.3 Testing Recommendations
1. **Unit tests** for group parsing logic
2. **Integration tests** with sample NPA exports
3. **Conflict detection tests** with overlapping ranges
4. **Edge case tests**:
   - Empty protocols array
   - Apps with no policies
   - Disabled policies
   - Multiple policies per app
   - Wildcard domains
   - Mixed IP/FQDN hosts

---

## 12. Change Log

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-10-30 | Andres Canello | Initial specification |

---

## 13. References

- Convert-ZPA2EPA specification (20251001-Transform-ZPA2EPA-ImportAccessGroups.md)
- Start-EntraPrivateAccessProvisioning specification (20251002-Provision-EntraPrivateAccessConfig-HandleMultipleEntraGroups.md)
- Netskope Private Access API documentation
- Microsoft Entra Private Access documentation

---

**End of Specification**
