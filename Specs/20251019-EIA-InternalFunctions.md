
# Internal Functions for Entra Internet Access (EIA)

## Overview
Add internal functions to manage Security Profiles (Filtering Profiles) and Filtering Policies using Microsoft Graph API. These functions will support Get and New operations only.

## File Organization
All functions specified in this document should be created in: **`Migrate2GSA/internal/functions/EIA/`**

These are internal functions for the Migrate2GSA PowerShell module and will **not be exported** to end users. They follow the internal function naming convention with the `Int` prefix (e.g., `Get-IntSecurityProfile`, `New-IntFilteringPolicy`).

The functions will be automatically dot-sourced by the module's `.psm1` file, which loads all `.ps1` files from the `internal/functions` directory recursively.

---

## 1. Security Profiles (Filtering Profiles)

### API Details
- **Endpoint**: `https://graph.microsoft.com/beta/networkAccess/filteringProfiles`
- **Documentation**: https://learn.microsoft.com/en-us/graph/api/resources/networkaccess-filteringprofile?view=graph-rest-beta

### Commands
- `Get-IntSecurityProfile`
- `New-IntSecurityProfile`

### Get-IntSecurityProfile

#### Function Signature
```powershell
function Get-IntSecurityProfile {
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [ValidateNotNullOrEmpty()]
        [string]$Id,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
}
```

#### Behavior
- **Parameter Set 'All'** (default): Retrieves all filtering profiles
  - URI: `https://graph.microsoft.com/beta/networkAccess/filteringProfiles`
  
- **Parameter Set 'ById'**: Retrieves a single profile by ID
  - URI: `https://graph.microsoft.com/beta/networkAccess/filteringProfiles/{id}`
  
- **Parameter Set 'ByName'**: Retrieves profile(s) by exact name match
  - URI: `https://graph.microsoft.com/beta/networkAccess/filteringProfiles?$filter=name eq '{Name}'`
  - Filter is constructed server-side (OData filter)

#### Implementation Notes
- Use `Invoke-InternalGraphRequest` for all Graph calls
- Return PSObject (all properties)
- No Graph connection check (rely on Invoke-InternalGraphRequest)
- Minimal logging
- Automatic pagination via Invoke-InternalGraphRequest

### New-IntSecurityProfile

#### Function Signature
```powershell
function New-IntSecurityProfile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('enabled', 'disabled')]
        [string]$State,
        
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Priority
    )
}
```

#### Request Body
```json
{
  "name": "string",
  "description": "string",
  "state": "enabled|disabled",
  "priority": 100,
  "policies": []
}
```

#### Behavior
- **Method**: POST
- **URI**: `https://graph.microsoft.com/beta/networkAccess/filteringProfiles`
- Returns the created filtering profile object directly (PSObject)
- Use `Invoke-InternalGraphRequest` with `-Method POST -Body $bodyJson`

#### Properties (Reference)
| Property | Type | Description |
|----------|------|-------------|
| id | String | Unique identifier (read-only) |
| name | String | Profile name (required) |
| description | String | Profile description (optional) |
| state | String | enabled or disabled (required) |
| priority | Int64 | Processing priority (required) |
| createdDateTime | DateTimeOffset | Creation timestamp (read-only) |
| lastModifiedDateTime | DateTimeOffset | Last update timestamp (read-only) |
| policies | PolicyLink[] | Associated policies (empty array on creation) |

---

## 2. Filtering Policies

### API Details
- **Endpoint**: `https://graph.microsoft.com/beta/networkAccess/filteringPolicies`
- **Documentation**: https://learn.microsoft.com/en-us/graph/api/resources/networkaccess-filteringpolicy?view=graph-rest-beta

### Commands
- `Get-IntFilteringPolicy`
- `New-IntFilteringPolicy`

### Get-IntFilteringPolicy

#### Function Signature
```powershell
function Get-IntFilteringPolicy {
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [ValidateNotNullOrEmpty()]
        [string]$Id,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
}
```

#### Behavior
- **Parameter Set 'All'** (default): Retrieves all filtering policies
  - URI: `https://graph.microsoft.com/beta/networkAccess/filteringPolicies`
  
- **Parameter Set 'ById'**: Retrieves a single policy by ID
  - URI: `https://graph.microsoft.com/beta/networkAccess/filteringPolicies/{id}`
  
- **Parameter Set 'ByName'**: Retrieves policy/policies by exact name match
  - URI: `https://graph.microsoft.com/beta/networkAccess/filteringPolicies?$filter=name eq '{Name}'`
  - Filter is constructed server-side (OData filter)

#### Implementation Notes
- Use `Invoke-InternalGraphRequest` for all Graph calls
- Return PSObject (all properties)
- No Graph connection check (rely on Invoke-InternalGraphRequest)
- Minimal logging
- Automatic pagination via Invoke-InternalGraphRequest

### New-IntFilteringPolicy

#### Function Signature
```powershell
function New-IntFilteringPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('block', 'allow')]
        [string]$Action = 'block'
    )
}
```

#### Request Body (Minimal)
```json
{
  "name": "string",
  "description": "string",
  "action": "block",
  "policyRules": []
}
```

#### Behavior
- **Method**: POST
- **URI**: `https://graph.microsoft.com/beta/networkAccess/filteringPolicies`
- Returns the created filtering policy object directly (PSObject)
- Use `Invoke-InternalGraphRequest` with `-Method POST -Body $bodyJson`
- Note: `policyRules` can be added later via separate API calls, so initial creation uses empty array

#### Properties (Reference)
| Property | Type | Description |
|----------|------|-------------|
| id | String | Unique identifier (read-only) |
| name | String | Policy name (required) |
| description | String | Policy description (optional) |
| action | String | block or allow (optional, defaults to block) |
| createdDateTime | DateTimeOffset | Creation timestamp (read-only) |
| lastModifiedDateTime | DateTimeOffset | Last update timestamp (read-only) |
| policyRules | PolicyRule[] | Associated policy rules (empty array on creation) |

---

## General Implementation Guidelines

### Common Patterns
1. **CmdletBinding**: All functions must support cmdlet binding
2. **Parameter Validation**: Use `[ValidateNotNullOrEmpty()]` for required string parameters
3. **Parameter Sets**: Separate parameter sets for All, ById, and ByName
4. **Error Handling**: Use try/catch blocks with `Write-Error` for failures
5. **Graph API Calls**: Use `Invoke-InternalGraphRequest` for all Graph operations
6. **Return Type**: Return PSObject directly (not wrapped in custom object)
7. **Logging**: Minimal logging (no verbose logging required)
8. **Pagination**: Automatic via `Invoke-InternalGraphRequest`
9. **Connection Check**: None (handled by `Invoke-InternalGraphRequest`)

### OData Filtering
- Use server-side filtering with `$filter` query parameter
- Exact match syntax: `$filter=name eq 'ExactName'`
- Construct filter string in PowerShell and append to URI
- Reference: https://learn.microsoft.com/en-us/graph/filter-query-parameter?tabs=http

### Example URI Construction for Name Filter
```powershell
$uri = "https://graph.microsoft.com/beta/networkAccess/filteringProfiles?`$filter=name eq '$Name'"
$response = Invoke-InternalGraphRequest -Method GET -Uri $uri
```

---

## 3. Filtering Policy Links

### API Details
- **Endpoint**: `https://graph.microsoft.com/beta/networkAccess/filteringProfiles/{profileId}/policies`
- **Documentation**: https://learn.microsoft.com/en-us/graph/api/resources/networkaccess-filteringpolicylink?view=graph-rest-beta

### Commands
- `Get-IntFilteringPolicyLink`
- `New-IntFilteringPolicyLink`

### Get-IntFilteringPolicyLink

#### Function Signature
```powershell
function Get-IntFilteringPolicyLink {
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileId,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [ValidateNotNullOrEmpty()]
        [string]$Id
    )
}
```

#### Behavior
- **Parameter Set 'All'** (default): Retrieves all policy links for a profile
  - URI: `https://graph.microsoft.com/beta/networkAccess/filteringProfiles/{profileId}/policies`
  
- **Parameter Set 'ById'**: Retrieves a single policy link by ID
  - URI: `https://graph.microsoft.com/beta/networkAccess/filteringProfiles/{profileId}/policies/{id}`

#### Implementation Notes
- `ProfileId` is always required (no name-based filtering for this resource)
- Use `Invoke-InternalGraphRequest` for all Graph calls
- Return PSObject (all properties)
- No Graph connection check
- Minimal logging
- Automatic pagination via Invoke-InternalGraphRequest

### New-IntFilteringPolicyLink

#### Function Signature
```powershell
function New-IntFilteringPolicyLink {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Priority,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('enabled', 'disabled')]
        [string]$State = 'enabled',
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('enabled', 'disabled')]
        [string]$LoggingState = 'enabled',
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('block', 'allow')]
        [string]$Action = 'block'
    )
}
```

#### Request Body
```json
{
  "priority": 100,
  "state": "enabled",
  "@odata.type": "#microsoft.graph.networkaccess.filteringPolicyLink",
  "loggingState": "enabled",
  "action": "block",
  "policy": {
    "id": "policy-guid",
    "@odata.type": "#microsoft.graph.networkaccess.filteringPolicy"
  }
}
```

#### Behavior
- **Method**: POST
- **URI**: `https://graph.microsoft.com/beta/networkAccess/filteringProfiles/{profileId}/policies`
- Returns the created policy link object directly (PSObject)
- Use `Invoke-InternalGraphRequest` with `-Method POST -Body $bodyJson`

---

## 4. Threat Intelligence Policies

### API Details
- **Endpoint**: `https://graph.microsoft.com/beta/networkAccess/threatIntelligencePolicies`
- **Documentation**: https://learn.microsoft.com/en-us/graph/api/resources/networkaccess-threatintelligencepolicy?view=graph-rest-beta

### Commands
- `Get-IntThreatIntelligencePolicy`
- `New-IntThreatIntelligencePolicy`

### Get-IntThreatIntelligencePolicy

#### Function Signature
```powershell
function Get-IntThreatIntelligencePolicy {
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [ValidateNotNullOrEmpty()]
        [string]$Id,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
}
```

#### Behavior
- **Parameter Set 'All'** (default): Retrieves all threat intelligence policies
  - URI: `https://graph.microsoft.com/beta/networkAccess/threatIntelligencePolicies`
  
- **Parameter Set 'ById'**: Retrieves a single policy by ID
  - URI: `https://graph.microsoft.com/beta/networkAccess/threatIntelligencePolicies/{id}`
  
- **Parameter Set 'ByName'**: Retrieves policy/policies by exact name match
  - URI: `https://graph.microsoft.com/beta/networkAccess/threatIntelligencePolicies?$filter=name eq '{Name}'`

### New-IntThreatIntelligencePolicy

#### Function Signature
```powershell
function New-IntThreatIntelligencePolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description
    )
}
```

#### Request Body
```json
{
  "name": "string",
  "description": "string",
  "policyRules": []
}
```

#### Behavior
- **Method**: POST
- **URI**: `https://graph.microsoft.com/beta/networkAccess/threatIntelligencePolicies`
- Returns the created threat intelligence policy object directly (PSObject)

---

## 5. Threat Intelligence Policy Links

### API Details
- **Endpoint**: `https://graph.microsoft.com/beta/networkAccess/filteringProfiles/{profileId}/policies` (threat intelligence type)
- **Documentation**: https://learn.microsoft.com/en-us/graph/api/resources/networkaccess-threatintelligencepolicylink?view=graph-rest-beta

### Commands
- `Get-IntThreatIntelligencePolicyLink`
- `New-IntThreatIntelligencePolicyLink`

### Get-IntThreatIntelligencePolicyLink

#### Function Signature
```powershell
function Get-IntThreatIntelligencePolicyLink {
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileId,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [ValidateNotNullOrEmpty()]
        [string]$Id
    )
}
```

#### Behavior
- Similar to FilteringPolicyLink but for threat intelligence policies
- **Parameter Set 'All'** (default): Retrieves all threat intelligence policy links for a profile
  - URI: `https://graph.microsoft.com/beta/networkAccess/filteringProfiles/{profileId}/policies` (filtered by type)

### New-IntThreatIntelligencePolicyLink

#### Function Signature
```powershell
function New-IntThreatIntelligencePolicyLink {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('enabled', 'disabled')]
        [string]$State = 'enabled'
    )
}
```

#### Request Body
```json
{
  "state": "enabled",
  "@odata.type": "#microsoft.graph.networkaccess.threatIntelligencePolicyLink",
  "policy": {
    "id": "policy-guid",
    "@odata.type": "#microsoft.graph.networkaccess.threatIntelligencePolicy"
  }
}
```

---

## 6. TLS Inspection Policies

### API Details
- **Endpoint**: `https://graph.microsoft.com/beta/networkAccess/tlsInspectionPolicies`
- **Documentation**: https://learn.microsoft.com/en-us/graph/api/resources/networkaccess-tlsinspectionpolicy?view=graph-rest-beta

### Commands
- `Get-IntTlsInspectionPolicy`
- `New-IntTlsInspectionPolicy`

### Get-IntTlsInspectionPolicy

#### Function Signature
```powershell
function Get-IntTlsInspectionPolicy {
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [ValidateNotNullOrEmpty()]
        [string]$Id,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
}
```

#### Behavior
- **Parameter Set 'All'** (default): Retrieves all TLS inspection policies
  - URI: `https://graph.microsoft.com/beta/networkAccess/tlsInspectionPolicies`
  
- **Parameter Set 'ById'**: Retrieves a single policy by ID
  - URI: `https://graph.microsoft.com/beta/networkAccess/tlsInspectionPolicies/{id}`
  
- **Parameter Set 'ByName'**: Retrieves policy/policies by exact name match
  - URI: `https://graph.microsoft.com/beta/networkAccess/tlsInspectionPolicies?$filter=name eq '{Name}'`

### New-IntTlsInspectionPolicy

#### Function Signature
```powershell
function New-IntTlsInspectionPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description
    )
}
```

#### Request Body
```json
{
  "name": "string",
  "description": "string",
  "policyRules": []
}
```

#### Behavior
- **Method**: POST
- **URI**: `https://graph.microsoft.com/beta/networkAccess/tlsInspectionPolicies`
- Returns the created TLS inspection policy object directly (PSObject)

---

## 7. Filtering Rules

Filtering rules are added to filtering policies to define specific traffic filtering behaviors. These rules are created via POST operations to the `policyRules` collection of a filtering policy.

### API Details
- **Endpoint**: `https://graph.microsoft.com/beta/networkAccess/filteringPolicies/{policyId}/policyRules`
- **Documentation**: https://learn.microsoft.com/en-us/graph/api/resources/networkaccess-filteringrule?view=graph-rest-beta

### Commands
- `New-IntFqdnFilteringRule`
- `New-IntWebCategoryFilteringRule`
- `New-IntUrlFilteringRule`
- `Get-IntFilteringRule`

### Get-IntFilteringRule

#### Function Signature
```powershell
function Get-IntFilteringRule {
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [ValidateNotNullOrEmpty()]
        [string]$Id
    )
}
```

#### Behavior
- **Parameter Set 'All'** (default): Retrieves all filtering rules for a policy
  - URI: `https://graph.microsoft.com/beta/networkAccess/filteringPolicies/{policyId}/policyRules`
  
- **Parameter Set 'ById'**: Retrieves a single rule by ID
  - URI: `https://graph.microsoft.com/beta/networkAccess/filteringPolicies/{policyId}/policyRules/{id}`

#### Implementation Notes
- `PolicyId` is always required
- Returns all rule types (FQDN, WebCategory, URL)
- Use `Invoke-InternalGraphRequest` for all Graph calls
- Return PSObject (all properties)
- Automatic pagination via Invoke-InternalGraphRequest

---

### New-IntFqdnFilteringRule

#### Function Signature
```powershell
function New-IntFqdnFilteringRule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Fqdns
    )
}
```

#### Request Body
```json
{
  "@odata.type": "#microsoft.graph.networkaccess.fqdnFilteringRule",
  "name": "Rule Name",
  "ruleType": "fqdn",
  "destinations": [
    {
      "@odata.type": "#microsoft.graph.networkaccess.fqdn",
      "value": "example.com"
    },
    {
      "@odata.type": "#microsoft.graph.networkaccess.fqdn",
      "value": "*.example.com"
    }
  ]
}
```

#### Behavior
- **Method**: POST
- **URI**: `https://graph.microsoft.com/beta/networkAccess/filteringPolicies/{policyId}/policyRules`
- Accepts array of FQDN strings (supports wildcards like `*.example.com`)
- Constructs destinations array with proper `@odata.type` for each FQDN
- Returns the created rule object directly (PSObject)

---

### New-IntWebCategoryFilteringRule

#### Function Signature
```powershell
function New-IntWebCategoryFilteringRule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Categories
    )
}
```

#### Request Body
```json
{
  "@odata.type": "#microsoft.graph.networkaccess.webCategoryFilteringRule",
  "name": "Rule Name",
  "ruleType": "webCategory",
  "destinations": [
    {
      "@odata.type": "#microsoft.graph.networkaccess.webCategory",
      "name": "ArtificialIntelligence"
    },
    {
      "@odata.type": "#microsoft.graph.networkaccess.webCategory",
      "name": "Dating"
    }
  ]
}
```

#### Behavior
- **Method**: POST
- **URI**: `https://graph.microsoft.com/beta/networkAccess/filteringPolicies/{policyId}/policyRules`
- Accepts array of web category names
- Constructs destinations array with proper `@odata.type` for each category
- Returns the created rule object directly (PSObject)

#### Common Web Categories
Examples include: `ArtificialIntelligence`, `Dating`, `Gambling`, `SocialNetworking`, `Streaming`, `Shopping`, etc.

---

### New-IntUrlFilteringRule

#### Function Signature
```powershell
function New-IntUrlFilteringRule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Urls
    )
}
```

#### Request Body
```json
{
  "@odata.type": "#microsoft.graph.networkaccess.urlFilteringRule",
  "name": "Rule Name",
  "ruleType": "url",
  "destinations": [
    {
      "@odata.type": "#microsoft.graph.networkaccess.url",
      "value": "https://example.com/path"
    },
    {
      "@odata.type": "#microsoft.graph.networkaccess.url",
      "value": "https://example.com/another-path"
    }
  ]
}
```

#### Behavior
- **Method**: POST
- **URI**: `https://graph.microsoft.com/beta/networkAccess/filteringPolicies/{policyId}/policyRules`
- Accepts array of full URL strings (including protocol and path)
- Constructs destinations array with proper `@odata.type` for each URL
- Returns the created rule object directly (PSObject)

**Note**: URL filtering is not yet fully documented in Microsoft Graph but follows the same pattern as FQDN and web category filtering rules.

---

## 8. Threat Intelligence Policy Rules

Threat intelligence rules are added to threat intelligence policies to define specific conditions and actions for evaluating network traffic against known threat intelligence data.

### API Details
- **Endpoint**: `https://graph.microsoft.com/beta/networkAccess/threatIntelligencePolicies/{policyId}/policyRules`
- **Documentation**: https://learn.microsoft.com/en-us/graph/api/networkaccess-threatintelligencepolicy-post-policyrules?view=graph-rest-beta

### Commands
- `Get-IntThreatIntelligenceRule`
- `New-IntThreatIntelligenceRule`

### Get-IntThreatIntelligenceRule

#### Function Signature
```powershell
function Get-IntThreatIntelligenceRule {
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [ValidateNotNullOrEmpty()]
        [string]$Id
    )
}
```

#### Behavior
- **Parameter Set 'All'** (default): Retrieves all threat intelligence rules for a policy
  - URI: `https://graph.microsoft.com/beta/networkAccess/threatIntelligencePolicies/{policyId}/policyRules`
  
- **Parameter Set 'ById'**: Retrieves a single rule by ID
  - URI: `https://graph.microsoft.com/beta/networkAccess/threatIntelligencePolicies/{policyId}/policyRules/{id}`

#### Implementation Notes
- `PolicyId` is always required
- Use `Invoke-InternalGraphRequest` for all Graph calls
- Return PSObject (all properties)
- Automatic pagination via Invoke-InternalGraphRequest

---

### New-IntThreatIntelligenceRule

#### Function Signature
```powershell
function New-IntThreatIntelligenceRule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Priority,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('allow', 'block')]
        [string]$Action,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('enabled', 'disabled', 'reportOnly')]
        [string]$Status,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('low', 'medium', 'high')]
        [string]$Severity,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Fqdns
    )
}
```

#### Request Body
```json
{
  "@odata.type": "#microsoft.graph.networkaccess.threatIntelligenceRule",
  "name": "Rule 1",
  "priority": 100,
  "description": "Rule 1",
  "action": "allow",
  "settings": {
    "status": "enabled"
  },
  "matchingConditions": {
    "severity": "high",
    "destinations": [
      {
        "@odata.type": "#microsoft.graph.networkaccess.threatIntelligenceFqdnDestination",
        "values": [
          "badsite.com",
          "*.verybadwebsite.com"
        ]
      }
    ]
  }
}
```

#### Behavior
- **Method**: POST
- **URI**: `https://graph.microsoft.com/beta/networkAccess/threatIntelligencePolicies/{policyId}/policyRules`
- Accepts array of FQDN strings (supports wildcards like `*.example.com`)
- Constructs destinations array with proper `@odata.type` for threat intelligence FQDN destinations
- Returns the created rule object directly (PSObject)

#### Properties
- **name**: Display name of the rule (required)
- **priority**: Processing priority (lower = higher priority, required)
- **description**: Optional description
- **action**: `allow` or `block` (required)
- **settings.status**: `enabled`, `disabled`, or `reportOnly` (required)
- **matchingConditions.severity**: `low`, `medium`, or `high` (required)
- **matchingConditions.destinations**: Array of FQDN destinations with threat intelligence type

---

## 9. TLS Inspection Policy Rules

TLS inspection rules are added to TLS inspection policies to define specific conditions for inspecting or bypassing TLS traffic.

### API Details
- **Endpoint**: `https://graph.microsoft.com/beta/networkAccess/tlsInspectionPolicies/{tlsInspectionPolicyId}/policyRules`
- **Documentation**: https://learn.microsoft.com/en-us/graph/api/networkaccess-tlsinspectionpolicy-post-policyrules?view=graph-rest-beta

### Commands
- `Get-IntTlsInspectionRule`
- `New-IntTlsInspectionRule`

### Get-IntTlsInspectionRule

#### Function Signature
```powershell
function Get-IntTlsInspectionRule {
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [ValidateNotNullOrEmpty()]
        [string]$Id
    )
}
```

#### Behavior
- **Parameter Set 'All'** (default): Retrieves all TLS inspection rules for a policy
  - URI: `https://graph.microsoft.com/beta/networkAccess/tlsInspectionPolicies/{policyId}/policyRules`
  
- **Parameter Set 'ById'**: Retrieves a single rule by ID
  - URI: `https://graph.microsoft.com/beta/networkAccess/tlsInspectionPolicies/{policyId}/policyRules/{id}`

#### Implementation Notes
- `PolicyId` is always required
- Use `Invoke-InternalGraphRequest` for all Graph calls
- Return PSObject (all properties)
- Automatic pagination via Invoke-InternalGraphRequest

---

### New-IntTlsInspectionRule

#### Function Signature
```powershell
function New-IntTlsInspectionRule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Priority,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('bypass', 'inspect')]
        [string]$Action,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('enabled', 'disabled')]
        [string]$Status,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Fqdns,
        
        [Parameter(Mandatory = $false)]
        [string[]]$WebCategories
    )
}
```

#### Request Body
```json
{
  "@odata.type": "#microsoft.graph.networkaccess.tlsInspectionRule",
  "name": "Contoso TLS Rule 1",
  "priority": 100,
  "description": "My TLS rule",
  "action": "inspect",
  "settings": {
    "status": "enabled"
  },
  "matchingConditions": {
    "destinations": [
      {
        "@odata.type": "#microsoft.graph.networkaccess.tlsInspectionFqdnDestination",
        "values": [
          "www.contoso.test.com",
          "*.contoso.org"
        ]
      },
      {
        "@odata.type": "#microsoft.graph.networkaccess.tlsInspectionWebCategoriesDestination",
        "values": [
          "Entertainment"
        ]
      }
    ]
  }
}
```

#### Behavior
- **Method**: POST
- **URI**: `https://graph.microsoft.com/beta/networkAccess/tlsInspectionPolicies/{policyId}/policyRules`
- Supports FQDN destinations and/or web category destinations
- At least one destination type (Fqdns or WebCategories) must be provided
- Constructs destinations array with proper `@odata.type` for each destination type
- Returns the created rule object directly (PSObject)

#### Properties
- **name**: Display name of the rule (required)
- **priority**: Processing priority (lower = higher priority, required)
- **description**: Optional description
- **action**: `bypass` or `inspect` (required)
- **settings.status**: `enabled` or `disabled` (required)
- **matchingConditions.destinations**: Array of FQDN and/or web category destinations

#### Implementation Notes
- Must validate that at least one of `Fqdns` or `WebCategories` is provided
- Can accept both destination types in a single rule
- FQDN destinations support wildcards (e.g., `*.example.com`)

---

## Future Enhancements
Additional object types and rule management functions may be added to this specification in future iterations.