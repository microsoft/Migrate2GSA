# Specification: Export-NetskopeConfig

**Date:** October 15, 2025  
**Status:** Draft  
v

## Overview

Create a PowerShell function to export Netskope configuration to JSON files for backup and migration purposes. This function will be similar to `Export-ZPAConfig` but adapted for Netskope's API structure and authentication model.

## Function Specification

### Function Name
`Export-NetskopeConfig`

### Synopsis
Exports Netskope configurations to JSON files for backup and migration purposes.

### Description
This PowerShell function connects to the Netskope API using an API token and exports various configuration types to JSON files. The function handles multiple configuration objects including Private Access applications, publishers, URL lists, policies, and custom profiles.

### Parameters

#### Mandatory Parameters

1. **ApiToken** (SecureString)
   - Type: `[SecureString]`
   - Mandatory: Yes
   - Description: The Netskope API token (generated from the Netskope portal)
   - Notes: Must be provided as a SecureString for security

2. **TenantUrl** (String)
   - Type: `[String]`
   - Mandatory: Yes
   - Description: The base tenant URL (e.g., "https://tenant.goskope.com")
   - Validation: 
     - Must be a valid HTTPS URL
     - Should not have trailing slashes
     - Format: `https://<tenant>.goskope.com` or custom domain
   - Example: `"https://contoso.goskope.com"`

#### Optional Parameters

3. **OutputDirectory** (String)
   - Type: `[String]`
   - Mandatory: No
   - Default: Current location `(Get-Location).Path`
   - Description: The output directory for backup files

4. **RequestDelay** (Int)
   - Type: `[Int]`
   - Mandatory: No
   - Default: 1
   - Description: Delay in seconds between API requests to avoid rate limiting

#### Common Parameters

The function supports common PowerShell parameters including:
- **Debug** - When specified, logs raw API responses for troubleshooting

## API Authentication

### Authentication Method
Netskope uses simple API token-based authentication via HTTP headers.

**Header Format:**
```
Netskope-Api-Token: <token>
```

### Base URL Processing
The function must validate and normalize the tenant URL:
- Remove trailing slashes
- Validate HTTPS protocol
- Ensure proper URL format

## Configuration Objects to Export

The following configuration objects should be exported:

### 1. Private Applications
- **Endpoint:** `/api/v2/steering/apps/private`
- **Method:** GET
- **Description:** Netskope Private Access applications
- **Output File:** `private_apps.json`

### 2. Publishers
- **Endpoint:** `/api/v2/infrastructure/publishers`
- **Method:** GET
- **Description:** Netskope Publishers
- **Output File:** `publishers.json`

### 3. URL Lists
- **Endpoint:** `/api/v2/policy/urllist`
- **Method:** GET
- **Description:** Custom URL lists used in policies
- **Output File:** `url_lists.json`

### 4. NPA Policies
- **Endpoint:** `/api/v2/policy/npa`
- **Method:** GET
- **Description:** Netskope Private Access policies
- **Output File:** `npa_policies.json`

### 5. NPA Policy Groups
- **Endpoint:** `/api/v2/policy/npa/policygroups`
- **Method:** GET
- **Description:** Netskope Private Access policy groups
- **Output File:** `npa_policy_groups.json`

### 6. Custom Categories
- **Endpoint:** `/api/v2/profiles/customcategories`
- **Method:** GET
- **Description:** Custom URL categories
- **Output File:** `custom_categories.json`

### 7. Destinations
- **Endpoint:** `/api/v2/profiles/destinations`
- **Method:** GET
- **Description:** Network destinations and locations
- **Output File:** `destinations.json`

## API Behavior Notes

### Pagination
**Important:** Netskope API does NOT support pagination. Each endpoint returns the complete result set in a single response. No need to implement page-based logic.

### Rate Limiting
- No specific rate limits documented
- Implement configurable delay between requests via `RequestDelay` parameter
- Default: 1 second between requests

### Response Format
Most endpoints return data in one of these formats:
- Direct array: `[{...}, {...}]`
- Object with data array: `{"data": [{...}], "status": "success"}`
- Object with result: `{"result": [{...}]}`

The function should handle all three formats gracefully.

## Internal Functions

### 1. Initialize-NetskopeSession
```powershell
function Initialize-NetskopeSession {
    param(
        [Parameter(Mandatory = $true)]
        [SecureString]$ApiToken,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantUrl
    )
    
    # Validate and normalize URL
    # Set up headers with API token
    # Return session object or set script-scoped variables
}
```

**Responsibilities:**
- Validate tenant URL format (must be HTTPS, no trailing slash)
- Convert SecureString token to plain text for header
- Create headers hashtable with `Netskope-Api-Token`
- Set script-scoped variables for use in other functions
- Test connectivity with a simple API call

### 2. Invoke-NetskopeApi
```powershell
function Invoke-NetskopeApi {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Endpoint,
        
        [Parameter(Mandatory = $false)]
        [int]$DelaySeconds = 1
    )
    
    # Make API call
    # Handle errors
    # Apply delay
    # Return response
}
```

**Responsibilities:**
- Construct full URL from base URL and endpoint
- Use script-scoped headers
- Make GET request using `Invoke-RestMethod`
- Handle HTTP errors gracefully
- Apply configurable delay after request
- Return parsed JSON response
- Use `Write-LogMessage` for logging request/response details
- When `-Debug` is active, log raw API responses using `Write-LogMessage` with Debug level

### 3. Get-Netskope[ObjectType]
Individual functions for each object type (similar to ZPA pattern):

- `Get-NetskopePrivateApps`
- `Get-NetskopePublishers`
- `Get-NetskopeUrlLists`
- `Get-NetskopeNpaPolicies`
- `Get-NetskopeNpaPolicyGroups`
- `Get-NetskopeCustomCategories`
- `Get-NetskopeDestinations`

Each function:
- Calls `Invoke-NetskopeApi` with appropriate endpoint
- Uses `Write-LogMessage` to display progress
- Returns the data portion of the response

### 4. Start-NetskopeFullBackup
```powershell
function Start-NetskopeFullBackup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputDir
    )
    
    # Create timestamped backup directory
    # Call all Get-Netskope* functions
    # Save individual JSON files
    # Create complete backup file
    # Display summary
}
```

**Responsibilities:**
- Create timestamped backup folder: `backup_YYYYMMDD_HHmmss`
- Call all object retrieval functions
- Save each configuration to individual JSON file
- Create complete backup file with metadata
- Track and report success/failure counts
- Return success/failure status

## Output Structure

### Individual Files
Each configuration type saved as separate JSON file with UTF-8 encoding:
- `private_apps.json`
- `publishers.json`
- `url_lists.json`
- `npa_policies.json`
- `npa_policy_groups.json`
- `custom_categories.json`
- `destinations.json`

### Complete Backup File
`netskope_complete_backup.json` containing:
```json
{
    "timestamp": "20251015_143022",
    "tenant_url": "https://contoso.goskope.com",
    "backup_type": "Netskope_Configuration",
    "configurations": {
        "private_apps": [...],
        "publishers": [...],
        "url_lists": [...],
        "npa_policies": [...],
        "npa_policy_groups": [...],
        "custom_categories": [...],
        "destinations": [...]
    }
}
```

## Error Handling

### Authentication Errors
- Invalid token → Clear error message
- Network connectivity issues → Detailed error with endpoint
- Invalid tenant URL → Validation error before API call

### API Errors
- 401 Unauthorized → "Invalid or expired API token"
- 403 Forbidden → "Insufficient permissions for endpoint"
- 404 Not Found → "Endpoint not available or feature not enabled"
- 429 Rate Limit → "Rate limit exceeded, increase RequestDelay"
- 500 Server Error → "Netskope API server error"

### Best Practices
- Use internal `Write-LogMessage` function for all logging output
  - Provides consistent formatting with colors
  - Automatically writes to log file
  - Supports different message types (Info, Warning, Error, Success)
- Continue backup even if one object type fails
- Log all failures in summary

## Usage Examples

### Example 1: Basic Usage
```powershell
$token = Read-Host "Enter API Token" -AsSecureString
Export-NetskopeConfig -ApiToken $token -TenantUrl "https://contoso.goskope.com"
```

### Example 2: Custom Output Directory
```powershell
$token = ConvertTo-SecureString "your-token" -AsPlainText -Force
Export-NetskopeConfig `
    -ApiToken $token `
    -TenantUrl "https://contoso.goskope.com" `
    -OutputDirectory "C:\Backups\Netskope"
```

### Example 3: With Request Delay
```powershell
$token = Read-Host "Enter API Token" -AsSecureString
Export-NetskopeConfig `
    -ApiToken $token `
    -TenantUrl "https://contoso.goskope.com" `
    -RequestDelay 2
```

### Example 4: Debug Mode with Raw API Responses
```powershell
$token = Read-Host "Enter API Token" -AsSecureString
Export-NetskopeConfig `
    -ApiToken $token `
    -TenantUrl "https://contoso.goskope.com" `
    -Debug
```

## Validation Requirements

### URL Validation Function
```powershell
function Test-TenantUrl {
    param([string]$Url)
    
    # Must start with https://
    # Must not end with /
    # Must be valid URI
    # Return normalized URL
}
```

### Token Validation
- Ensure SecureString is not null or empty
- Convert to plain text only when needed for API call
- Clear from memory after use where possible

## Success Criteria

1. ✅ Successfully authenticate with Netskope API using token
2. ✅ Export all 7 configuration object types
3. ✅ Handle API errors gracefully without stopping entire backup
4. ✅ Create timestamped backup folders
5. ✅ Save both individual and complete backup files
6. ✅ Validate tenant URL before making API calls
7. ✅ Provide clear progress indicators and summary
8. ✅ Handle empty responses (no data) without failing
9. ✅ Follow PowerShell best practices and coding standards
10. ✅ Include comprehensive help documentation

## Testing Scenarios

### Positive Tests
1. Valid token and URL → Successful backup
2. Empty configuration objects → Warning, no error
3. Custom output directory → Creates if not exists
4. Multiple runs → Separate timestamped folders

### Negative Tests
1. Invalid token → Authentication error
2. Invalid URL format → Validation error
3. Network timeout → Clear error message
4. Insufficient permissions → Warning, continue with other objects
5. Invalid output path → Create directory or error

## Dependencies

- PowerShell 5.1 or higher
- .NET Framework for SecureString handling
- `Invoke-RestMethod` cmdlet
- Network access to Netskope tenant
- Valid Netskope API token with appropriate permissions
- Internal module functions:
  - `Write-LogMessage` - For consistent logging and output

## Security Considerations

1. **API Token Protection:**
   - Always use SecureString for token input
   - Convert to plain text only when needed
   - Don't log token in output/errors
   - Clear sensitive variables after use

2. **Output Files:**
   - May contain sensitive configuration data
   - Recommend securing backup directory with appropriate ACLs
   - Consider encryption for backup files

3. **Logging:**
   - Use `Write-LogMessage` internal function for all output and logging
   - Log API endpoints and response codes
   - Never log authentication headers or tokens
   - Sanitize error messages to remove sensitive data
   - Log file stored in output directory with backup
   - When `-Debug` parameter is used, log raw API responses for troubleshooting

## Future Enhancements

1. Support for additional Netskope objects:
   - SCIM groups/users
   - DLP profiles
   - GRE/IPSec tunnels
   - Bandwidth control policies

2. Incremental backups (compare with previous)
3. Export to different formats (CSV, XML)
4. Backup comparison and diff reporting
5. Restore functionality
6. Progress bars using `Write-Progress`

## References

- Netskope REST API v2 Documentation
- Netskope API Postman Collection
- ZPA Export Implementation: `Export-ZPAConfig.ps1`

## Notes

- Unlike ZPA, Netskope doesn't require customer ID in URL path
- API responses may vary in structure between endpoints
- Some endpoints may return empty arrays for disabled features
- Test with actual Netskope tenant to confirm endpoint availability
