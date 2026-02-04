# Internal Graph API Request Handler Function Specification

## Overview
Internal PowerShell function to handle Microsoft Graph API requests with automatic throttling detection, retry logic with exponential backoff, and proper error handling following Microsoft's throttling best practices.

## Function Name
`Invoke-InternalGraphRequest`

## Purpose
- Centralize all Graph API calls with consistent error handling
- Automatically detect and handle 429 (Too Many Requests) throttling responses
- Implement exponential backoff with jitter as per Microsoft recommendations
- Respect Retry-After headers when present
- Provide consistent logging for all Graph API operations

## Parameters

| Parameter | Type | Mandatory | Default | Description |
|-----------|------|-----------|---------|-------------|
| Uri | String | Yes | - | The Graph API endpoint URI (relative or absolute) |
| Method | String | No | GET | HTTP method (GET, POST, PUT, PATCH, DELETE) |
| Body | Object | No | null | Request body for POST/PUT/PATCH operations |
| Headers | Hashtable | No | @{} | Additional headers (Command header added automatically) |
| MaxRetries | Int32 | No | 4 | Maximum number of retry attempts |
| CallingCommand | String | No | (auto-detected) | Name of calling function for header tracking |
| FollowPagination | Switch | No | True | Automatically follow @odata.nextLink for paginated results |
| OutputType | String | No | PSObject | Output format (PSObject, Json, or Raw) |

## Throttling Detection and Handling

### Detected Status Codes
- **429 (Too Many Requests)**: Primary throttling response
- No other status codes trigger automatic retry (503, 504, etc. should be handled by calling function if needed)

### Retry Strategy
1. **Exponential Backoff with Jitter**
   - Base delay: 500 milliseconds (0.5 seconds)
   - Max delay: 10 seconds
   - Formula: `min(baseDelay * (2^attempt) + random_jitter, maxDelay)`
   - Jitter range: 0-500 milliseconds random

2. **Retry-After Header**
   - If present in 429 response, use this value instead of calculated backoff
   - Can be in seconds (integer) or HTTP-date format
   - Add small jitter (0-200 milliseconds) to prevent thundering herd

3. **Maximum Retries**
   - Default: 4 retries (5 total attempts)
   - Configurable via parameter

## Logging Requirements

### Standard Logging
- Retry attempts: "Retry {current}/{max} after {delay}s due to throttling (Retry-After: {value})" - INFO level with Write-LogMessage
  - Include Retry-After value if present in response

### Debug Logging (when $DebugPreference -eq 'Continue')
- Initial request details (URI, Method)
- Final success/failure status
- Backoff calculation details
- Note: Invoke-GraphRequest already logs request/response details, so no need to duplicate

### No Logging For
- Request/response headers and body (handled by Invoke-GraphRequest)
- Correlation IDs
- Performance metrics

## Implementation Details

### Custom Headers
- Automatically add custom header with calling command name
- Use `New-EntraBetaCustomHeaders -Command $CallingCommand`
- CallingCommand auto-detected via `$MyInvocation.MyCommand.Name` from calling function
- Merge with any additional headers provided

### Error Handling
- Throw terminating errors after max retries exceeded
- Include original error details in exception
- Provide actionable error messages

### Pagination Support
- When FollowPagination switch is used (default: True):
  - Automatically follow @odata.nextLink
  - Aggregate all results into single array
  - Apply same retry logic to each page request
  - Log pagination progress in Debug mode only

## Usage Examples

```powershell
# Simple GET request (pagination enabled by default)
$users = Invoke-InternalGraphRequest -Uri "/v1.0/users"

# Disable pagination
$firstPage = Invoke-InternalGraphRequest -Uri "/v1.0/users" -FollowPagination:$false

# POST with body
$body = @{
    displayName = "Test App"
    requiredResourceAccess = @()
}
$app = Invoke-InternalGraphRequest -Uri "/v1.0/applications" -Method POST -Body $body

# Custom retry count
$result = Invoke-InternalGraphRequest -Uri "/beta/networkAccess/connectivity" -MaxRetries 6

# From another function (auto-detects calling command)
function Get-MyCustomData {
    # Will automatically use "Get-MyCustomData" in the Command header
    return Invoke-InternalGraphRequest -Uri "/v1.0/me"
}
```

## Integration with Existing Code

### Migration Path
1. Replace direct `Invoke-GraphRequest` calls with `Invoke-InternalGraphRequest`
2. Remove manual retry logic from calling functions
3. Simplify error handling in calling functions

### Example Migration
```powershell
# Before:
$customHeaders = New-EntraBetaCustomHeaders -Command 'Start-EntraPrivateAccessProvisioning'
$null = Invoke-GraphRequest -Method GET -Headers $customHeaders -OutputType PSObject -Uri "/beta/networkAccess/tenantStatus"

# After:
$null = Invoke-InternalGraphRequest -Uri "/beta/networkAccess/tenantStatus"
# CallingCommand automatically detected as "Start-EntraPrivateAccessProvisioning"
```

## Dependencies
- `Invoke-GraphRequest` cmdlet (from Microsoft.Graph.Authentication module)
- `New-EntraBetaCustomHeaders` cmdlet
- `Write-LogMessage` function for logging

## Testing Considerations
- Mock `Invoke-GraphRequest` to simulate 429 responses
- Test Retry-After header parsing (both formats)
- Verify exponential backoff calculations
- Test pagination aggregation
- Validate error messages after max retries

## Future Enhancements (Out of Scope)
- Async operation monitoring (202 Accepted responses)
- Request batching for optimization
- Proactive rate limiting
- Circuit breaker pattern
- Response caching
- Telemetry and metrics collection

## Notes
- This function is internal and not exposed as a public cmdlet
- All Graph API calls in the module should migrate to use this function
- The function wraps the existing `Invoke-GraphRequest` rather than replacing it
- Token management remains handled by `Invoke-GraphRequest`
