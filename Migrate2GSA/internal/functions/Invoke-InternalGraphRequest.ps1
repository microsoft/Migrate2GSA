function Invoke-InternalGraphRequest {
    <#
    .SYNOPSIS
        Internal function to handle Microsoft Graph API requests with automatic throttling detection and retry logic.
    
    .DESCRIPTION
        Centralizes all Graph API calls with consistent error handling, automatic detection of 429 throttling
        responses, and exponential backoff with jitter as per Microsoft recommendations. Respects Retry-After
        headers when present and provides consistent logging for all Graph API operations.
    
    .PARAMETER Uri
        The Graph API endpoint URI (relative or absolute).
    
    .PARAMETER Method
        HTTP method to use. Valid values: GET, POST, PUT, PATCH, DELETE. Default: GET
    
    .PARAMETER Body
        Request body for POST/PUT/PATCH operations.
    
    .PARAMETER Headers
        Additional headers to include in the request. Command header is added automatically.
    
    .PARAMETER MaxRetries
        Maximum number of retry attempts for throttled requests. Default: 4
    
    .PARAMETER CallingCommand
        Name of calling function for header tracking. Auto-detected if not specified.
    
    .PARAMETER DisablePagination
        Disable automatic pagination. By default, the function follows @odata.nextLink for paginated results.
    
    .PARAMETER OutputType
        Output format. Valid values: PSObject, Json, Raw. Default: PSObject
    
    .OUTPUTS
        Returns the response from the Graph API in the specified format.
    
    .EXAMPLE
        $users = Invoke-InternalGraphRequest -Uri "/v1.0/users"
        Simple GET request with pagination enabled by default.
    
    .EXAMPLE
        $firstPage = Invoke-InternalGraphRequest -Uri "/v1.0/users" -DisablePagination
        GET request without pagination.
    
    .EXAMPLE
        $body = @{
            displayName = "Test App"
            requiredResourceAccess = @()
        }
        $app = Invoke-InternalGraphRequest -Uri "/v1.0/applications" -Method POST -Body $body
        POST request with body.
    
    .EXAMPLE
        $result = Invoke-InternalGraphRequest -Uri "/beta/networkAccess/connectivity" -MaxRetries 6
        GET request with custom retry count.
    
    .NOTES
        This is an internal function and should not be exported from the module.
        All Graph API calls in the module should use this function for consistent error handling.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Uri,
        
        [Parameter()]
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',
        
        [Parameter()]
        [object]$Body = $null,
        
        [Parameter()]
        [hashtable]$Headers = @{},
        
        [Parameter()]
        [ValidateRange(0, 10)]
        [int]$MaxRetries = 4,
        
        [Parameter()]
        [string]$CallingCommand = '',
        
        [Parameter()]
        [switch]$DisablePagination,
        
        [Parameter()]
        [ValidateSet('PSObject', 'Json', 'Raw')]
        [string]$OutputType = 'PSObject'
    )
    
    begin {
        # Auto-detect calling command if not specified
        if ([string]::IsNullOrWhiteSpace($CallingCommand)) {
            $callerInfo = Get-PSCallStack | Select-Object -Skip 1 -First 1
            if ($callerInfo -and $callerInfo.Command) {
                $CallingCommand = $callerInfo.Command
            } else {
                $CallingCommand = 'Unknown'
            }
        }
        
        # Constants for exponential backoff
        $baseDelayMs = 500
        $maxDelayMs = 10000
        $jitterMaxMs = 500
        $retryAfterJitterMaxMs = 200
        
        # Initialize results array for pagination
        $allResults = @()
    }
    
    process {
        $attempt = 0
        $currentUri = $Uri
        $hasMorePages = $true
        
        while ($hasMorePages) {
            $attempt = 0
            $success = $false
            $pageResult = $null
            
            while (-not $success -and $attempt -le $MaxRetries) {
                try {
                    # Build custom headers with calling command
                    $customHeaderParams = @{
                        Command = $CallingCommand
                    }
                    if ($DebugPreference -eq 'Continue') {
                        $customHeaderParams['Debug'] = $true
                    }
                    $commandHeaders = New-EntraBetaCustomHeaders @customHeaderParams
                    
                    # Merge with any additional headers provided
                    $mergedHeaders = @{}
                    # Copy commandHeaders to mergedHeaders
                    if ($commandHeaders) {
                        foreach ($key in $commandHeaders.Keys) {
                            $mergedHeaders[$key] = $commandHeaders[$key]
                        }
                    }
                    # Add any additional headers
                    if ($Headers) {
                        foreach ($key in $Headers.Keys) {
                            $mergedHeaders[$key] = $Headers[$key]
                        }
                    }
                    
                    # Build request parameters
                    $requestParams = @{
                        Method = $Method
                        Uri = $currentUri
                        Headers = $mergedHeaders
                        OutputType = $OutputType
                    }
                    
                    if ($Body) {
                        $requestParams['Body'] = $Body
                    }
                    
                    if ($DebugPreference -eq 'Continue') {
                        $requestParams['Debug'] = $true
                        Write-Debug "Invoke-InternalGraphRequest: Calling $Method $currentUri (Attempt $($attempt + 1)/$($MaxRetries + 1))"
                    }
                    
                    # Make the API request
                    $pageResult = Invoke-GraphRequest @requestParams
                    
                    $success = $true
                    
                    if ($DebugPreference -eq 'Continue') {
                        Write-Debug "Invoke-InternalGraphRequest: Request successful"
                    }
                }
                catch {
                    $exception = $_
                    $statusCode = $null
                    
                    # Try to extract status code from exception
                    if ($exception.Exception -and $exception.Exception.Response) {
                        $statusCode = [int]$exception.Exception.Response.StatusCode
                    } elseif ($exception.Exception.Message -match 'status code (\d+)') {
                        $statusCode = [int]$matches[1]
                    }
                    
                    # Check if this is a throttling error (429)
                    if ($statusCode -eq 429 -and $attempt -lt $MaxRetries) {
                        $attempt++
                        
                        # Try to get Retry-After header
                        $retryAfter = $null
                        $retryAfterSeconds = $null
                        
                        if ($exception.Exception.Response -and $exception.Exception.Response.Headers) {
                            $retryAfter = $exception.Exception.Response.Headers['Retry-After']
                        }
                        
                        if ($retryAfter) {
                            # Parse Retry-After header (can be seconds or HTTP-date)
                            if ($retryAfter -match '^\d+$') {
                                # Integer seconds
                                $retryAfterSeconds = [int]$retryAfter
                            } else {
                                # Try to parse as HTTP-date
                                try {
                                    $retryAfterDate = [DateTime]::ParseExact($retryAfter, 'R', [System.Globalization.CultureInfo]::InvariantCulture)
                                    $retryAfterSeconds = [int]($retryAfterDate - (Get-Date)).TotalSeconds
                                    if ($retryAfterSeconds -lt 0) { $retryAfterSeconds = 1 }
                                } catch {
                                    # Failed to parse, use exponential backoff
                                    $retryAfterSeconds = $null
                                }
                            }
                        }
                        
                        # Calculate delay
                        if ($retryAfterSeconds) {
                            # Use Retry-After value with small jitter
                            $jitter = Get-Random -Minimum 0 -Maximum $retryAfterJitterMaxMs
                            $delayMs = ($retryAfterSeconds * 1000) + $jitter
                            $delaySeconds = [math]::Round($delayMs / 1000.0, 2)
                            
                            Write-LogMessage "Retry $attempt/$MaxRetries after ${delaySeconds}s due to throttling (Retry-After: $retryAfter)" -Level INFO -Component "GraphAPI"
                        } else {
                            # Use exponential backoff with jitter
                            $exponentialDelay = $baseDelayMs * [math]::Pow(2, $attempt - 1)
                            $jitter = Get-Random -Minimum 0 -Maximum $jitterMaxMs
                            $delayMs = [math]::Min($exponentialDelay + $jitter, $maxDelayMs)
                            $delaySeconds = [math]::Round($delayMs / 1000.0, 2)
                            
                            if ($DebugPreference -eq 'Continue') {
                                Write-Debug "Invoke-InternalGraphRequest: Calculated backoff - Base: ${baseDelayMs}ms, Exponential: ${exponentialDelay}ms, Jitter: ${jitter}ms, Final: ${delayMs}ms"
                            }
                            
                            Write-LogMessage "Retry $attempt/$MaxRetries after ${delaySeconds}s due to throttling" -Level INFO -Component "GraphAPI"
                        }
                        
                        # Wait before retrying
                        Start-Sleep -Milliseconds $delayMs
                    } else {
                        # Not a throttling error or max retries exceeded
                        if ($statusCode -eq 429) {
                            Write-LogMessage "Maximum retry attempts ($MaxRetries) exceeded for throttled request to $currentUri" -Level ERROR -Component "GraphAPI"
                        }
                        
                        # Re-throw the exception
                        throw
                    }
                }
            }
            
            # Handle pagination
            if (-not $DisablePagination -and $pageResult) {
                # Check if result has value property (collection response)
                if ($pageResult.PSObject.Properties['value']) {
                    $allResults += $pageResult.value
                    
                    # Check for next page
                    if ($pageResult.PSObject.Properties['@odata.nextLink'] -and $pageResult.'@odata.nextLink') {
                        $currentUri = $pageResult.'@odata.nextLink'
                        
                        if ($DebugPreference -eq 'Continue') {
                            Write-Debug "Invoke-InternalGraphRequest: Following pagination to next page"
                        }
                    } else {
                        $hasMorePages = $false
                    }
                } else {
                    # Single object response, not a collection
                    $allResults = $pageResult
                    $hasMorePages = $false
                }
            } else {
                # Pagination disabled or no result
                $allResults = $pageResult
                $hasMorePages = $false
            }
        }
        
        return $allResults
    }
}
