function Get-IntServicePrincipal {
    <#
    .SYNOPSIS
        Retrieves service principals from Microsoft Entra ID with optional filtering.
    
    .DESCRIPTION
        Queries Microsoft Entra ID to retrieve service principals using the Microsoft Graph API.
        Supports OData filter expressions to retrieve specific service principals based on various
        properties such as displayName, appId, servicePrincipalType, accountEnabled, and more.
        
        The function supports standard OData filter operators including:
        - Equality: eq, ne
        - Comparison: lt, gt, le, ge
        - Logical: and, or, not
        - String functions: startswith, endswith, contains
        - Lambda operators: any, all (for collections)
        
        For advanced queries using 'not', 'ne', 'endswith', or lambda operators, the function
        automatically includes the ConsistencyLevel header and $count parameter as required by
        Microsoft Graph.
    
    .PARAMETER Id
        The object ID of the service principal to retrieve. When provided, the function
        retrieves the service principal directly by ID, ignoring any Filter parameter.
    
    .PARAMETER Filter
        OData filter expression to query service principals. If not provided, returns all
        service principals in the tenant (subject to Microsoft Graph pagination limits).
        This parameter is ignored if Id is specified.
        
        Common filter examples:
        - "displayName eq 'MyApp'" - Exact match
        - "appId eq '00000000-0000-0000-0000-000000000000'" - By application ID
        - "startswith(displayName, 'Finance')" - Starts with
        - "servicePrincipalType eq 'Application'" - By type
        - "accountEnabled eq true" - Active only
        - "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')" - By tag
    
    .OUTPUTS
        Returns service principal objects with all properties from Microsoft Graph.
        Returns $null if no service principals match the filter criteria.
    
    .EXAMPLE
        Get-ServicePrincipal -Id 'a1b2c3d4-e5f6-4a5b-8c7d-9e8f7a6b5c4d'
        Retrieves the service principal with the specified object ID directly.
    
    .EXAMPLE
        Get-ServicePrincipal -Filter "appId eq 'a1b2c3d4-e5f6-4a5b-8c7d-9e8f7a6b5c4d'"
        Retrieves the service principal with the specified application ID using filter.
    
    .EXAMPLE
        Get-ServicePrincipal -Filter "displayName eq 'Contoso App'"
        Retrieves the service principal with exact display name match.
    
    .EXAMPLE
        Get-ServicePrincipal -Filter "startswith(displayName, 'Azure')"
        Retrieves all service principals whose display name starts with "Azure".
    
    .EXAMPLE
        Get-ServicePrincipal -Filter "servicePrincipalType eq 'Application' and accountEnabled eq true"
        Retrieves all enabled application service principals.
    
    .EXAMPLE
        Get-ServicePrincipal -Filter "tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')"
        Retrieves service principals with the specified tag using lambda operator.
    
    .EXAMPLE
        Get-ServicePrincipal
        Retrieves all service principals in the tenant.
    
    .NOTES
        Author: GitHub Copilot
        Requires: Microsoft Graph API permissions (Application.Read.All or Directory.Read.All minimum)
        
        Advanced Query Requirements:
        Some filter operations require advanced query capabilities and will automatically include
        the ConsistencyLevel: eventual header and $count=true parameter. These include:
        - not operator
        - ne operator
        - endswith function
        - Lambda operators (any, all)
        - Filtering on certain properties
        
    .LINK
        https://learn.microsoft.com/en-us/graph/filter-query-parameter
        https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'ById')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Id,
        
        [Parameter(Mandatory = $false, ParameterSetName = 'ByFilter')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Filter
    )
    
    process {
        try {
            # Build the base URI
            if ($Id) {
                # Direct retrieval by ID
                $uri = "https://graph.microsoft.com/beta/servicePrincipals/$Id"
                
                # Prepare parameters for the API request
                $params = @{
                    Method = 'GET'
                    Uri = $uri
                    OutputType = 'PSObject'
                }
                
                # Invoke the API request
                $response = Invoke-InternalGraphRequest @params
                
                return $response
            }
            else {
                # Filter-based or all service principals retrieval
                $uri = "https://graph.microsoft.com/beta/servicePrincipals"
                
                # Detect if advanced query is needed based on filter content
                $requiresAdvancedQuery = $false
                if ($Filter) {
                    # Check for operators and functions that require advanced query
                    $advancedPatterns = @(
                        '\bnot\s*\(',           # not operator
                        '\bne\b',               # ne operator
                        '\bendswith\s*\(',      # endswith function
                        '/any\s*\(',            # any lambda operator
                        '/all\s*\('             # all lambda operator
                    )
                    
                    foreach ($pattern in $advancedPatterns) {
                        if ($Filter -match $pattern) {
                            $requiresAdvancedQuery = $true
                            break
                        }
                    }
                }
                
                # Prepare parameters for the API request
                $params = @{
                    Method = 'GET'
                    Uri = $uri
                    OutputType = 'PSObject'
                }
                
                # Add filter to URI if provided
                if ($Filter) {
                    $encodedFilter = [System.Web.HttpUtility]::UrlEncode($Filter)
                    $params.Uri += "?`$filter=$encodedFilter"
                    
                    # Add count parameter for advanced queries
                    if ($requiresAdvancedQuery) {
                        $params.Uri += "&`$count=true"
                    }
                }
                
                # Add ConsistencyLevel header for advanced queries
                if ($requiresAdvancedQuery) {
                    $params['Headers'] = @{
                        'ConsistencyLevel' = 'eventual'
                    }
                }

                
                # Invoke the API request
                $response = Invoke-InternalGraphRequest @params
                
                # Handle response
                if ($response) {
                    # Check if response has a value property (collection)
                    if ($response.PSObject.Properties.Name -contains 'value') {
                        $servicePrincipals = $response.value
                        
                        if ($servicePrincipals -and $servicePrincipals.Count -gt 0) {
                            return $servicePrincipals
                        } else {
                            return $null
                        }
                    } else {
                        # Single object response
                        return $response
                    }
                } else {
                    return $null
                }
            }
        }
        catch {
            Write-Error "Failed to retrieve service principals: $_"
            throw
        }
    }
}
