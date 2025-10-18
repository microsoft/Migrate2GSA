function Get-IntGroup {
    <#
    .SYNOPSIS
        Retrieves groups from Microsoft Entra ID with optional filtering.
    
    .DESCRIPTION
        Queries Microsoft Entra ID to retrieve groups using the Microsoft Graph API.
        Supports OData filter expressions to retrieve specific groups based on various
        properties such as displayName, mailNickname, securityEnabled, mailEnabled, and more.
        
        The function supports standard OData filter operators including:
        - Equality: eq, ne
        - Comparison: lt, gt, le, ge
        - Logical: and, or, not
        - String functions: startswith, endswith, contains
        - Lambda operators: any, all (for collections)
        
        For advanced queries using 'not', 'ne', 'endswith', or lambda operators, the function
        automatically includes the ConsistencyLevel header and $count parameter as required by
        Microsoft Graph.
    
    .PARAMETER Filter
        OData filter expression to query groups. If not provided, returns all
        groups in the tenant (subject to Microsoft Graph pagination limits).
        
        Common filter examples:
        - "displayName eq 'Sales Team'" - Exact match
        - "startswith(displayName, 'Finance')" - Starts with
        - "securityEnabled eq true" - Security groups only
        - "mailEnabled eq true" - Mail-enabled groups
        - "groupTypes/any(c:c eq 'Unified')" - Microsoft 365 groups
        - "isAssignableToRole eq true" - Role-assignable groups
    
    .OUTPUTS
        Returns group objects with all properties from Microsoft Graph.
        Returns $null if no groups match the filter criteria.
    
    .EXAMPLE
        Get-IntGroup -Filter "displayName eq 'Convergence'"
        Retrieves the group with the exact display name "Convergence".
    
    .EXAMPLE
        Get-IntGroup -Filter "startswith(displayName, 'Sales')"
        Retrieves all groups whose display name starts with "Sales".
    
    .EXAMPLE
        Get-IntGroup -Filter "securityEnabled eq true and mailEnabled eq false"
        Retrieves all security groups that are not mail-enabled.
    
    .EXAMPLE
        Get-IntGroup -Filter "groupTypes/any(c:c eq 'Unified')"
        Retrieves all Microsoft 365 groups using lambda operator.
    
    .EXAMPLE
        Get-IntGroup
        Retrieves all groups in the tenant.
    
    .NOTES
        Author: GitHub Copilot
        Requires: Microsoft Graph API permissions (Group.Read.All or Directory.Read.All minimum)
        
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
        https://learn.microsoft.com/en-us/graph/api/group-list
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Filter
    )
    
    process {
        try {
            # Build the base URI
            $uri = "https://graph.microsoft.com/beta/groups"
            
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
                    $groups = $response.value
                    
                    if ($groups -and $groups.Count -gt 0) {
                        return $groups
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
        catch {
            Write-Error "Failed to retrieve groups: $_"
            throw
        }
    }
}
