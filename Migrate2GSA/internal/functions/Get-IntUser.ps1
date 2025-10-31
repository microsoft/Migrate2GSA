function Get-IntUser {
    <#
    .SYNOPSIS
        Retrieves users from Microsoft Entra ID with optional filtering.
    
    .DESCRIPTION
        Queries Microsoft Entra ID to retrieve users using the Microsoft Graph API.
        Supports OData filter expressions to retrieve specific users based on various
        properties such as userPrincipalName, displayName, mail, and more.
    
    .PARAMETER Filter
        OData filter expression to query users. If not provided, returns all
        users in the tenant (subject to Microsoft Graph pagination limits).
        
        Common filter examples:
        - "userPrincipalName eq 'john@contoso.com'" - Exact match
        - "startswith(displayName, 'John')" - Starts with
        - "mail eq 'john.doe@contoso.com'" - Email match
    
    .OUTPUTS
        Returns user objects with all properties from Microsoft Graph.
        Returns $null if no users match the filter criteria.
    
    .EXAMPLE
        Get-IntUser -Filter "userPrincipalName eq 'john@contoso.com'"
        Retrieves the user with the exact UPN.
    
    .EXAMPLE
        Get-IntUser -Filter "startswith(displayName, 'John')"
        Retrieves all users whose display name starts with "John".
    
    .NOTES
        Author: Andres Canello
        Requires: Microsoft Graph API permissions (User.Read.All minimum)
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
            $uri = "https://graph.microsoft.com/beta/users"
            
            # Prepare parameters for the API request
            $params = @{
                Method     = 'GET'
                Uri        = $uri
                OutputType = 'PSObject'
            }
            
            # Add filter to URI if provided
            if ($Filter) {
                $encodedFilter = [System.Web.HttpUtility]::UrlEncode($Filter)
                $params.Uri += "?`$filter=$encodedFilter"
            }
            
            # Invoke the API request
            $response = Invoke-InternalGraphRequest @params
            
            # Handle response
            if ($response) {
                # Check if response has a value property (collection)
                if ($response.PSObject.Properties.Name -contains 'value') {
                    $users = $response.value
                    
                    if ($users -and $users.Count -gt 0) {
                        return $users
                    }
                    else {
                        return $null
                    }
                }
                else {
                    # Single object response
                    return $response
                }
            }
            else {
                return $null
            }
        }
        catch {
            Write-Error "Failed to retrieve users: $_"
            throw
        }
    }
}
