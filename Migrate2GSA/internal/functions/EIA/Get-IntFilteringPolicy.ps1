function Get-IntFilteringPolicy {
    <#
    .SYNOPSIS
        Retrieves Entra Internet Access filtering policies.
    
    .DESCRIPTION
        Gets filtering policies from Microsoft Graph API. Can retrieve all policies,
        a specific policy by ID, or filter by exact name match.
    
    .PARAMETER Id
        The unique identifier of the filtering policy to retrieve.
    
    .PARAMETER Name
        The exact name of the filtering policy to retrieve.
    
    .EXAMPLE
        Get-IntFilteringPolicy
        Retrieves all filtering policies.
    
    .EXAMPLE
        Get-IntFilteringPolicy -Id "12345678-1234-1234-1234-123456789012"
        Retrieves a specific filtering policy by ID.
    
    .EXAMPLE
        Get-IntFilteringPolicy -Name "Block Social Media"
        Retrieves filtering policy/policies with exact name match.
    #>
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [ValidateNotNullOrEmpty()]
        [string]$Id,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    try {
        $uri = switch ($PSCmdlet.ParameterSetName) {
            'ById' {
                "https://graph.microsoft.com/beta/networkAccess/filteringPolicies/$Id"
            }
            'ByName' {
                "https://graph.microsoft.com/beta/networkAccess/filteringPolicies?`$filter=name eq '$Name'"
            }
            default {
                "https://graph.microsoft.com/beta/networkAccess/filteringPolicies"
            }
        }

        $response = Invoke-InternalGraphRequest -Method GET -Uri $uri
        return $response
    }
    catch {
        Write-Error "Failed to retrieve filtering policy: $_"
        throw
    }
}
