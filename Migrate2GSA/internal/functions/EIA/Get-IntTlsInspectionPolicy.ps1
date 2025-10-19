function Get-IntTlsInspectionPolicy {
    <#
    .SYNOPSIS
        Retrieves Entra Internet Access TLS inspection policies.
    
    .DESCRIPTION
        Gets TLS inspection policies from Microsoft Graph API. Can retrieve all policies,
        a specific policy by ID, or filter by exact name match.
    
    .PARAMETER Id
        The unique identifier of the TLS inspection policy to retrieve.
    
    .PARAMETER Name
        The exact name of the TLS inspection policy to retrieve.
    
    .EXAMPLE
        Get-IntTlsInspectionPolicy
        Retrieves all TLS inspection policies.
    
    .EXAMPLE
        Get-IntTlsInspectionPolicy -Id "12345678-1234-1234-1234-123456789012"
        Retrieves a specific TLS inspection policy by ID.
    
    .EXAMPLE
        Get-IntTlsInspectionPolicy -Name "Corporate TLS Policy"
        Retrieves TLS inspection policy/policies with exact name match.
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
                "https://graph.microsoft.com/beta/networkAccess/tlsInspectionPolicies/$Id"
            }
            'ByName' {
                "https://graph.microsoft.com/beta/networkAccess/tlsInspectionPolicies?`$filter=name eq '$Name'"
            }
            default {
                "https://graph.microsoft.com/beta/networkAccess/tlsInspectionPolicies"
            }
        }

        $response = Invoke-InternalGraphRequest -Method GET -Uri $uri
        return $response
    }
    catch {
        Write-Error "Failed to retrieve TLS inspection policy: $_"
        throw
    }
}
