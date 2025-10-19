function Get-IntThreatIntelligencePolicy {
    <#
    .SYNOPSIS
        Retrieves Entra Internet Access threat intelligence policies.
    
    .DESCRIPTION
        Gets threat intelligence policies from Microsoft Graph API. Can retrieve all policies,
        a specific policy by ID, or filter by exact name match.
    
    .PARAMETER Id
        The unique identifier of the threat intelligence policy to retrieve.
    
    .PARAMETER Name
        The exact name of the threat intelligence policy to retrieve.
    
    .EXAMPLE
        Get-IntThreatIntelligencePolicy
        Retrieves all threat intelligence policies.
    
    .EXAMPLE
        Get-IntThreatIntelligencePolicy -Id "12345678-1234-1234-1234-123456789012"
        Retrieves a specific threat intelligence policy by ID.
    
    .EXAMPLE
        Get-IntThreatIntelligencePolicy -Name "Block Known Threats"
        Retrieves threat intelligence policy/policies with exact name match.
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
                "https://graph.microsoft.com/beta/networkAccess/threatIntelligencePolicies/$Id"
            }
            'ByName' {
                "https://graph.microsoft.com/beta/networkAccess/threatIntelligencePolicies?`$filter=name eq '$Name'"
            }
            default {
                "https://graph.microsoft.com/beta/networkAccess/threatIntelligencePolicies"
            }
        }

        $response = Invoke-InternalGraphRequest -Method GET -Uri $uri
        return $response
    }
    catch {
        Write-Error "Failed to retrieve threat intelligence policy: $_"
        throw
    }
}
