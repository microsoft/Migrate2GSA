function Get-IntSecurityProfile {
    <#
    .SYNOPSIS
        Retrieves Entra Internet Access security profiles (filtering profiles).
    
    .DESCRIPTION
        Gets security profiles from Microsoft Graph API. Can retrieve all profiles,
        a specific profile by ID, or filter by exact name match.
    
    .PARAMETER Id
        The unique identifier of the security profile to retrieve.
    
    .PARAMETER Name
        The exact name of the security profile to retrieve.
    
    .EXAMPLE
        Get-IntSecurityProfile
        Retrieves all security profiles.
    
    .EXAMPLE
        Get-IntSecurityProfile -Id "12345678-1234-1234-1234-123456789012"
        Retrieves a specific security profile by ID.
    
    .EXAMPLE
        Get-IntSecurityProfile -Name "Production Profile"
        Retrieves security profile(s) with exact name match.
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
                "https://graph.microsoft.com/beta/networkAccess/filteringProfiles/$Id"
            }
            'ByName' {
                "https://graph.microsoft.com/beta/networkAccess/filteringProfiles?`$filter=name eq '$Name'"
            }
            default {
                "https://graph.microsoft.com/beta/networkAccess/filteringProfiles"
            }
        }

        $response = Invoke-InternalGraphRequest -Method GET -Uri $uri
        return $response
    }
    catch {
        Write-Error "Failed to retrieve security profile: $_"
        throw
    }
}
