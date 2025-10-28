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
    
    .PARAMETER ExpandLinks
        When specified, expands both policy links (filtering policies, threat intelligence, etc.) 
        and Conditional Access policy links associated with the security profile.
    
    .EXAMPLE
        Get-IntSecurityProfile
        Retrieves all security profiles.
    
    .EXAMPLE
        Get-IntSecurityProfile -Id "12345678-1234-1234-1234-123456789012"
        Retrieves a specific security profile by ID.
    
    .EXAMPLE
        Get-IntSecurityProfile -Name "Production Profile"
        Retrieves security profile(s) with exact name match.
    
    .EXAMPLE
        Get-IntSecurityProfile -ExpandLinks
        Retrieves all security profiles with expanded policy links and Conditional Access policy links.
    
    .EXAMPLE
        Get-IntSecurityProfile -Id "12345678-1234-1234-1234-123456789012" -ExpandLinks
        Retrieves a specific security profile by ID with expanded links.
    #>
    [CmdletBinding(DefaultParameterSetName = 'All')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ById')]
        [ValidateNotNullOrEmpty()]
        [string]$Id,
        
        [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [switch]$ExpandLinks
    )

    try {
        # Build base URI
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

        # Add expand query parameter if switch is specified
        if ($ExpandLinks) {
            $expandParam = '?$expand=policies($expand=policy),ConditionalAccessPolicies'
            
            # Determine correct separator based on whether URI already has query parameters
            if ($uri -match '\?') {
                $uri += "&$($expandParam.TrimStart('?'))"
            }
            else {
                $uri += $expandParam
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
