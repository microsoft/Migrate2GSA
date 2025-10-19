function New-IntSecurityProfile {
    <#
    .SYNOPSIS
        Creates a new Entra Internet Access security profile (filtering profile).
    
    .DESCRIPTION
        Creates a new security profile in Microsoft Graph API with the specified
        name, description, state, and priority.
    
    .PARAMETER Name
        The name of the security profile.
    
    .PARAMETER Description
        Optional description of the security profile.
    
    .PARAMETER State
        The state of the profile. Valid values: enabled, disabled.
    
    .PARAMETER Priority
        The processing priority of the profile (higher numbers = lower priority).
    
    .EXAMPLE
        New-IntSecurityProfile -Name "Production Profile" -State enabled -Priority 100
        Creates a new enabled security profile with priority 100.
    
    .EXAMPLE
        New-IntSecurityProfile -Name "Test Profile" -Description "Test environment" -State disabled -Priority 200
        Creates a new disabled security profile with description and priority 200.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('enabled', 'disabled')]
        [string]$State,
        
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Priority
    )

    try {
        $body = @{
            name        = $Name
            state       = $State
            priority    = $Priority
            policies    = @()
        }

        if ($Description) {
            $body['description'] = $Description
        }

        $bodyJson = $body | ConvertTo-Json -Depth 10
        $uri = "https://graph.microsoft.com/beta/networkAccess/filteringProfiles"

        $response = Invoke-InternalGraphRequest -Method POST -Uri $uri -Body $bodyJson
        return $response
    }
    catch {
        Write-Error "Failed to create security profile: $_"
        throw
    }
}
