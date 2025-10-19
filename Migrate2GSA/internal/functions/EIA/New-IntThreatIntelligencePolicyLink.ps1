function New-IntThreatIntelligencePolicyLink {
    <#
    .SYNOPSIS
        Creates a new threat intelligence policy link to a security profile.
    
    .DESCRIPTION
        Links a threat intelligence policy to a security profile with specified state.
    
    .PARAMETER ProfileId
        The unique identifier of the security profile.
    
    .PARAMETER PolicyId
        The unique identifier of the threat intelligence policy to link.
    
    .PARAMETER State
        The state of the policy link. Valid values: enabled, disabled. Default: enabled.
    
    .EXAMPLE
        New-IntThreatIntelligencePolicyLink -ProfileId "profile-id" -PolicyId "policy-id"
        Creates a new threat intelligence policy link with default enabled state.
    
    .EXAMPLE
        New-IntThreatIntelligencePolicyLink -ProfileId "profile-id" -PolicyId "policy-id" -State disabled
        Creates a new threat intelligence policy link in disabled state.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('enabled', 'disabled')]
        [string]$State = 'enabled'
    )

    try {
        $body = @{
            state         = $State
            '@odata.type' = '#microsoft.graph.networkaccess.threatIntelligencePolicyLink'
            policy        = @{
                id            = $PolicyId
                '@odata.type' = '#microsoft.graph.networkaccess.threatIntelligencePolicy'
            }
        }

        $bodyJson = $body | ConvertTo-Json -Depth 10
        $uri = "https://graph.microsoft.com/beta/networkAccess/filteringProfiles/$ProfileId/policies"

        $response = Invoke-InternalGraphRequest -Method POST -Uri $uri -Body $bodyJson
        return $response
    }
    catch {
        Write-Error "Failed to create threat intelligence policy link: $_"
        throw
    }
}
