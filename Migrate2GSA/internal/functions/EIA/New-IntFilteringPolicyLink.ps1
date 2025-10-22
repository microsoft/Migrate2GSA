function New-IntFilteringPolicyLink {
    <#
    .SYNOPSIS
        Creates a new filtering policy link to a security profile.
    
    .DESCRIPTION
        Links a filtering policy to a security profile with specified priority,
        state, logging state, and action.
    
    .PARAMETER ProfileId
        The unique identifier of the security profile.
    
    .PARAMETER PolicyId
        The unique identifier of the filtering policy to link.
    
    .PARAMETER Priority
        The processing priority of the policy link.
    
    .PARAMETER State
        The state of the policy link. Valid values: enabled, disabled. Default: enabled.
    
    .PARAMETER LoggingState
        The logging state. Valid values: enabled, disabled. Default: enabled.
    
    .PARAMETER Action
        The action to take. Valid values: block, allow.
    
    .EXAMPLE
        New-IntFilteringPolicyLink -ProfileId "profile-id" -PolicyId "policy-id" -Priority 100
        Creates a new policy link with default enabled state and block action.
    
    .EXAMPLE
        New-IntFilteringPolicyLink -ProfileId "profile-id" -PolicyId "policy-id" -Priority 50 -State enabled -LoggingState disabled -Action allow
        Creates a new policy link with custom settings.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ProfileId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Priority,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('enabled', 'disabled')]
        [string]$State = 'enabled',
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('enabled', 'disabled')]
        [string]$LoggingState = 'enabled',
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('block', 'allow')]
        [string]$Action
    )

    try {
        $body = @{
            priority             = $Priority
            state                = $State
            '@odata.type'        = '#microsoft.graph.networkaccess.filteringPolicyLink'
            loggingState         = $LoggingState
            action               = $Action
            policy               = @{
                id            = $PolicyId
                '@odata.type' = '#microsoft.graph.networkaccess.filteringPolicy'
            }
        }

        $bodyJson = $body | ConvertTo-Json -Depth 10
        $uri = "https://graph.microsoft.com/beta/networkAccess/filteringProfiles/$ProfileId/policies"

        $response = Invoke-InternalGraphRequest -Method POST -Uri $uri -Body $bodyJson
        return $response
    }
    catch {
        Write-Error "Failed to create filtering policy link: $_"
        throw
    }
}
