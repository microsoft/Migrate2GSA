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
        The action to take. Valid values: block, allow. Only used for filtering policies.
    
    .PARAMETER PolicyType
        The type of policy being linked. Valid values: WebContentFiltering, TLSInspection.
        This determines the correct @odata.type to use in the request.
    
    .EXAMPLE
        New-IntFilteringPolicyLink -ProfileId "profile-id" -PolicyId "policy-id" -Priority 100 -PolicyType "WebContentFiltering"
        Creates a new web content filtering policy link with default enabled state.
    
    .EXAMPLE
        New-IntFilteringPolicyLink -ProfileId "profile-id" -PolicyId "policy-id" -Priority 50 -State enabled -LoggingState disabled -Action allow -PolicyType "WebContentFiltering"
        Creates a new web content filtering policy link with custom settings.
    
    .EXAMPLE
        New-IntFilteringPolicyLink -ProfileId "profile-id" -PolicyId "policy-id" -Priority 100 -PolicyType "TLSInspection"
        Creates a new TLS inspection policy link.
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
        [string]$Action,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('WebContentFiltering', 'TLSInspection')]
        [string]$PolicyType = 'WebContentFiltering'
    )

    try {
        # Determine @odata.type based on policy type
        $policyLinkOdataType = if ($PolicyType -eq 'TLSInspection') {
            '#microsoft.graph.networkaccess.tlsInspectionPolicyLink'
        }
        else {
            '#microsoft.graph.networkaccess.filteringPolicyLink'
        }
        
        $policyOdataType = if ($PolicyType -eq 'TLSInspection') {
            '#microsoft.graph.networkaccess.tlsInspectionPolicy'
        }
        else {
            '#microsoft.graph.networkaccess.filteringPolicy'
        }
        
        $body = @{
            priority             = $Priority
            state                = $State
            '@odata.type'        = $policyLinkOdataType
            loggingState         = $LoggingState
            policy               = @{
                id            = $PolicyId
                '@odata.type' = $policyOdataType
            }
        }
        
        # Only add action for filtering policies (not for TLS inspection)
        if ($PolicyType -eq 'WebContentFiltering' -and $Action) {
            $body['action'] = $Action
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
