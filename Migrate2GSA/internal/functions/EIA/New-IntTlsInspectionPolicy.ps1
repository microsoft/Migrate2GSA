function New-IntTlsInspectionPolicy {
    <#
    .SYNOPSIS
        Creates a new Entra Internet Access TLS inspection policy.
    
    .DESCRIPTION
        Creates a new TLS inspection policy in Microsoft Graph API with the
        specified name and description.
    
    .PARAMETER Name
        The name of the TLS inspection policy.
    
    .PARAMETER Description
        Optional description of the TLS inspection policy.
    
    .PARAMETER DefaultAction
        The default action to take when no rules in the policy match the traffic.
        Valid values: 'bypass', 'inspect'. Required.
    
    .EXAMPLE
        New-IntTlsInspectionPolicy -Name "Corporate TLS Policy" -DefaultAction "bypass"
        Creates a new TLS inspection policy with bypass as default action.
    
    .EXAMPLE
        New-IntTlsInspectionPolicy -Name "TLS Bypass Policy" -Description "Bypass TLS inspection for trusted sites" -DefaultAction "bypass"
        Creates a new TLS inspection policy with description and bypass action.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('bypass', 'inspect')]
        [string]$DefaultAction
    )

    try {
        $body = @{
            name        = $Name
            policyRules = @()
            settings    = @{
                defaultAction = $DefaultAction
            }
        }

        if ($Description) {
            $body['description'] = $Description
        }

        $bodyJson = $body | ConvertTo-Json -Depth 10
        $uri = "https://graph.microsoft.com/beta/networkAccess/tlsInspectionPolicies"

        $response = Invoke-InternalGraphRequest -Method POST -Uri $uri -Body $bodyJson
        return $response
    }
    catch {
        Write-Error "Failed to create TLS inspection policy: $_"
        throw
    }
}
