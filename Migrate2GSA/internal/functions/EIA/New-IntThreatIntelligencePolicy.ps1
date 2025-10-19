function New-IntThreatIntelligencePolicy {
    <#
    .SYNOPSIS
        Creates a new Entra Internet Access threat intelligence policy.
    
    .DESCRIPTION
        Creates a new threat intelligence policy in Microsoft Graph API with the
        specified name and description.
    
    .PARAMETER Name
        The name of the threat intelligence policy.
    
    .PARAMETER Description
        Optional description of the threat intelligence policy.
    
    .EXAMPLE
        New-IntThreatIntelligencePolicy -Name "Block Known Threats"
        Creates a new threat intelligence policy.
    
    .EXAMPLE
        New-IntThreatIntelligencePolicy -Name "High Severity Threats" -Description "Block high severity threat indicators"
        Creates a new threat intelligence policy with description.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Description
    )

    try {
        $body = @{
            name        = $Name
            policyRules = @()
        }

        if ($Description) {
            $body['description'] = $Description
        }

        $bodyJson = $body | ConvertTo-Json -Depth 10
        $uri = "https://graph.microsoft.com/beta/networkAccess/threatIntelligencePolicies"

        $response = Invoke-InternalGraphRequest -Method POST -Uri $uri -Body $bodyJson
        return $response
    }
    catch {
        Write-Error "Failed to create threat intelligence policy: $_"
        throw
    }
}
