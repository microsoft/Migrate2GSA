function New-IntFqdnFilteringRule {
    <#
    .SYNOPSIS
        Creates a new FQDN filtering rule for a filtering policy.
    
    .DESCRIPTION
        Creates a new FQDN-based filtering rule in Microsoft Graph API for a specific
        filtering policy. Supports wildcard FQDNs (e.g., *.example.com).
    
    .PARAMETER PolicyId
        The unique identifier of the filtering policy.
    
    .PARAMETER Name
        The name of the filtering rule.
    
    .PARAMETER Fqdns
        Array of fully qualified domain names to filter. Supports wildcards.
    
    .EXAMPLE
        New-IntFqdnFilteringRule -PolicyId "policy-id" -Name "Block Social Media" -Fqdns @("facebook.com", "*.twitter.com")
        Creates a new FQDN filtering rule blocking specified domains.
    
    .EXAMPLE
        New-IntFqdnFilteringRule -PolicyId "policy-id" -Name "Block Example" -Fqdns @("example.com")
        Creates a new FQDN filtering rule for a single domain.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PolicyId,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Fqdns
    )

    try {
        $destinations = @()
        foreach ($fqdn in $Fqdns) {
            $destinations += @{
                '@odata.type' = '#microsoft.graph.networkaccess.fqdn'
                value         = $fqdn
            }
        }

        $body = @{
            '@odata.type' = '#microsoft.graph.networkaccess.fqdnFilteringRule'
            name          = $Name
            ruleType      = 'fqdn'
            destinations  = $destinations
        }

        $bodyJson = $body | ConvertTo-Json -Depth 10
        $uri = "https://graph.microsoft.com/beta/networkAccess/filteringPolicies/$PolicyId/policyRules"

        $response = Invoke-InternalGraphRequest -Method POST -Uri $uri -Body $bodyJson
        return $response
    }
    catch {
        Write-Error "Failed to create FQDN filtering rule: $_"
        throw
    }
}
