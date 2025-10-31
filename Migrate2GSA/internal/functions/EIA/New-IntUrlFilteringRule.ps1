function New-IntUrlFilteringRule {
    <#
    .SYNOPSIS
        Creates a new URL filtering rule for a filtering policy.
    
    .DESCRIPTION
        Creates a new URL-based filtering rule in Microsoft Graph API for a specific
        filtering policy. Accepts full URLs including protocol and path.
    
    .PARAMETER PolicyId
        The unique identifier of the filtering policy.
    
    .PARAMETER Name
        The name of the filtering rule.
    
    .PARAMETER Urls
        Array of full URLs to filter (including protocol and path).
    
    .EXAMPLE
        New-IntUrlFilteringRule -PolicyId "policy-id" -Name "Block Specific Pages" -Urls @("https://example.com/blocked", "https://test.com/admin")
        Creates a new URL filtering rule blocking specified URLs.
    
    .EXAMPLE
        New-IntUrlFilteringRule -PolicyId "policy-id" -Name "Block Login Page" -Urls @("https://example.com/login")
        Creates a new URL filtering rule for a single URL.
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
        [string[]]$Urls
    )

    try {
        $destinations = @()
        foreach ($url in $Urls) {
            $destinations += @{
                '@odata.type' = '#microsoft.graph.networkaccess.url'
                value         = $url
            }
        }

        $body = @{
            '@odata.type' = '#microsoft.graph.networkaccess.fqdnFilteringRule'
            name          = $Name
            ruleType      = 'url'
            destinations  = $destinations
        }

        $bodyJson = $body | ConvertTo-Json -Depth 10
        $uri = "https://graph.microsoft.com/beta/networkAccess/filteringPolicies/$PolicyId/policyRules"

        $response = Invoke-InternalGraphRequest -Method POST -Uri $uri -Body $bodyJson
        return $response
    }
    catch {
        Write-Error "Failed to create URL filtering rule: $_"
        throw
    }
}
