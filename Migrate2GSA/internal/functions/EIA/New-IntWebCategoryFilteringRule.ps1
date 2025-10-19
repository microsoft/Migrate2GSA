function New-IntWebCategoryFilteringRule {
    <#
    .SYNOPSIS
        Creates a new web category filtering rule for a filtering policy.
    
    .DESCRIPTION
        Creates a new web category-based filtering rule in Microsoft Graph API for a
        specific filtering policy. Uses predefined web categories like
        ArtificialIntelligence, Dating, Gambling, etc.
    
    .PARAMETER PolicyId
        The unique identifier of the filtering policy.
    
    .PARAMETER Name
        The name of the filtering rule.
    
    .PARAMETER Categories
        Array of web category names to filter.
    
    .EXAMPLE
        New-IntWebCategoryFilteringRule -PolicyId "policy-id" -Name "Block Entertainment" -Categories @("SocialNetworking", "Streaming")
        Creates a new web category filtering rule blocking specified categories.
    
    .EXAMPLE
        New-IntWebCategoryFilteringRule -PolicyId "policy-id" -Name "Block AI Sites" -Categories @("ArtificialIntelligence")
        Creates a new web category filtering rule for a single category.
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
        [string[]]$Categories
    )

    try {
        $destinations = @()
        foreach ($category in $Categories) {
            $destinations += @{
                '@odata.type' = '#microsoft.graph.networkaccess.webCategory'
                name          = $category
            }
        }

        $body = @{
            '@odata.type' = '#microsoft.graph.networkaccess.webCategoryFilteringRule'
            name          = $Name
            ruleType      = 'webCategory'
            destinations  = $destinations
        }

        $bodyJson = $body | ConvertTo-Json -Depth 10
        $uri = "https://graph.microsoft.com/beta/networkAccess/filteringPolicies/$PolicyId/policyRules"

        $response = Invoke-InternalGraphRequest -Method POST -Uri $uri -Body $bodyJson
        return $response
    }
    catch {
        Write-Error "Failed to create web category filtering rule: $_"
        throw
    }
}
