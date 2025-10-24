function New-IntTlsInspectionRule {
    <#
    .SYNOPSIS
        Creates a new TLS inspection rule for a TLS inspection policy.
    
    .DESCRIPTION
        Creates a new TLS inspection rule in Microsoft Graph API for a specific TLS
        inspection policy. Supports FQDN and/or web category destinations.
    
    .PARAMETER PolicyId
        The unique identifier of the TLS inspection policy.
    
    .PARAMETER Name
        The name of the TLS inspection rule.
    
    .PARAMETER Priority
        The processing priority of the rule (lower numbers = higher priority).
    
    .PARAMETER Description
        Optional description of the rule.
    
    .PARAMETER Action
        The action to take. Valid values: bypass, inspect.
    
    .PARAMETER Status
        The status of the rule. Valid values: enabled, disabled.
    
    .PARAMETER Fqdns
        Optional array of fully qualified domain names. Supports wildcards.
    
    .PARAMETER WebCategories
        Optional array of web category names.
    
    .EXAMPLE
        New-IntTlsInspectionRule -PolicyId "policy-id" -Name "Bypass Financial Sites" -Priority 100 -Action bypass -Status enabled -Fqdns @("*.bank.com", "banking.example.com")
        Creates a new TLS inspection rule to bypass inspection for specified FQDNs.
    
    .EXAMPLE
        New-IntTlsInspectionRule -PolicyId "policy-id" -Name "Inspect Entertainment" -Priority 200 -Action inspect -Status enabled -WebCategories @("Entertainment", "SocialNetworking")
        Creates a new TLS inspection rule to inspect specified web categories.
    
    .EXAMPLE
        New-IntTlsInspectionRule -PolicyId "policy-id" -Name "Mixed Rule" -Priority 150 -Action bypass -Status enabled -Fqdns @("*.example.com") -WebCategories @("Banking")
        Creates a new TLS inspection rule with both FQDN and web category destinations.
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
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Priority,
        
        [Parameter(Mandatory = $false)]
        [string]$Description,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('bypass', 'inspect')]
        [string]$Action,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('enabled', 'disabled')]
        [string]$Status,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Fqdns,
        
        [Parameter(Mandatory = $false)]
        [string[]]$WebCategories
    )

    # Validate that at least one destination type is provided
    if (-not $Fqdns -and -not $WebCategories) {
        Write-Error "At least one of Fqdns or WebCategories must be provided."
        throw "At least one destination type (Fqdns or WebCategories) is required."
    }

    try {
        $destinations = @()

        # Add FQDN destinations
        if ($Fqdns) {
            $destinations += @{
                '@odata.type' = '#microsoft.graph.networkaccess.tlsInspectionFqdnDestination'
                values        = $Fqdns
            }
        }

        # Add web category destinations
        # Note: The API uses tlsInspectionWebCategoryDestination (singular) not tlsInspectionWebCategoriesDestination (plural)
        # as shown in the official documentation. This is the actual working format as of Oct 2025.
        if ($WebCategories) {
            $destinations += @{
                '@odata.type' = '#microsoft.graph.networkaccess.tlsInspectionWebCategoryDestination'
                values        = $WebCategories
            }
        }

        $body = @{
            '@odata.type'      = '#microsoft.graph.networkaccess.tlsInspectionRule'
            name               = $Name
            priority           = $Priority
            action             = $Action
            settings           = @{
                status = $Status
            }
            matchingConditions = @{
                destinations = $destinations
            }
        }

        if ($Description) {
            $body['description'] = $Description
        }

        $bodyJson = $body | ConvertTo-Json -Depth 10
        $uri = "https://graph.microsoft.com/beta/networkAccess/tlsInspectionPolicies/$PolicyId/policyRules"

        $response = Invoke-InternalGraphRequest -Method POST -Uri $uri -Body $bodyJson
        return $response
    }
    catch {
        Write-Error "Failed to create TLS inspection rule: $_"
        throw
    }
}
