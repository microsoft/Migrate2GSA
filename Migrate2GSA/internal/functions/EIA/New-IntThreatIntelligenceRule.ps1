function New-IntThreatIntelligenceRule {
    <#
    .SYNOPSIS
        Creates a new threat intelligence rule for a threat intelligence policy.
    
    .DESCRIPTION
        Creates a new threat intelligence rule in Microsoft Graph API for a specific
        threat intelligence policy. Supports FQDN destinations with wildcards.
    
    .PARAMETER PolicyId
        The unique identifier of the threat intelligence policy.
    
    .PARAMETER Name
        The name of the threat intelligence rule.
    
    .PARAMETER Priority
        The processing priority of the rule (lower numbers = higher priority).
    
    .PARAMETER Description
        Optional description of the rule.
    
    .PARAMETER Action
        The action to take. Valid values: allow, block.
    
    .PARAMETER Status
        The status of the rule. Valid values: enabled, disabled, reportOnly.
    
    .PARAMETER Severity
        The severity level. Valid values: low, medium, high.
    
    .PARAMETER Fqdns
        Array of fully qualified domain names to match. Supports wildcards.
    
    .EXAMPLE
        New-IntThreatIntelligenceRule -PolicyId "975d3ea5-a5df-43f4-b725-c1f952e59d6a" -Name "Block Bad Sites" -Priority 100 -Action block -Status enabled -Severity high -Fqdns @("badsite.com", "*.verybadwebsite.com")
        Creates a new threat intelligence rule blocking specified threat domains.
    
    .EXAMPLE
        New-IntThreatIntelligenceRule -PolicyId "975d3ea5-a5df-43f4-b725-c1f952e59d6a" -Name "Allow Known Safe Sites" -Priority 50 -Description "Whitelist for false positives" -Action allow -Status enabled -Severity low -Fqdns @("safecorp.com")
        Creates a new threat intelligence rule allowing specified domains.
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
        [ValidateSet('allow', 'block')]
        [string]$Action,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('enabled', 'disabled', 'reportOnly')]
        [string]$Status,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('low', 'medium', 'high')]
        [string]$Severity,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Fqdns
    )

    try {
        $body = @{
            '@odata.type'       = '#microsoft.graph.networkaccess.threatIntelligenceRule'
            name                = $Name
            priority            = $Priority
            action              = $Action
            settings            = @{
                status = $Status
            }
            matchingConditions  = @{
                severity     = $Severity
                destinations = @(
                    @{
                        '@odata.type' = '#microsoft.graph.networkaccess.threatIntelligenceFqdnDestination'
                        values        = $Fqdns
                    }
                )
            }
        }

        if ($Description) {
            $body['description'] = $Description
        }

        $bodyJson = $body | ConvertTo-Json -Depth 10
        $uri = "https://graph.microsoft.com/beta/networkAccess/threatIntelligencePolicies/$PolicyId/policyRules"

        $response = Invoke-InternalGraphRequest -Method POST -Uri $uri -Body $bodyJson
        return $response
    }
    catch {
        Write-Error "Failed to create threat intelligence rule: $_"
        throw
    }
}
