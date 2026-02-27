function Get-FilteringRuleDestinations {
    <#
    .SYNOPSIS
        Extracts destination values from a web content filtering rule.
    
    .DESCRIPTION
        Parses a web content filtering rule object and extracts destination values based on the rule type.
        Handles different destination object structures for FQDN, URL, and webCategory rules.
        
        Rule destinations are returned as objects with different properties:
        - FQDN rules: destinations[].value
        - URL rules: destinations[].value
        - webCategory rules: destinations[].name
    
    .PARAMETER Rule
        The filtering rule object returned from Get-IntFilteringRule.
    
    .OUTPUTS
        System.String[]
        Array of destination strings ready for CSV export (join with semicolons).
    
    .EXAMPLE
        $rule = Get-IntFilteringRule -PolicyId $policyId | Select-Object -First 1
        $destinations = Get-FilteringRuleDestinations -Rule $rule
        $csvField = $destinations -join ';'
    
    .EXAMPLE
        $rules = Get-IntFilteringRule -PolicyId $policyId
        foreach ($rule in $rules) {
            $destinations = Get-FilteringRuleDestinations -Rule $rule
            Write-Host "Rule '$($rule.name)' has $($destinations.Count) destination(s)"
        }
    
    .NOTES
        Author: Franck Heilmann and Andres Canello
        Used by: Export-EntraInternetAccessConfig
        
        This function is specific to web content filtering rules. For TLS inspection rules,
        use Get-TlsInspectionRuleDestinations instead.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [PSCustomObject]$Rule
    )

    try {
        # Validate rule has required properties
        if (-not $Rule.PSObject.Properties['ruleType']) {
            Write-LogMessage "Rule object missing 'ruleType' property. Cannot extract destinations." -Level ERROR -Component "DestinationExtraction"
            return @()
        }

        if (-not $Rule.PSObject.Properties['destinations']) {
            Write-LogMessage "Rule '$($Rule.name)' has no 'destinations' property. Returning empty array." -Level WARN -Component "DestinationExtraction"
            return @()
        }

        # Handle null or empty destinations
        if (-not $Rule.destinations -or @($Rule.destinations).Count -eq 0) {
            Write-LogMessage "Rule '$($Rule.name)' has null or empty destinations array." -Level WARN -Component "DestinationExtraction"
            return @()
        }

        # Extract destinations based on rule type
        $destinations = @()
        $ruleType = $Rule.ruleType.ToLower()

        switch ($ruleType) {
            'fqdn' {
                # FQDN destinations: Extract .value property
                foreach ($dest in $Rule.destinations) {
                    if ($dest.PSObject.Properties['value'] -and -not [string]::IsNullOrWhiteSpace($dest.value)) {
                        $destinations += $dest.value
                    }
                    else {
                        Write-LogMessage "FQDN destination in rule '$($Rule.name)' missing 'value' property or is empty" -Level WARN -Component "DestinationExtraction"
                    }
                }
            }
            'url' {
                # URL destinations: Extract .value property (same as FQDN)
                foreach ($dest in $Rule.destinations) {
                    if ($dest.PSObject.Properties['value'] -and -not [string]::IsNullOrWhiteSpace($dest.value)) {
                        $destinations += $dest.value
                    }
                    else {
                        Write-LogMessage "URL destination in rule '$($Rule.name)' missing 'value' property or is empty" -Level WARN -Component "DestinationExtraction"
                    }
                }
            }
            'webcategory' {
                # Web category destinations: Extract .name property (not displayName)
                foreach ($dest in $Rule.destinations) {
                    if ($dest.PSObject.Properties['name'] -and -not [string]::IsNullOrWhiteSpace($dest.name)) {
                        $destinations += $dest.name
                    }
                    else {
                        Write-LogMessage "WebCategory destination in rule '$($Rule.name)' missing 'name' property or is empty" -Level WARN -Component "DestinationExtraction"
                    }
                }
            }
            default {
                Write-LogMessage "Unknown rule type '$ruleType' in rule '$($Rule.name)'. Cannot extract destinations." -Level ERROR -Component "DestinationExtraction"
                return @()
            }
        }

        if ($destinations.Count -eq 0) {
            Write-LogMessage "No valid destinations extracted from rule '$($Rule.name)' (type: $ruleType)" -Level WARN -Component "DestinationExtraction"
        }

        return $destinations
    }
    catch {
        Write-LogMessage "Error extracting destinations from rule '$($Rule.name)': $_" -Level ERROR -Component "DestinationExtraction"
        return @()
    }
}
