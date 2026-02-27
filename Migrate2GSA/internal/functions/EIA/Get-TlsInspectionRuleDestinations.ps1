function Get-TlsInspectionRuleDestinations {
    <#
    .SYNOPSIS
        Extracts destination values from a TLS inspection rule.
    
    .DESCRIPTION
        Parses a TLS inspection rule object and extracts destination values from the nested
        matchingConditions.destinations structure. Handles different destination types including
        web categories and FQDNs.
        
        TLS inspection rules have a different structure than filtering rules:
        - Destinations are nested in matchingConditions.destinations
        - Web categories come as values[] array (already strings)
        - FQDNs use similar object structure to filtering rules
        - matchingConditions can be null for system rules that match all traffic
    
    .PARAMETER Rule
        The TLS inspection rule object returned from Get-IntTlsInspectionRule.
    
    .OUTPUTS
        System.String[]
        Array of destination strings ready for CSV export (join with semicolons).
        Returns empty array if matchingConditions is null or no destinations found.
    
    .EXAMPLE
        $rule = Get-IntTlsInspectionRule -PolicyId $policyId | Select-Object -First 1
        $destinations = Get-TlsInspectionRuleDestinations -Rule $rule
        $csvField = $destinations -join ';'
    
    .EXAMPLE
        $rules = Get-IntTlsInspectionRule -PolicyId $policyId
        foreach ($rule in $rules) {
            $destinations = Get-TlsInspectionRuleDestinations -Rule $rule
            if ($destinations.Count -eq 0) {
                Write-Host "Rule '$($rule.name)' has no specific destinations (matches all)"
            }
        }
    
    .NOTES
        Author: Franck Heilmann and Andres Canello
        Used by: Export-EntraInternetAccessConfig
        
        This function is specific to TLS inspection rules. For web content filtering rules,
        use Get-FilteringRuleDestinations instead.
        
        System-generated rules may have null matchingConditions, which is expected behavior.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [PSCustomObject]$Rule
    )

    try {
        # TLS inspection rules may have null matchingConditions (e.g., system bypass rules)
        if (-not $Rule.PSObject.Properties['matchingConditions'] -or -not $Rule.matchingConditions) {
            Write-LogMessage "TLS rule '$($Rule.name)' has no matchingConditions (may be system rule matching all traffic)" -Level DEBUG -Component "DestinationExtraction"
            return @()
        }

        # Check if destinations exist within matchingConditions
        if (-not $Rule.matchingConditions.PSObject.Properties['destinations'] -or -not $Rule.matchingConditions.destinations) {
            Write-LogMessage "TLS rule '$($Rule.name)' has matchingConditions but no destinations array" -Level DEBUG -Component "DestinationExtraction"
            return @()
        }

        $destinations = @()
        $destinationObjects = @($Rule.matchingConditions.destinations)

        if ($destinationObjects.Count -eq 0) {
            Write-LogMessage "TLS rule '$($Rule.name)' has empty destinations array in matchingConditions" -Level DEBUG -Component "DestinationExtraction"
            return @()
        }

        # Process each destination object
        foreach ($dest in $destinationObjects) {
            # Determine destination type by @odata.type
            $odataType = if ($dest.PSObject.Properties['@odata.type']) { $dest.'@odata.type' } else { $null }

            if (-not $odataType) {
                Write-LogMessage "Destination in TLS rule '$($Rule.name)' missing @odata.type property" -Level WARN -Component "DestinationExtraction"
                continue
            }

            # Web category destinations
            if ($odataType -like '*webCategory*' -or $odataType -like '*WebCategory*') {
                if ($dest.PSObject.Properties['values'] -and $dest.values) {
                    # Values is already an array of strings
                    $categoryValues = @($dest.values)
                    foreach ($category in $categoryValues) {
                        if (-not [string]::IsNullOrWhiteSpace($category)) {
                            $destinations += $category
                        }
                    }
                }
                else {
                    Write-LogMessage "WebCategory destination in TLS rule '$($Rule.name)' missing 'values' array" -Level WARN -Component "DestinationExtraction"
                }
            }
            # FQDN destinations
            elseif ($odataType -like '*fqdn*' -or $odataType -like '*Fqdn*') {
                if ($dest.PSObject.Properties['value'] -and -not [string]::IsNullOrWhiteSpace($dest.value)) {
                    $destinations += $dest.value
                }
                else {
                    Write-LogMessage "FQDN destination in TLS rule '$($Rule.name)' missing 'value' property or is empty" -Level WARN -Component "DestinationExtraction"
                }
            }
            # Unknown destination type
            else {
                Write-LogMessage "Unknown destination type '$odataType' in TLS rule '$($Rule.name)'. Attempting to extract value/values." -Level WARN -Component "DestinationExtraction"
                
                # Attempt fallback extraction
                if ($dest.PSObject.Properties['value'] -and -not [string]::IsNullOrWhiteSpace($dest.value)) {
                    $destinations += $dest.value
                }
                elseif ($dest.PSObject.Properties['values'] -and $dest.values) {
                    $destinations += @($dest.values)
                }
            }
        }

        if ($destinations.Count -eq 0) {
            Write-LogMessage "No valid destinations extracted from TLS rule '$($Rule.name)'" -Level DEBUG -Component "DestinationExtraction"
        }

        return $destinations
    }
    catch {
        Write-LogMessage "Error extracting destinations from TLS rule '$($Rule.name)': $_" -Level ERROR -Component "DestinationExtraction"
        return @()
    }
}
