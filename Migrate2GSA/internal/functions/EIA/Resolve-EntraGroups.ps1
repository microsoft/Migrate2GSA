function Resolve-EntraGroups {
    <#
    .SYNOPSIS
        Resolves and caches Entra ID groups for Conditional Access policy assignments.
    
    .DESCRIPTION
        Parses EntraGroups column from security profiles CSV, aggregates and deduplicates group names,
        resolves each group via Microsoft Graph, and caches the results for efficient lookup during provisioning.
    
    .PARAMETER ConfigData
        Security profiles configuration data (one row per profile with CA policy information).
    
    .OUTPUTS
        None. Results are stored in $Global:EntraGroupCache hashtable.
    
    .EXAMPLE
        Resolve-EntraGroups -ConfigData $securityProfilesConfig
    
    .NOTES
        Author: Andres Canello
        Requires: Group.Read.All Graph API permission
        Missing groups are cached as $null for later validation.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ConfigData
    )
    
    try {
        Write-LogMessage "Starting group resolution..." -Level INFO -Component "Validation"
        
        # Aggregate all unique group names from all security profiles
        $allGroups = @()
        foreach ($row in $ConfigData) {
            if ($row.PSObject.Properties.Name -contains 'ParsedGroups' -and $row.ParsedGroups.Count -gt 0) {
                $allGroups += $row.ParsedGroups
            }
        }
        
        # Deduplicate groups
        $uniqueGroups = $allGroups | Select-Object -Unique | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        
        if ($uniqueGroups.Count -eq 0) {
            Write-LogMessage "No groups to resolve" -Level INFO -Component "Validation"
            return
        }
        
        Write-LogMessage "Found $($uniqueGroups.Count) unique groups to resolve" -Level INFO -Component "Validation"
        
        # Resolve each group
        $resolvedCount = 0
        $missingCount = 0
        
        foreach ($groupName in $uniqueGroups) {
            try {
                Write-LogMessage "Resolving group: $groupName" -Level DEBUG -Component "Validation"
                
                $filter = "displayName eq '$groupName'"
                $group = Get-IntGroup -Filter $filter
                
                if ($null -ne $group) {
                    # Handle array response (take first match)
                    if ($group -is [array]) {
                        $group = $group[0]
                    }
                    
                    $Global:EntraGroupCache[$groupName] = $group.id
                    $resolvedCount++
                    Write-LogMessage "Resolved group: $groupName (ID: $($group.id))" -Level DEBUG -Component "Validation"
                }
                else {
                    $Global:EntraGroupCache[$groupName] = $null
                    $missingCount++
                    Write-LogMessage "Group not found in tenant: $groupName" -Level WARN -Component "Validation"
                }
            }
            catch {
                $Global:EntraGroupCache[$groupName] = $null
                $missingCount++
                Write-LogMessage "Failed to resolve group '$groupName': $_" -Level WARN -Component "Validation"
            }
        }
        
        Write-LogMessage "Group resolution completed: $resolvedCount resolved, $missingCount missing" -Level INFO -Component "Validation"
    }
    catch {
        Write-LogMessage "Failed to resolve groups: $_" -Level ERROR -Component "Validation"
        throw
    }
}
