function Show-ProvisioningPlan {
    <#
    .SYNOPSIS
        Displays provisioning plan summary for WhatIf mode.
    
    .DESCRIPTION
        Analyzes configuration data and displays a summary of what would be provisioned.
        Shows object counts, conflicts, and recommendations for WhatIf analysis.
    
    .PARAMETER PoliciesConfig
        Policies configuration data (rules).
    
    .PARAMETER SecurityProfilesConfig
        Security profiles configuration data (optional).
    
    .OUTPUTS
        None. Writes summary to console and log.
    
    .EXAMPLE
        Show-ProvisioningPlan -PoliciesConfig $policiesConfig -SecurityProfilesConfig $securityProfilesConfig
    
    .NOTES
        Author: Andres Canello
        This function is called in WhatIf mode to preview provisioning operations.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$PoliciesConfig,
        
        [Parameter(Mandatory = $false)]
        [array]$SecurityProfilesConfig
    )
    
    try {
        # Determine component name based on WhatIf mode
        $component = if ($WhatIfPreference) { "WhatIf" } else { "Plan" }
        
        Write-LogMessage "OBJECTS TO BE CREATED:" -Level SUMMARY -Component $component
        Write-LogMessage "======================" -Level INFO -Component $component
        Write-LogMessage "" -Level INFO
        
        # Analyze policies
        $policyGroups = $PoliciesConfig | Group-Object -Property PolicyName, PolicyType
        $totalPolicies = $policyGroups.Count
        $totalRules = $PoliciesConfig.Count
        
        $webContentPolicies = ($policyGroups | Where-Object { $_.Name -match 'WebContentFiltering' }).Count
        $tlsPolicies = ($policyGroups | Where-Object { $_.Name -match 'TLSInspection' }).Count
        
        Write-LogMessage "✅ Web Content Filtering Policies: $webContentPolicies policies" -Level SUCCESS -Component $component
        foreach ($group in ($policyGroups | Where-Object { $_.Name -match 'WebContentFiltering' })) {
            $policyName = ($group.Name -split ', ')[0]
            $ruleCount = $group.Count
            $action = $group.Group[0].PolicyAction
            Write-LogMessage "   - $policyName`: $ruleCount rules ($action action)" -Level INFO -Component $component
        }
        Write-LogMessage "" -Level INFO
        
        Write-LogMessage "✅ TLS Inspection Policies: $tlsPolicies policies" -Level SUCCESS -Component $component
        foreach ($group in ($policyGroups | Where-Object { $_.Name -match 'TLSInspection' })) {
            $policyName = ($group.Name -split ', ')[0]
            $ruleCount = $group.Count
            $defaultAction = $group.Group[0].PolicyAction
            Write-LogMessage "   - $policyName`: $ruleCount rules (default: $defaultAction)" -Level INFO -Component $component
        }
        Write-LogMessage "" -Level INFO
        
        # Analyze security profiles
        if ($null -ne $SecurityProfilesConfig -and $SecurityProfilesConfig.Count -gt 0) {
            Write-LogMessage "✅ Security Profiles: $($SecurityProfilesConfig.Count) profiles" -Level SUCCESS -Component $component
            foreach ($profile in $SecurityProfilesConfig) {
                $linkCount = $profile.ParsedPolicyLinks.Count
                Write-LogMessage "   - $($profile.SecurityProfileName): Links $linkCount policies, Priority $($profile.Priority)" -Level INFO -Component $component
            }
            Write-LogMessage "" -Level INFO
            
            # Count CA policies
            $caPolicyCount = 0
            $totalUsers = 0
            $totalGroups = 0
            
            foreach ($profile in $SecurityProfilesConfig) {
                if ($profile.ParsedUsers.Count -gt 0 -or $profile.ParsedGroups.Count -gt 0) {
                    $caPolicyCount++
                    $totalUsers += $profile.ParsedUsers.Count
                    $totalGroups += $profile.ParsedGroups.Count
                }
            }
            
            if ($caPolicyCount -gt 0) {
                Write-LogMessage "✅ Conditional Access Policies: $caPolicyCount policies" -Level SUCCESS -Component $component
                foreach ($profile in $SecurityProfilesConfig) {
                    if ($profile.ParsedUsers.Count -gt 0 -or $profile.ParsedGroups.Count -gt 0) {
                        Write-LogMessage "   - $($profile.CADisplayName): Links $($profile.SecurityProfileName), $($profile.ParsedUsers.Count) users, $($profile.ParsedGroups.Count) groups" -Level INFO -Component $component
                    }
                }
                Write-LogMessage "" -Level INFO
            }
        }
        
        # Summary
        Write-LogMessage "SUMMARY:" -Level SUMMARY -Component $component
        Write-LogMessage "========" -Level INFO -Component $component
        Write-LogMessage "Total Objects to Create: $($totalPolicies + $SecurityProfilesConfig.Count + $caPolicyCount)" -Level INFO -Component $component
        Write-LogMessage "- Policies: $totalPolicies ($webContentPolicies Web Content, $tlsPolicies TLS)" -Level INFO -Component $component
        Write-LogMessage "- Rules: $totalRules" -Level INFO -Component $component
        
        if ($null -ne $SecurityProfilesConfig) {
            Write-LogMessage "- Security Profiles: $($SecurityProfilesConfig.Count)" -Level INFO -Component $component
            if ($caPolicyCount -gt 0) {
                Write-LogMessage "- CA Policies: $caPolicyCount (covering $totalUsers users, $totalGroups groups)" -Level INFO -Component $component
            }
        }
        Write-LogMessage "" -Level INFO
        
        Write-LogMessage "RECOMMENDATION:" -Level SUMMARY -Component $component
        Write-LogMessage "- Review the above summary" -Level INFO -Component $component
        Write-LogMessage "- Verify policy names, priorities, and assignments" -Level INFO -Component $component
        if ($WhatIfPreference) {
            Write-LogMessage "- Run without -WhatIf to execute provisioning" -Level INFO -Component $component
        }
        Write-LogMessage "" -Level INFO
    }
    catch {
        Write-LogMessage "Error displaying provisioning plan: $_" -Level ERROR -Component "Plan"
    }
}
