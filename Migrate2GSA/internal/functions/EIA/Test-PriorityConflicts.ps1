function Test-PriorityConflicts {
    <#
    .SYNOPSIS
        Detects priority conflicts in security profiles and policy links.
    
    .DESCRIPTION
        Validates that security profile priorities and policy link priorities don't conflict with:
        1. Other profiles within the CSV (CSV-to-CSV conflicts)
        2. Existing profiles in the target tenant (CSV-to-Tenant conflicts)
        3. Other policy links within the same profile (duplicate policy link priorities)
        
        Throws error if any conflicts are detected, stopping provisioning.
    
    .PARAMETER ConfigData
        Security profiles configuration data from CSV.
    
    .OUTPUTS
        None. Throws error if conflicts are detected.
    
    .EXAMPLE
        Test-PriorityConflicts -ConfigData $securityProfilesConfig
    
    .NOTES
        Author: Andres Canello
        This function makes READ-ONLY Graph API calls to retrieve existing security profiles.
        Runs in both normal execution and -WhatIf mode.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ConfigData
    )
    
    try {
        Write-LogMessage "Checking CSV internal duplicates, CSV-to-Tenant conflicts, and policy link priorities..." -Level INFO -Component "Validation"
        
        $conflictsFound = 0
        $csvConflicts = 0
        $tenantConflicts = 0
        $policyLinkConflicts = 0
        
        #region Load Tenant Data
        Write-LogMessage "Retrieving existing security profiles from tenant..." -Level DEBUG -Component "Validation"
        
        try {
            $existingProfiles = Get-IntSecurityProfile
            
            # Build tenant priority lookup: Priority -> @(ProfileNames)
            $tenantPriorityLookup = @{}
            
            if ($null -ne $existingProfiles) {
                # Handle Graph API collection response structure
                $profilesList = $existingProfiles
                
                # Check if response has a 'value' property (collection response)
                if ($existingProfiles.PSObject.Properties.Name -contains 'value') {
                    $profilesList = $existingProfiles.value
                    Write-LogMessage "Retrieved collection response with $($profilesList.Count) profiles" -Level DEBUG -Component "Validation"
                }
                
                # Ensure we have an array
                if ($profilesList -isnot [array]) {
                    $profilesList = @($profilesList)
                }
                
                # Build priority lookup
                foreach ($profile in $profilesList) {
                    # Ensure priority is treated as [int] for consistent hashtable key matching
                    $priority = [int]$profile.priority
                    $profileName = $profile.name
                    
                    if ($null -ne $priority -and -not [string]::IsNullOrWhiteSpace($profileName)) {
                        if (-not $tenantPriorityLookup.ContainsKey($priority)) {
                            $tenantPriorityLookup[$priority] = @()
                        }
                        $tenantPriorityLookup[$priority] += $profileName
                        
                        Write-LogMessage "Tenant profile: '$profileName' (Priority: $priority)" -Level DEBUG -Component "Validation"
                    }
                }
                
                Write-LogMessage "Found $($profilesList.Count) existing security profiles in tenant" -Level DEBUG -Component "Validation"
                Write-LogMessage "Priority lookup built: $($tenantPriorityLookup.Keys.Count) unique priorities used" -Level DEBUG -Component "Validation"
            }
            else {
                Write-LogMessage "No existing security profiles found in tenant" -Level DEBUG -Component "Validation"
            }
        }
        catch {
            Write-LogMessage "Failed to retrieve existing security profiles: $_" -Level WARN -Component "Validation"
            Write-LogMessage "Exception details: $($_.Exception.Message)" -Level WARN -Component "Validation"
            # Continue with validation even if tenant retrieval fails (might be first provisioning)
        }
        #endregion
        
        #region Check CSV Duplicate Priorities
        Write-LogMessage "Checking for duplicate priorities within CSV..." -Level DEBUG -Component "Validation"
        
        $csvPriorityGroups = $ConfigData | Group-Object -Property Priority | Where-Object { $_.Count -gt 1 }
        
        foreach ($duplicate in $csvPriorityGroups) {
            $priority = $duplicate.Name
            $conflictingProfiles = $duplicate.Group.SecurityProfileName -join ", "
            
            Write-LogMessage "PRIORITY CONFLICT: Priority $priority used by multiple CSV profiles: $conflictingProfiles (Source: CSV)" -Level ERROR -Component "Validation"
            $csvConflicts++
            $conflictsFound++
        }
        #endregion
        
        #region Check CSV-to-Tenant Priority Conflicts
        Write-LogMessage "Checking for CSV-to-Tenant priority conflicts..." -Level DEBUG -Component "Validation"
        
        foreach ($csvRow in $ConfigData) {
            $csvProfileName = $csvRow.SecurityProfileName
            $csvProfileNameWithSuffix = "${csvProfileName}[Migrate2GSA]"
            $csvPriority = [int]$csvRow.Priority
            
            Write-LogMessage "Checking priority $csvPriority for CSV profile: $csvProfileName" -Level DEBUG -Component "Validation"
            
            # Check if this priority is already used by a tenant profile
            if ($tenantPriorityLookup.ContainsKey($csvPriority)) {
                $tenantProfilesAtPriority = $tenantPriorityLookup[$csvPriority]
                
                Write-LogMessage "Found tenant profiles with priority $csvPriority`: $($tenantProfilesAtPriority -join ', ')" -Level DEBUG -Component "Validation"
                
                # Check if the tenant profile is NOT the same profile we're trying to create/reuse
                # (reused profiles keep their existing priorities, so this is not a conflict)
                $isReusedProfile = $tenantProfilesAtPriority -contains $csvProfileNameWithSuffix
                
                if (-not $isReusedProfile) {
                    # Real conflict: CSV wants to create a NEW profile with priority already used by different tenant profile(s)
                    $conflictingTenantProfiles = $tenantProfilesAtPriority -join ", "
                    Write-LogMessage "PRIORITY CONFLICT: Security Profile '$csvProfileName' (priority $csvPriority) conflicts with existing tenant profile(s): $conflictingTenantProfiles (Sources: CSV vs Tenant)" -Level ERROR -Component "Validation"
                    $tenantConflicts++
                    $conflictsFound++
                }
                else {
                    Write-LogMessage "Priority $csvPriority is used by profile being reused: $csvProfileNameWithSuffix (no conflict)" -Level DEBUG -Component "Validation"
                }
            }
            else {
                Write-LogMessage "Priority $csvPriority not found in tenant (available for use)" -Level DEBUG -Component "Validation"
            }
        }
        #endregion
        
        #region Check Policy Link Priority Duplicates
        Write-LogMessage "Checking for duplicate policy link priorities within security profiles..." -Level DEBUG -Component "Validation"
        
        foreach ($csvRow in $ConfigData) {
            $profileName = $csvRow.SecurityProfileName
            
            if ($csvRow.PSObject.Properties.Name -contains 'ParsedPolicyLinks' -and $csvRow.ParsedPolicyLinks.Count -gt 0) {
                # Group policy links by priority
                $linkPriorityGroups = $csvRow.ParsedPolicyLinks | Group-Object -Property Priority | Where-Object { $_.Count -gt 1 }
                
                foreach ($duplicate in $linkPriorityGroups) {
                    $linkPriority = $duplicate.Name
                    $conflictingPolicies = $duplicate.Group.PolicyName -join ", "
                    
                    Write-LogMessage "POLICY LINK PRIORITY CONFLICT: Security Profile '$profileName' has duplicate priority $linkPriority for policies: $conflictingPolicies (Source: CSV SecurityProfileLinks)" -Level ERROR -Component "Validation"
                    $policyLinkConflicts++
                    $conflictsFound++
                }
            }
        }
        #endregion
        
        #region Throw Error if Conflicts Found
        if ($conflictsFound -gt 0) {
            $errorMessage = "PRIORITY CONFLICTS DETECTED: $csvConflicts CSV duplicate(s), $tenantConflicts CSV-to-Tenant conflict(s), $policyLinkConflicts Policy Link duplicate(s). Please fix conflicts and re-run."
            
            Write-LogMessage $errorMessage -Level ERROR -Component "Validation"
            throw $errorMessage
        }
        #endregion
        
        Write-LogMessage "Validated $($ConfigData.Count) security profile(s): No priority conflicts detected" -Level SUCCESS -Component "Validation"
    }
    catch {
        # Re-throw to stop execution
        throw
    }
}
