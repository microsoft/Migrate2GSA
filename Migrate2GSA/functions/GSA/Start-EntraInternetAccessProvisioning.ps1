<#
.SYNOPSIS
    Provisions Microsoft Entra Internet Access filtering policies and security profiles from CSV configuration data.

.DESCRIPTION
    This script reads CSV configuration files containing Entra Internet Access policies, security profiles,
    and provisions them automatically into a target Entra tenant. It provides comprehensive logging, error handling,
    and supports retry scenarios through output CSV generation.
    
    The script handles:
    - Web Content Filtering Policies and their rules (FQDN, URL, webCategory)
    - TLS Inspection Policies and their rules (bypass, inspect)
    - Security Profiles with policy links
    - Conditional Access Policies with user/group assignments
    
    All created objects are automatically suffixed with [Migrate2GSA] for identification.

.PARAMETER PoliciesCsvPath
    Path to the CSV file containing web content filtering policies, TLS inspection policies, and their rules.
    This parameter is REQUIRED.

.PARAMETER SecurityProfilesCsvPath
    Path to the CSV file containing security profiles (with links to policies) and Conditional Access policies.
    This parameter is OPTIONAL - only needed if provisioning security profiles or CA policies.

.PARAMETER PolicyName
    Optional filter to provision only the policy with this exact name (case-insensitive).
    Mutually exclusive with -SecurityProfilesCsvPath parameter.

.PARAMETER SkipCAPoliciesProvisioning
    Skip creation of ALL Conditional Access policies. Security Profiles are still created with policy links
    but no CA policies are provisioned.

.PARAMETER LogPath
    Path for the log file. Defaults to $PWD\${timestamp}_Start-EntraInternetAccessProvisioning.log

.PARAMETER Force
    Skip confirmation prompts for automated execution.

.EXAMPLE
    Start-EntraInternetAccessProvisioning -PoliciesCsvPath ".\policies.csv" -SecurityProfilesCsvPath ".\security_profiles.csv"
    
.EXAMPLE
    Start-EntraInternetAccessProvisioning -PoliciesCsvPath ".\policies.csv" -SecurityProfilesCsvPath ".\security_profiles.csv" -WhatIf

.EXAMPLE
    Start-EntraInternetAccessProvisioning -PoliciesCsvPath ".\policies.csv" -PolicyName "Finance_WebFilter"

.EXAMPLE
    Start-EntraInternetAccessProvisioning -PoliciesCsvPath ".\policies.csv" -SecurityProfilesCsvPath ".\security_profiles.csv" -SkipCAPoliciesProvisioning

.NOTES
    Author: Andres Canello
    Version: 1.0
    Requires: PowerShell 7+, Microsoft.Graph.Authentication module
    
    All created objects are suffixed with [Migrate2GSA]:
    - Policies: PolicyName[Migrate2GSA]
    - Security Profiles: SecurityProfileName[Migrate2GSA]
    - Conditional Access Policies: CADisplayName[Migrate2GSA]
#>

function Start-EntraInternetAccessProvisioning {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Path to CSV file containing policies and rules")]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$PoliciesCsvPath,
        
        [Parameter(Mandatory = $false, HelpMessage = "Path to CSV file containing security profiles and CA policies")]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$SecurityProfilesCsvPath,
        
        [Parameter(Mandatory = $false, HelpMessage = "Filter to provision only this specific policy name")]
        [string]$PolicyName,
        
        [Parameter(Mandatory = $false, HelpMessage = "Skip Conditional Access policy creation")]
        [switch]$SkipCAPoliciesProvisioning,
        
        [Parameter(HelpMessage = "Log file path")]
        [string]$LogPath,
        
        [Parameter(HelpMessage = "Skip confirmation prompts")]
        [switch]$Force
    )
    
    BEGIN {
        #region Parameter Validation
        # Validate mutual exclusivity: -PolicyName and -SecurityProfilesCsvPath cannot be used together
        if ($PSBoundParameters.ContainsKey('PolicyName') -and $PSBoundParameters.ContainsKey('SecurityProfilesCsvPath')) {
            throw "Parameters -PolicyName and -SecurityProfilesCsvPath are mutually exclusive. Policy filtering is for testing individual policies; provisioning a single policy would create incomplete security profiles."
        }
        #endregion
        
        #region Initialize Logging
        # Generate timestamp for all output files
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        
        # Set default log path if not provided
        if ([string]::IsNullOrWhiteSpace($LogPath)) {
            $script:LogPath = Join-Path $PWD "${timestamp}_Start-EntraInternetAccessProvisioning.log"
        }
        else {
            $script:LogPath = $LogPath
        }
        
        # Initialize log file
        Write-LogMessage "===============================================" -Level INFO -Component "Main"
        Write-LogMessage "START-ENTRAINTERNETACCESSPROVISIONING" -Level INFO -Component "Main"
        Write-LogMessage "===============================================" -Level INFO -Component "Main"
        Write-LogMessage "Execution started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level INFO -Component "Main"
        Write-LogMessage "Policies CSV: $PoliciesCsvPath" -Level INFO -Component "Main"
        if ($PSBoundParameters.ContainsKey('SecurityProfilesCsvPath')) {
            Write-LogMessage "Security Profiles CSV: $SecurityProfilesCsvPath" -Level INFO -Component "Main"
        }
        if ($PSBoundParameters.ContainsKey('PolicyName')) {
            Write-LogMessage "Policy Name Filter: $PolicyName" -Level INFO -Component "Main"
        }
        if ($SkipCAPoliciesProvisioning) {
            Write-LogMessage "Skip CA Policies: Enabled" -Level INFO -Component "Main"
        }
        Write-LogMessage "WhatIf Mode: $($WhatIfPreference.IsPresent)" -Level INFO -Component "Main"
        Write-LogMessage "" -Level INFO
        #endregion
        
        #region Global Variables
        $Global:ProvisioningStats = @{
            TotalPolicies           = 0
            CreatedPolicies         = 0
            ReusedPolicies          = 0
            FailedPolicies          = 0
            TotalRules              = 0
            CreatedRules            = 0
            ReusedRules             = 0
            FailedRules             = 0
            TotalSecurityProfiles   = 0
            CreatedSecurityProfiles = 0
            ReusedSecurityProfiles  = 0
            FailedSecurityProfiles  = 0
            TotalCAPolicies         = 0
            CreatedCAPolicies       = 0
            SkippedCAPolicies       = 0
            FailedCAPolicies        = 0
            FilteredRecords         = 0
            StartTime               = Get-Date
            EndTime                 = $null
        }
        
        $Global:EntraUserCache = @{}
        $Global:EntraGroupCache = @{}
        $Global:ProvisioningResults = @()
        $Global:RecordLookup = @{}
        $Global:PolicyIdCache = @{}
        $Global:PolicyTypeCache = @{}
        $Global:SecurityProfileIdCache = @{}
        #endregion
        
        #region WhatIf Mode Setup
        if ($WhatIfPreference) {
            $whatIfLogPath = Join-Path $PWD "${timestamp}_Start-EntraInternetAccessProvisioning_WhatIf.log"
            $script:WhatIfLogPath = $whatIfLogPath
            
            Write-LogMessage "===============================================" -Level INFO -Component "WhatIf"
            Write-LogMessage "PROVISION WHAT-IF ANALYSIS" -Level INFO -Component "WhatIf"
            Write-LogMessage "===============================================" -Level INFO -Component "WhatIf"
            Write-LogMessage "Analysis Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level INFO -Component "WhatIf"
            Write-LogMessage "Policies CSV: $PoliciesCsvPath" -Level INFO -Component "WhatIf"
            if ($PSBoundParameters.ContainsKey('SecurityProfilesCsvPath')) {
                Write-LogMessage "Security Profiles CSV: $SecurityProfilesCsvPath" -Level INFO -Component "WhatIf"
            }
            if ($PSBoundParameters.ContainsKey('PolicyName')) {
                Write-LogMessage "Policy Name Filter: $PolicyName" -Level INFO -Component "WhatIf"
            }
            Write-LogMessage "" -Level INFO
        }
        #endregion
    }
    
    PROCESS {
        try {
            #region Pre-Flight Validation
            Write-LogMessage "=== PRE-FLIGHT VALIDATION ===" -Level SUMMARY -Component "Validation"
            
            # Check required PowerShell modules
            Test-RequiredModules -RequiredModules @('Microsoft.Graph.Authentication')
            
            # Determine required Graph scopes based on user intent
            $requiredScopes = @('NetworkAccess.ReadWrite.All')
            $willProvisionCAPolicies = $PSBoundParameters.ContainsKey('SecurityProfilesCsvPath') -and -not $SkipCAPoliciesProvisioning
            
            if ($willProvisionCAPolicies) {
                Write-LogMessage "CA policy provisioning enabled - validating additional scopes" -Level INFO -Component "Auth"
                $requiredScopes += @(
                    'Policy.ReadWrite.ConditionalAccess',
                    'User.Read.All',
                    'Group.Read.All'
                )
            }
            
            # Validate Graph connection and scopes
            Test-GraphConnection -RequiredScopes $requiredScopes
            
            # Validate Global Secure Access tenant onboarding status
            Write-LogMessage "Validating Global Secure Access tenant status..." -Level INFO -Component "Validation"
            $tenantStatus = Get-IntGSATenantStatus
            if ($tenantStatus.onboardingStatus -ne 'onboarded') {
                Write-LogMessage "Global Secure Access has not been activated on this tenant. Current onboarding status: $($tenantStatus.onboardingStatus). Please complete tenant onboarding before running this script." -Level ERROR -Component "Validation"
                throw "Tenant onboarding validation failed. Status: $($tenantStatus.onboardingStatus)"
            }
            Write-LogMessage "Global Secure Access tenant status validated: $($tenantStatus.onboardingStatus)" -Level SUCCESS -Component "Validation"
            Write-LogMessage "" -Level INFO
            #endregion
            
            #region Load and Validate Configuration Files
            Write-LogMessage "=== LOADING CONFIGURATION FILES ===" -Level SUMMARY -Component "Config"
            
            # Import policies CSV (REQUIRED)
            $policiesConfig = Import-PoliciesConfig -ConfigPath $PoliciesCsvPath -PolicyFilter $PolicyName
            
            if ($null -eq $policiesConfig -or $policiesConfig.Count -eq 0) {
                Write-LogMessage "No policies to provision after filtering. Exiting." -Level WARN -Component "Config"
                return
            }
            
            $Global:ProvisioningStats.TotalRules = $policiesConfig.Count
            
            # Import security profiles CSV (OPTIONAL)
            $securityProfilesConfig = $null
            if ($PSBoundParameters.ContainsKey('SecurityProfilesCsvPath')) {
                $securityProfilesConfig = Import-SecurityProfilesConfig -ConfigPath $SecurityProfilesCsvPath
                
                if ($null -eq $securityProfilesConfig -or $securityProfilesConfig.Count -eq 0) {
                    Write-LogMessage "No security profiles to provision after filtering." -Level WARN -Component "Config"
                }
                else {
                    $Global:ProvisioningStats.TotalSecurityProfiles = $securityProfilesConfig.Count
                }
            }
            Write-LogMessage "" -Level INFO
            #endregion
            
            #region Resolve Users and Groups (if CA policies will be provisioned)
            if ($willProvisionCAPolicies -and $null -ne $securityProfilesConfig) {
                Write-LogMessage "=== RESOLVING USER AND GROUP ASSIGNMENTS ===" -Level SUMMARY -Component "Validation"
                
                # Resolve users (function handles all logging)
                Resolve-EntraUsers -ConfigData $securityProfilesConfig
                
                # Resolve groups (function handles all logging)
                Resolve-EntraGroups -ConfigData $securityProfilesConfig
                
                # Test for missing users/groups (function handles all logging)
                Test-UserGroupDependencies -ConfigData $securityProfilesConfig
                Write-LogMessage "" -Level INFO
            }
            #endregion
            
            #region Priority Conflict Detection (if Security Profiles provided)
            if ($PSBoundParameters.ContainsKey('SecurityProfilesCsvPath') -and $null -ne $securityProfilesConfig) {
                Write-LogMessage "=== PRIORITY CONFLICT DETECTION ===" -Level SUMMARY -Component "Validation"
                Test-PriorityConflicts -ConfigData $securityProfilesConfig
                Write-LogMessage "Priority conflict detection completed successfully" -Level SUCCESS -Component "Validation"
                Write-LogMessage "" -Level INFO
            }
            #endregion
            
            #region Show Provisioning Plan and User Confirmation
            # Show provisioning plan (always display for visibility)
            Write-LogMessage "=== PROVISIONING PLAN ===" -Level SUMMARY -Component "Plan"
            Show-ProvisioningPlan -PoliciesConfig $policiesConfig -SecurityProfilesConfig $securityProfilesConfig
            Write-LogMessage "" -Level INFO
            
            # Confirm execution unless Force or WhatIf is specified
            if (-not $Force -and -not $WhatIfPreference) {
                $confirmation = Read-Host "Proceed with provisioning? (y/N)"
                if ($confirmation -notmatch '^[Yy]') {
                    Write-LogMessage "Provisioning cancelled by user" -Level INFO -Component "Main"
                    return
                }
                Write-LogMessage "" -Level INFO
            }
            #endregion
            
            #region WhatIf Mode - Exit After Plan
            if ($WhatIfPreference) {
                Write-LogMessage "WhatIf analysis completed. Run without -WhatIf to execute provisioning." -Level INFO -Component "WhatIf"
                return
            }
            #endregion
            
            #region Provision Policies and Rules
            Write-LogMessage "=== PROVISIONING POLICIES AND RULES ===" -Level SUMMARY -Component "PolicyProvisioning"
            
            # Group policy rules by PolicyName and PolicyType
            $policyGroups = $policiesConfig | Group-Object -Property PolicyName, PolicyType
            $Global:ProvisioningStats.TotalPolicies = $policyGroups.Count
            $currentPolicyNumber = 0
            
            foreach ($policyGroup in $policyGroups) {
                $groupKey = $policyGroup.Name -split ', '
                $policyName = $groupKey[0]
                $policyType = $groupKey[1]
                $rulesForPolicy = $policyGroup.Group
                $currentPolicyNumber++
                
                # Get policy action from first rule
                $policyAction = $rulesForPolicy[0].PolicyAction
                
                # Add visual separator and enhanced policy header
                Write-LogMessage " " -Level INFO -Component "PolicyProvisioning"
                Write-LogMessage "╔═══════════════════════════════════════════════════════════════════════════════════════" -Level SUMMARY -Component "PolicyProvisioning"
                Write-LogMessage "║ 🔒 POLICY [$currentPolicyNumber/$($policyGroups.Count)]: $policyName" -Level SUMMARY -Component "PolicyProvisioning"
                Write-LogMessage "║ 📋 Type: $policyType | Rules: $($rulesForPolicy.Count) | Action: $policyAction" -Level SUMMARY -Component "PolicyProvisioning"
                Write-LogMessage "╚═══════════════════════════════════════════════════════════════════════════════════════" -Level SUMMARY -Component "PolicyProvisioning"
                
                Write-LogMessage "Processing policy: $policyName ($policyType)" -Level INFO -Component "PolicyProvisioning"
                
                # Provision based on policy type
                if ($policyType -eq 'WebContentFiltering') {
                    $policyResult = New-WebContentFilteringPolicy -PolicyGroup $policyGroup
                    
                    if ($policyResult.Success) {
                        if ($policyResult.Action -eq 'Created') {
                            $Global:ProvisioningStats.CreatedPolicies++
                        }
                        elseif ($policyResult.Action -eq 'Reused') {
                            $Global:ProvisioningStats.ReusedPolicies++
                        }
                        
                        # Provision rules
                        $rulesResult = New-WebContentFilteringRules -PolicyId $policyResult.PolicyId -Rules $rulesForPolicy -PolicyName $policyName
                        
                        # Only cache policy ID if rules succeeded or policy was reused with existing rules
                        if ($rulesResult.HasSuccessfulRules -or ($policyResult.Action -eq 'Reused' -and $rulesResult.ReusedRules -gt 0)) {
                            $Global:PolicyIdCache[$policyName] = $policyResult.PolicyId
                            $Global:PolicyTypeCache[$policyName] = 'WebContentFiltering'
                            Write-LogMessage "Policy '$policyName' cached for security profile linking (Type: WebContentFiltering)" -Level DEBUG -Component "PolicyProvisioning"
                        }
                        else {
                            Write-LogMessage "Policy '$policyName' NOT cached - all rules failed or no rules exist" -Level WARN -Component "PolicyProvisioning"
                        }
                    }
                    else {
                        $Global:ProvisioningStats.FailedPolicies++
                        Write-LogMessage "Failed to create/reuse policy: $policyName. Error: $($policyResult.Error)" -Level ERROR -Component "PolicyProvisioning"
                    }
                }
                elseif ($policyType -eq 'TLSInspection') {
                    $policyResult = New-TLSInspectionPolicy -PolicyGroup $policyGroup
                    
                    if ($policyResult.Success) {
                        if ($policyResult.Action -eq 'Created') {
                            $Global:ProvisioningStats.CreatedPolicies++
                        }
                        elseif ($policyResult.Action -eq 'Reused') {
                            $Global:ProvisioningStats.ReusedPolicies++
                        }
                        
                        # Provision rules
                        $rulesResult = New-TLSInspectionRules -PolicyId $policyResult.PolicyId -Rules $rulesForPolicy -PolicyName $policyName
                        
                        # Only cache policy ID if rules succeeded or policy was reused with existing rules
                        if ($rulesResult.HasSuccessfulRules -or ($policyResult.Action -eq 'Reused' -and $rulesResult.ReusedRules -gt 0)) {
                            $Global:PolicyIdCache[$policyName] = $policyResult.PolicyId
                            $Global:PolicyTypeCache[$policyName] = 'TLSInspection'
                            Write-LogMessage "Policy '$policyName' cached for security profile linking (Type: TLSInspection)" -Level DEBUG -Component "PolicyProvisioning"
                        }
                        else {
                            Write-LogMessage "Policy '$policyName' NOT cached - all rules failed or no rules exist" -Level WARN -Component "PolicyProvisioning"
                        }
                    }
                    else {
                        $Global:ProvisioningStats.FailedPolicies++
                        Write-LogMessage "Failed to create/reuse TLS policy: $policyName. Error: $($policyResult.Error)" -Level ERROR -Component "PolicyProvisioning"
                    }
                }
                else {
                    Write-LogMessage "Unknown policy type: $policyType for policy $policyName. Skipping." -Level WARN -Component "PolicyProvisioning"
                }
            }
            
            Write-LogMessage "" -Level INFO
            Write-LogMessage "Policy provisioning completed: $($Global:ProvisioningStats.CreatedPolicies) created, $($Global:ProvisioningStats.ReusedPolicies) reused, $($Global:ProvisioningStats.FailedPolicies) failed" -Level SUMMARY -Component "PolicyProvisioning"
            Write-LogMessage "" -Level INFO
            #endregion
            
            #region Provision Security Profiles and CA Policies
            if ($PSBoundParameters.ContainsKey('SecurityProfilesCsvPath') -and $null -ne $securityProfilesConfig) {
                Write-LogMessage "=== PROVISIONING SECURITY PROFILES ===" -Level SUMMARY -Component "SecurityProfileProvisioning"
                
                $currentProfileNumber = 0
                
                foreach ($profileRow in $securityProfilesConfig) {
                    $profileName = $profileRow.SecurityProfileName
                    $currentProfileNumber++
                    
                    # Determine if CA policy will be created
                    $hasUsers = $profileRow.ParsedUsers.Count -gt 0
                    $hasGroups = $profileRow.ParsedGroups.Count -gt 0
                    $willCreateCA = if ($hasUsers -or $hasGroups) { "Yes" } else { "No" }
                    
                    # Add visual separator and enhanced profile header
                    Write-LogMessage " " -Level INFO -Component "SecurityProfileProvisioning"
                    Write-LogMessage "╔═══════════════════════════════════════════════════════════════════════════════════════" -Level SUMMARY -Component "SecurityProfileProvisioning"
                    Write-LogMessage "║ 🛡️ SECURITY PROFILE [$currentProfileNumber/$($securityProfilesConfig.Count)]: $profileName" -Level SUMMARY -Component "SecurityProfileProvisioning"
                    Write-LogMessage "║ 🔗 Priority: $($profileRow.Priority) | Policy Links: $($profileRow.ParsedPolicyLinks.Count) | CA Policy: $willCreateCA" -Level SUMMARY -Component "SecurityProfileProvisioning"
                    Write-LogMessage "╚═══════════════════════════════════════════════════════════════════════════════════════" -Level SUMMARY -Component "SecurityProfileProvisioning"
                    
                    Write-LogMessage "Processing security profile: $profileName" -Level INFO -Component "SecurityProfileProvisioning"
                    
                    # Provision security profile
                    $profileResult = New-SecurityProfile -ProfileRow $profileRow
                    
                    if ($profileResult.Success) {
                        if ($profileResult.Action -eq 'Created') {
                            $Global:ProvisioningStats.CreatedSecurityProfiles++
                        }
                        elseif ($profileResult.Action -eq 'Reused') {
                            $Global:ProvisioningStats.ReusedSecurityProfiles++
                        }
                        
                        # Cache security profile ID
                        $Global:SecurityProfileIdCache[$profileName] = $profileResult.ProfileId
                        
                        # Provision CA policy if needed and all policy links succeeded
                        if ($profileResult.ShouldCreateCAPolicy -and $profileResult.AllPolicyLinksSucceeded) {
                            $Global:ProvisioningStats.TotalCAPolicies++
                            
                            if (-not $SkipCAPoliciesProvisioning) {
                                # Add CA policy header
                                $caDisplayName = $profileRow.CADisplayName
                                $userCount = $profileRow.ParsedUsers.Count
                                $groupCount = $profileRow.ParsedGroups.Count
                                
                                Write-LogMessage "  ┌─────────────────────────────────────────────────────────────────────" -Level INFO -Component "ConditionalAccessProvisioning"
                                Write-LogMessage "  │ 🔐 CONDITIONAL ACCESS: $caDisplayName" -Level INFO -Component "ConditionalAccessProvisioning"
                                Write-LogMessage "  │ 👥 Users: $userCount | Groups: $groupCount" -Level INFO -Component "ConditionalAccessProvisioning"
                                Write-LogMessage "  └─────────────────────────────────────────────────────────────────────" -Level INFO -Component "ConditionalAccessProvisioning"
                                
                                $caResult = New-ConditionalAccessPolicy -ProfileRow $profileRow -SecurityProfileId $profileResult.ProfileId
                                
                                if ($caResult.Success) {
                                    if ($caResult.Action -eq 'Created') {
                                        $Global:ProvisioningStats.CreatedCAPolicies++
                                    }
                                    elseif ($caResult.Action -eq 'Skipped') {
                                        $Global:ProvisioningStats.SkippedCAPolicies++
                                    }
                                }
                                else {
                                    $Global:ProvisioningStats.FailedCAPolicies++
                                }
                            }
                            else {
                                Write-LogMessage "Skipping CA policy creation (SkipCAPoliciesProvisioning enabled)" -Level INFO -Component "ConditionalAccessProvisioning"
                                $Global:ProvisioningStats.SkippedCAPolicies++
                            }
                        }
                    }
                    else {
                        $Global:ProvisioningStats.FailedSecurityProfiles++
                        Write-LogMessage "Failed to create/reuse security profile: $profileName. Error: $($profileResult.Error)" -Level ERROR -Component "SecurityProfileProvisioning"
                    }
                }
                
                Write-LogMessage "" -Level INFO
                Write-LogMessage "Security profile provisioning completed: $($Global:ProvisioningStats.CreatedSecurityProfiles) created, $($Global:ProvisioningStats.ReusedSecurityProfiles) reused, $($Global:ProvisioningStats.FailedSecurityProfiles) failed" -Level SUMMARY -Component "SecurityProfileProvisioning"
                
                if ($Global:ProvisioningStats.TotalCAPolicies -gt 0) {
                    Write-LogMessage "CA policy provisioning completed: $($Global:ProvisioningStats.CreatedCAPolicies) created, $($Global:ProvisioningStats.SkippedCAPolicies) skipped, $($Global:ProvisioningStats.FailedCAPolicies) failed" -Level SUMMARY -Component "ConditionalAccessProvisioning"
                }
                Write-LogMessage "" -Level INFO
            }
            #endregion
            
            #region Export Results
            Write-LogMessage "=== EXPORTING RESULTS ===" -Level SUMMARY -Component "Export"
            
            # Export policies results
            $policiesOutputPath = Join-Path $PWD "${timestamp}_policies_provisioned.csv"
            Export-ProvisioningResults -OutputPath $policiesOutputPath -ConfigType 'Policies'
            Write-LogMessage "Policies results exported to: $policiesOutputPath" -Level SUCCESS -Component "Export"
            
            # Export security profiles results (if applicable)
            if ($PSBoundParameters.ContainsKey('SecurityProfilesCsvPath') -and $null -ne $securityProfilesConfig) {
                $profilesOutputPath = Join-Path $PWD "${timestamp}_security_profiles_provisioned.csv"
                Export-ProvisioningResults -OutputPath $profilesOutputPath -ConfigType 'SecurityProfiles'
                Write-LogMessage "Security profiles results exported to: $profilesOutputPath" -Level SUCCESS -Component "Export"
            }
            
            Write-LogMessage "" -Level INFO
            #endregion
            
            #region Final Summary
            $Global:ProvisioningStats.EndTime = Get-Date
            $duration = $Global:ProvisioningStats.EndTime - $Global:ProvisioningStats.StartTime
            
            Write-LogMessage "===============================================" -Level SUMMARY -Component "Summary"
            Write-LogMessage "PROVISIONING SUMMARY" -Level SUMMARY -Component "Summary"
            Write-LogMessage "===============================================" -Level SUMMARY -Component "Summary"
            Write-LogMessage "Execution completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level INFO -Component "Summary"
            Write-LogMessage "Total duration: $($duration.ToString('hh\:mm\:ss'))" -Level INFO -Component "Summary"
            Write-LogMessage "" -Level INFO
            Write-LogMessage "Policies: $($Global:ProvisioningStats.CreatedPolicies) created, $($Global:ProvisioningStats.ReusedPolicies) reused, $($Global:ProvisioningStats.FailedPolicies) failed (Total: $($Global:ProvisioningStats.TotalPolicies))" -Level SUMMARY -Component "Summary"
            Write-LogMessage "Rules: $($Global:ProvisioningStats.CreatedRules) created, $($Global:ProvisioningStats.ReusedRules) reused, $($Global:ProvisioningStats.FailedRules) failed (Total: $($Global:ProvisioningStats.TotalRules))" -Level SUMMARY -Component "Summary"
            
            if ($PSBoundParameters.ContainsKey('SecurityProfilesCsvPath')) {
                Write-LogMessage "Security Profiles: $($Global:ProvisioningStats.CreatedSecurityProfiles) created, $($Global:ProvisioningStats.ReusedSecurityProfiles) reused, $($Global:ProvisioningStats.FailedSecurityProfiles) failed (Total: $($Global:ProvisioningStats.TotalSecurityProfiles))" -Level SUMMARY -Component "Summary"
                
                if ($Global:ProvisioningStats.TotalCAPolicies -gt 0) {
                    Write-LogMessage "CA Policies: $($Global:ProvisioningStats.CreatedCAPolicies) created, $($Global:ProvisioningStats.SkippedCAPolicies) skipped, $($Global:ProvisioningStats.FailedCAPolicies) failed (Total: $($Global:ProvisioningStats.TotalCAPolicies))" -Level SUMMARY -Component "Summary"
                }
            }
            
            Write-LogMessage "" -Level INFO
            Write-LogMessage "Log file: $script:LogPath" -Level INFO -Component "Summary"
            Write-LogMessage "Results CSVs: $PWD\${timestamp}_*_provisioned.csv" -Level INFO -Component "Summary"
            Write-LogMessage "===============================================" -Level SUMMARY -Component "Summary"
            #endregion
        }
        catch {
            # Error already logged by the throwing function, just log the location
            Write-LogMessage "Provisioning terminated due to validation error. See details above." -Level ERROR -Component "Main"
            
            # Exit gracefully without rethrowing (avoids duplicate error messages)
            return
        }
    }
    
    END {
        Write-LogMessage "Script execution completed." -Level INFO -Component "Main"
    }
    
    #region Internal Helper Functions
    
    # Note: The following internal helper functions are defined inline for this main function.
    # In production, these would typically be moved to separate files in the internal/functions directory.
    
    # Placeholder for internal functions - to be implemented in separate files:
    # - Import-PoliciesConfig
    # - Import-SecurityProfilesConfig
    # - Resolve-EntraUsers
    # - Resolve-EntraGroups
    # - Test-UserGroupDependencies
    # - Test-PriorityConflicts
    # - Show-ProvisioningPlan
    # - New-WebContentFilteringPolicy
    # - New-WebContentFilteringRules
    # - New-TLSInspectionPolicy
    # - New-TLSInspectionRules
    # - New-SecurityProfile
    # - New-ConditionalAccessPolicy
    # - Export-ProvisioningResults
    
    #endregion
}
