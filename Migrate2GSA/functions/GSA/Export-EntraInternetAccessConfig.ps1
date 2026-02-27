<#
.SYNOPSIS
    Exports Microsoft Entra Internet Access configurations to CSV format.

.DESCRIPTION
    Retrieves all Entra Internet Access (EIA) policy configurations from an existing
    Entra tenant and exports them to CSV files. The exported CSVs are formatted to be directly
    compatible with the Start-EntraInternetAccessProvisioning function, enabling backup/restore
    and migration scenarios.

    Exports include:
    - Web Content Filtering Policies and their rules (FQDN, URL, webCategory)
    - TLS Inspection Policies and their rules (bypass, inspect)
    - Security Profiles with policy links and priorities
    - Conditional Access Policies with user/group assignments (optional)

    Each policy rule creates one row in the Policies CSV. Each security profile creates
    one row in the Security Profiles CSV.

.PARAMETER OutputPath
    Directory where the timestamped backup folder will be created.
    Defaults to the current directory.

.PARAMETER IncludeConditionalAccessPolicies
    When specified, exports Conditional Access policies linked to security profiles,
    including user and group assignments. Also forces creation of Security Profiles CSV
    even if no security profiles exist.

.PARAMETER LogPath
    Path for the log file. Defaults to the timestamped backup folder.

.EXAMPLE
    Export-EntraInternetAccessConfig

    Exports to current directory: .\GSA-backup_20260227_143022\InternetAccess\

.EXAMPLE
    Export-EntraInternetAccessConfig -OutputPath "C:\GSA-Backups"

    Exports to: C:\GSA-Backups\GSA-backup_20260227_143022\InternetAccess\

.EXAMPLE
    Export-EntraInternetAccessConfig -IncludeConditionalAccessPolicies

    Exports policies, security profiles, and Conditional Access policy assignments.

.EXAMPLE
    Export-EntraInternetAccessConfig -OutputPath "C:\Backups" -LogPath "C:\Logs\EIA-Export.log"

    Custom log location outside the backup folder.

.NOTES
    Author: Franck Heilmann and Andres Canello
    Version: 1.0
    Requires: PowerShell 7+, Microsoft.Graph.Authentication module
    Required scopes: 
        - NetworkAccessPolicy.Read.All (for EIA policies and security profiles)
        - Policy.Read.All (for Conditional Access policies, if -IncludeConditionalAccessPolicies)
        - User.Read.All (for user resolution, if -IncludeConditionalAccessPolicies)
        - Directory.Read.All (for group resolution, if -IncludeConditionalAccessPolicies)
#>

function Export-EntraInternetAccessConfig {
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = "Directory where timestamped backup folder will be created")]
        [string]$OutputPath = $PWD,

        [Parameter(HelpMessage = "Include Conditional Access policies and assignments in export")]
        [switch]$IncludeConditionalAccessPolicies,

        [Parameter(HelpMessage = "Path for the log file")]
        [string]$LogPath
    )

    #region Initialization
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFolderName = "GSA-backup_$timestamp"
    $internetAccessFolder = Join-Path -Path $OutputPath -ChildPath $backupFolderName | Join-Path -ChildPath "InternetAccess"
    $policiesCsvFileName = "${timestamp}_EIA_Policies.csv"
    $policiesCsvFilePath = Join-Path -Path $internetAccessFolder -ChildPath $policiesCsvFileName
    $securityProfilesCsvFileName = "${timestamp}_EIA_SecurityProfiles.csv"
    $securityProfilesCsvFilePath = Join-Path -Path $internetAccessFolder -ChildPath $securityProfilesCsvFileName

    # Set log path
    if (-not $LogPath) {
        $LogPath = Join-Path -Path $internetAccessFolder -ChildPath "${timestamp}_Export-EIA.log"
    }

    # Validate OutputPath write permissions by creating the folder structure
    try {
        if (-not (Test-Path -Path $internetAccessFolder)) {
            New-Item -Path $internetAccessFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
    }
    catch {
        Write-Error "Cannot create output folder '$internetAccessFolder': $_"
        throw "Output path validation failed. Ensure you have write permissions to '$OutputPath'."
    }

    # Set script-scoped LogPath for Write-LogMessage
    $script:LogPath = $LogPath

    # Initialize caches and counters
    $userCache = @{}
    $groupCache = @{}
    $graphApiCalls = 0
    $cachedLookups = 0
    $warningCount = 0
    $errorCount = 0
    $startTime = Get-Date
    #endregion

    #region Validation
    Write-LogMessage "Starting Entra Internet Access configuration export..." -Level INFO -Component "Export"
    Write-LogMessage "Output folder: $internetAccessFolder" -Level INFO -Component "Export"
    Write-LogMessage "Timestamp: $timestamp" -Level INFO -Component "Export"
    Write-LogMessage "Include Conditional Access Policies: $($IncludeConditionalAccessPolicies.IsPresent)" -Level INFO -Component "Export"

    # Validate required PowerShell modules
    $requiredModules = @('Microsoft.Graph.Authentication')
    Test-RequiredModules -RequiredModules $requiredModules

    # Build required scopes based on parameters
    $requiredScopes = @('NetworkAccessPolicy.Read.All')
    if ($IncludeConditionalAccessPolicies) {
        $requiredScopes += 'Policy.Read.All'
        $requiredScopes += 'User.Read.All'
        $requiredScopes += 'Directory.Read.All'
    }

    # Validate Graph connection with read-only scopes
    Test-GraphConnection -RequiredScopes $requiredScopes

    # Validate GSA tenant onboarding status
    Write-LogMessage "Validating Global Secure Access tenant onboarding status..." -Level INFO -Component "Validation"
    $tenantStatus = Get-IntGSATenantStatus
    $graphApiCalls++
    if ($tenantStatus.onboardingStatus -ne 'onboarded') {
        Write-LogMessage "Global Secure Access has not been activated on this tenant. Current onboarding status: $($tenantStatus.onboardingStatus). Please complete tenant onboarding before running this script." -Level ERROR -Component "Validation"
        throw "Tenant onboarding validation failed. Status: $($tenantStatus.onboardingStatus)"
    }
    Write-LogMessage "Global Secure Access tenant status validated: $($tenantStatus.onboardingStatus)" -Level SUCCESS -Component "Validation"
    #endregion

    #region Export Web Content Filtering Policies
    Write-Progress -Activity "Exporting Internet Access Configuration" -Status "Retrieving Web Content Filtering policies..." -PercentComplete 10

    Write-LogMessage "Retrieving Web Content Filtering policies..." -Level INFO -Component "Export"
    $filteringPolicies = Get-IntFilteringPolicy
    $graphApiCalls++

    $filteringPolicies = if ($filteringPolicies) { @($filteringPolicies) } else { @() }
    $totalFilteringPolicies = $filteringPolicies.Count
    Write-LogMessage "Found $totalFilteringPolicies Web Content Filtering policy/policies" -Level INFO -Component "Export"

    $policiesRows = @()
    $totalFilteringRules = 0
    $filteringPoliciesWithNoRules = 0

    if ($totalFilteringPolicies -gt 0) {
        $currentPolicyIndex = 0
        foreach ($policy in $filteringPolicies) {
            $currentPolicyIndex++
            $percentComplete = 10 + (($currentPolicyIndex / $totalFilteringPolicies) * 30)
            Write-Progress -Activity "Exporting Internet Access Configuration" `
                -Status "Processing Web Content Filtering policy $currentPolicyIndex of ${totalFilteringPolicies}: $($policy.name)" `
                -PercentComplete $percentComplete

            Write-LogMessage "Processing Web Content Filtering policy $currentPolicyIndex/${totalFilteringPolicies}: $($policy.name) (ID: $($policy.id))" -Level INFO -Component "Export"

            # Get rules for this policy
            try {
                $rules = Get-IntFilteringRule -PolicyId $policy.id
                $graphApiCalls++
                $rules = if ($rules) { @($rules) } else { @() }

                if ($rules.Count -eq 0) {
                    Write-LogMessage "  Policy '$($policy.name)' has no rules. Skipping." -Level WARN -Component "Export"
                    $warningCount++
                    $filteringPoliciesWithNoRules++
                    continue
                }

                Write-LogMessage "  Found $($rules.Count) rule(s) for policy '$($policy.name)'" -Level INFO -Component "Export"
                $totalFilteringRules += $rules.Count

                foreach ($rule in $rules) {
                    # Extract destinations using helper function
                    $destinations = Get-FilteringRuleDestinations -Rule $rule
                    $destinationsString = $destinations -join ';'

                    if ([string]::IsNullOrWhiteSpace($destinationsString)) {
                        Write-LogMessage "    Rule '$($rule.name)' has no valid destinations. Skipping." -Level WARN -Component "Export"
                        $warningCount++
                        continue
                    }

                    # Build CSV row
                    $policiesRows += [PSCustomObject]@{
                        PolicyName       = $policy.name
                        PolicyType       = "WebContentFiltering"
                        PolicyAction     = $policy.action.ToLower()
                        Description      = $policy.description
                        RuleType         = $rule.ruleType
                        RuleDestinations = $destinationsString
                        RuleName         = $rule.name
                        Provision        = "no"
                    }
                }
            }
            catch {
                Write-LogMessage "  Failed to retrieve rules for policy '$($policy.name)': $_" -Level ERROR -Component "Export"
                $errorCount++
            }
        }
    }
    #endregion

    #region Export TLS Inspection Policies
    Write-Progress -Activity "Exporting Internet Access Configuration" -Status "Retrieving TLS Inspection policies..." -PercentComplete 40

    Write-LogMessage "Retrieving TLS Inspection policies..." -Level INFO -Component "Export"
    $tlsPolicies = Get-IntTlsInspectionPolicy
    $graphApiCalls++

    $tlsPolicies = if ($tlsPolicies) { @($tlsPolicies) } else { @() }
    $totalTlsPolicies = $tlsPolicies.Count
    Write-LogMessage "Found $totalTlsPolicies TLS Inspection policy/policies" -Level INFO -Component "Export"

    $totalTlsRules = 0
    $tlsPoliciesWithNoRules = 0

    if ($totalTlsPolicies -gt 0) {
        $currentPolicyIndex = 0
        foreach ($policy in $tlsPolicies) {
            $currentPolicyIndex++
            $percentComplete = 40 + (($currentPolicyIndex / $totalTlsPolicies) * 20)
            Write-Progress -Activity "Exporting Internet Access Configuration" `
                -Status "Processing TLS Inspection policy $currentPolicyIndex of ${totalTlsPolicies}: $($policy.name)" `
                -PercentComplete $percentComplete

            Write-LogMessage "Processing TLS Inspection policy $currentPolicyIndex/${totalTlsPolicies}: $($policy.name) (ID: $($policy.id))" -Level INFO -Component "Export"

            # Extract default action from settings object
            $defaultAction = if ($policy.settings -and $policy.settings.defaultAction) {
                $policy.settings.defaultAction.ToLower()
            }
            else {
                Write-LogMessage "  Policy '$($policy.name)' missing settings.defaultAction. Defaulting to 'bypass'." -Level WARN -Component "Export"
                $warningCount++
                "bypass"
            }

            # Get rules for this policy
            try {
                $rules = Get-IntTlsInspectionRule -PolicyId $policy.id
                $graphApiCalls++
                $rules = if ($rules) { @($rules) } else { @() }

                if ($rules.Count -eq 0) {
                    Write-LogMessage "  Policy '$($policy.name)' has no rules. Skipping." -Level WARN -Component "Export"
                    $warningCount++
                    $tlsPoliciesWithNoRules++
                    continue
                }

                Write-LogMessage "  Found $($rules.Count) rule(s) for policy '$($policy.name)'" -Level INFO -Component "Export"
                $totalTlsRules += $rules.Count

                foreach ($rule in $rules) {
                    # Extract destinations using helper function (handles nested matchingConditions)
                    $destinations = Get-TlsInspectionRuleDestinations -Rule $rule
                    $destinationsString = $destinations -join ';'

                    # Note: TLS rules can have empty destinations (system rules matching all traffic)
                    # This is valid, so we don't skip these rules

                    # Build CSV row
                    $policiesRows += [PSCustomObject]@{
                        PolicyName       = $policy.name
                        PolicyType       = "TLSInspection"
                        PolicyAction     = $defaultAction
                        Description      = $policy.description
                        RuleType         = $rule.action  # 'bypass' or 'inspect'
                        RuleDestinations = $destinationsString
                        RuleName         = $rule.name
                        Provision        = "no"
                    }
                }
            }
            catch {
                Write-LogMessage "  Failed to retrieve rules for TLS policy '$($policy.name)': $_" -Level ERROR -Component "Export"
                $errorCount++
            }
        }
    }
    #endregion

    #region Write Policies CSV
    Write-Progress -Activity "Exporting Internet Access Configuration" -Status "Writing Policies CSV..." -PercentComplete 60

    try {
        if ($policiesRows.Count -gt 0) {
            $policiesRows | Export-Csv -Path $policiesCsvFilePath -NoTypeInformation -Encoding UTF8
            $policiesCsvFileInfo = Get-Item -Path $policiesCsvFilePath
            $policiesCsvSizeKB = [math]::Round($policiesCsvFileInfo.Length / 1KB, 1)
            Write-LogMessage "Policies CSV written: $policiesCsvFilePath ($policiesCsvSizeKB KB, $($policiesRows.Count) rows)" -Level SUCCESS -Component "Export"
        }
        else {
            # Create empty CSV with headers only
            Write-LogMessage "No policy rules found. Creating empty Policies CSV with headers only." -Level WARN -Component "Export"
            $warningCount++
            
            $emptyRow = [PSCustomObject]@{
                PolicyName       = $null
                PolicyType       = $null
                PolicyAction     = $null
                Description      = $null
                RuleType         = $null
                RuleDestinations = $null
                RuleName         = $null
                Provision        = $null
            }
            @($emptyRow) | Select-Object * | Export-Csv -Path $policiesCsvFilePath -NoTypeInformation -Encoding UTF8
            $headerLine = Get-Content -Path $policiesCsvFilePath -First 1
            Set-Content -Path $policiesCsvFilePath -Value $headerLine -Encoding UTF8
            
            Write-LogMessage "Empty Policies CSV created at: $policiesCsvFilePath" -Level INFO -Component "Export"
        }
    }
    catch {
        Write-LogMessage "Failed to write Policies CSV file: $_" -Level ERROR -Component "Export"
        $errorCount++
        throw "CSV export failed: $_"
    }
    #endregion

    #region Determine Security Profiles CSV Creation
    $shouldCreateSecurityProfilesCsv = $false
    $securityProfiles = @()

    Write-Progress -Activity "Exporting Internet Access Configuration" -Status "Retrieving Security Profiles..." -PercentComplete 65

    Write-LogMessage "Retrieving Security Profiles..." -Level INFO -Component "Export"
    $securityProfiles = Get-IntSecurityProfile
    $graphApiCalls++
    $securityProfiles = if ($securityProfiles) { @($securityProfiles) } else { @() }

    if ($securityProfiles.Count -gt 0) {
        $shouldCreateSecurityProfilesCsv = $true
        Write-LogMessage "Found $($securityProfiles.Count) security profile(s) for export" -Level INFO -Component "SecurityProfiles"
    }

    # Override if -IncludeConditionalAccessPolicies is specified
    if ($IncludeConditionalAccessPolicies) {
        $shouldCreateSecurityProfilesCsv = $true
        Write-LogMessage "Security Profiles CSV will be created (IncludeConditionalAccessPolicies specified)" -Level INFO -Component "SecurityProfiles"
    }

    if (-not $shouldCreateSecurityProfilesCsv) {
        Write-LogMessage "Security Profiles CSV will not be created (no profiles exist and IncludeConditionalAccessPolicies not specified)" -Level INFO -Component "SecurityProfiles"
    }
    #endregion

    #region Export Security Profiles
    $securityProfileRows = @()
    $profilesWithNoLinks = 0
    $profilesWithCA = 0

    if ($shouldCreateSecurityProfilesCsv) {
        if ($securityProfiles.Count -gt 0) {
            $currentProfileIndex = 0
            foreach ($secProfile in $securityProfiles) {
                $currentProfileIndex++
                $percentComplete = 65 + (($currentProfileIndex / $securityProfiles.Count) * 20)
                Write-Progress -Activity "Exporting Internet Access Configuration" `
                    -Status "Processing Security Profile $currentProfileIndex of $($securityProfiles.Count): $($secProfile.name)" `
                    -PercentComplete $percentComplete

                Write-LogMessage "Processing Security Profile $currentProfileIndex/$($securityProfiles.Count): $($secProfile.name) (ID: $($secProfile.id))" -Level INFO -Component "SecurityProfiles"

                # Get policy links using helper function (handles expansion)
                $securityProfileLinksString = Get-SecurityProfilePolicyLinks -ProfileId $secProfile.id
                $graphApiCalls++

                # Skip if no valid policy links
                if ([string]::IsNullOrWhiteSpace($securityProfileLinksString)) {
                    Write-LogMessage "  Skipping security profile '$($secProfile.name)' - no valid policy links" -Level WARN -Component "SecurityProfiles"
                    $warningCount++
                    $profilesWithNoLinks++
                    continue
                }

                # Initialize CA fields
                $caDisplayName = ""
                $entraUsers = ""
                $entraGroups = ""

                # Populate CA fields if requested
                if ($IncludeConditionalAccessPolicies) {
                    Write-LogMessage "  Looking for Conditional Access policy linked to profile '$($secProfile.name)'" -Level INFO -Component "ConditionalAccess"
                    
                    try {
                        # Retrieve all CA policies
                        $allCaPolicies = Invoke-InternalGraphRequest -Method GET -Uri "/beta/identity/conditionalAccess/policies"
                        $graphApiCalls++

                        # Find CA policy linked to this security profile
                        $linkedCaPolicy = $allCaPolicies | Where-Object {
                            $_.sessionControls -and 
                            $_.sessionControls.globalSecureAccessFilteringProfile -and
                            $_.sessionControls.globalSecureAccessFilteringProfile.profileId -eq $secProfile.id
                        } | Select-Object -First 1

                        if ($linkedCaPolicy) {
                            $caDisplayName = $linkedCaPolicy.displayName
                            Write-LogMessage "    Found linked CA policy: $caDisplayName" -Level INFO -Component "ConditionalAccess"
                            $profilesWithCA++

                            # Extract user assignments
                            $userUpns = @()
                            if ($linkedCaPolicy.conditions.users.includeUsers -and 
                                $linkedCaPolicy.conditions.users.includeUsers -notin @('None', 'All')) {
                                
                                foreach ($userId in $linkedCaPolicy.conditions.users.includeUsers) {
                                    # Skip special values
                                    if ($userId -in @('All', 'None', 'GuestsOrExternalUsers')) { continue }
                                    
                                    # Check cache first
                                    if ($userCache.ContainsKey($userId)) {
                                        $userUpns += $userCache[$userId]
                                        $cachedLookups++
                                    }
                                    else {
                                        try {
                                            $user = Get-IntUser -Filter "id eq '$userId'"
                                            $graphApiCalls++
                                            if ($user -and $user.userPrincipalName) {
                                                $userUpns += $user.userPrincipalName
                                                $userCache[$userId] = $user.userPrincipalName
                                            }
                                            else {
                                                Write-LogMessage "      Failed to resolve user ID $userId" -Level WARN -Component "ConditionalAccess"
                                                $warningCount++
                                            }
                                        }
                                        catch {
                                            Write-LogMessage "      Error resolving user ID $userId`: $_" -Level WARN -Component "ConditionalAccess"
                                            $warningCount++
                                        }
                                    }
                                }
                            }
                            $entraUsers = $userUpns -join ';'

                            # Extract group assignments
                            $groupNames = @()
                            if ($linkedCaPolicy.conditions.users.includeGroups -and 
                                $linkedCaPolicy.conditions.users.includeGroups -ne 'None') {
                                
                                foreach ($groupId in $linkedCaPolicy.conditions.users.includeGroups) {
                                    # Skip special values
                                    if ($groupId -in @('None')) { continue }
                                    
                                    # Check cache first
                                    if ($groupCache.ContainsKey($groupId)) {
                                        $groupNames += $groupCache[$groupId]
                                        $cachedLookups++
                                    }
                                    else {
                                        try {
                                            $group = Get-IntGroup -Filter "id eq '$groupId'"
                                            $graphApiCalls++
                                            if ($group -and $group.displayName) {
                                                $groupNames += $group.displayName
                                                $groupCache[$groupId] = $group.displayName
                                            }
                                            else {
                                                Write-LogMessage "      Failed to resolve group ID $groupId" -Level WARN -Component "ConditionalAccess"
                                                $warningCount++
                                            }
                                        }
                                        catch {
                                            Write-LogMessage "      Error resolving group ID $groupId`: $_" -Level WARN -Component "ConditionalAccess"
                                            $warningCount++
                                        }
                                    }
                                }
                            }
                            $entraGroups = $groupNames -join ';'

                            # Log if special guest assignments exist
                            if ($linkedCaPolicy.conditions.users.includeGuestsOrExternalUsers) {
                                Write-LogMessage "      CA policy includes guest/external users (not exported to CSV)" -Level WARN -Component "ConditionalAccess"
                                $warningCount++
                            }
                        }
                        else {
                            Write-LogMessage "    No Conditional Access policy linked to profile '$($secProfile.name)'" -Level INFO -Component "ConditionalAccess"
                        }
                    }
                    catch {
                        Write-LogMessage "  Error retrieving CA policy for profile '$($secProfile.name)': $_" -Level ERROR -Component "ConditionalAccess"
                        $errorCount++
                    }
                }

                # Build CSV row
                $securityProfileRows += [PSCustomObject]@{
                    SecurityProfileName  = $secProfile.name
                    Priority             = $secProfile.priority
                    SecurityProfileLinks = $securityProfileLinksString
                    CADisplayName        = $caDisplayName
                    EntraUsers           = $entraUsers
                    EntraGroups          = $entraGroups
                    Provision            = "no"
                }
            }
        }
        else {
            Write-LogMessage "No security profiles found in tenant." -Level INFO -Component "SecurityProfiles"
        }
    }
    #endregion

    #region Write Security Profiles CSV
    if ($shouldCreateSecurityProfilesCsv) {
        Write-Progress -Activity "Exporting Internet Access Configuration" -Status "Writing Security Profiles CSV..." -PercentComplete 85

        try {
            if ($securityProfileRows.Count -gt 0) {
                $securityProfileRows | Export-Csv -Path $securityProfilesCsvFilePath -NoTypeInformation -Encoding UTF8
                $securityProfilesCsvFileInfo = Get-Item -Path $securityProfilesCsvFilePath
                $securityProfilesCsvSizeKB = [math]::Round($securityProfilesCsvFileInfo.Length / 1KB, 1)
                Write-LogMessage "Security Profiles CSV written: $securityProfilesCsvFilePath ($securityProfilesCsvSizeKB KB, $($securityProfileRows.Count) rows)" -Level SUCCESS -Component "Export"
            }
            else {
                # Create empty CSV with headers only
                Write-LogMessage "No security profiles with valid policy links. Creating empty Security Profiles CSV with headers only." -Level INFO -Component "Export"
                
                $emptyRow = [PSCustomObject]@{
                    SecurityProfileName  = $null
                    Priority             = $null
                    SecurityProfileLinks = $null
                    CADisplayName        = $null
                    EntraUsers           = $null
                    EntraGroups          = $null
                    Provision            = $null
                }
                @($emptyRow) | Select-Object * | Export-Csv -Path $securityProfilesCsvFilePath -NoTypeInformation -Encoding UTF8
                $headerLine = Get-Content -Path $securityProfilesCsvFilePath -First 1
                Set-Content -Path $securityProfilesCsvFilePath -Value $headerLine -Encoding UTF8
                
                Write-LogMessage "Empty Security Profiles CSV created at: $securityProfilesCsvFilePath" -Level INFO -Component "Export"
            }
        }
        catch {
            Write-LogMessage "Failed to write Security Profiles CSV file: $_" -Level ERROR -Component "Export"
            $errorCount++
            throw "CSV export failed: $_"
        }
    }
    #endregion

    Write-Progress -Activity "Exporting Internet Access Configuration" -Completed

    #region Summary Report
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationSeconds = [math]::Round($duration.TotalSeconds, 1)

    $logFileInfo = if (Test-Path $LogPath) { Get-Item -Path $LogPath } else { $null }
    $logSizeKB = if ($logFileInfo) { [math]::Round($logFileInfo.Length / 1KB, 1) } else { 0 }

    $policiesCsvFileInfoFinal = if (Test-Path $policiesCsvFilePath) { Get-Item -Path $policiesCsvFilePath } else { $null }
    $policiesCsvSizeKBFinal = if ($policiesCsvFileInfoFinal) { [math]::Round($policiesCsvFileInfoFinal.Length / 1KB, 1) } else { 0 }

    $securityProfilesCsvSizeKBFinal = 0
    if ($shouldCreateSecurityProfilesCsv -and (Test-Path $securityProfilesCsvFilePath)) {
        $securityProfilesCsvFileInfoFinal = Get-Item -Path $securityProfilesCsvFilePath
        $securityProfilesCsvSizeKBFinal = [math]::Round($securityProfilesCsvFileInfoFinal.Length / 1KB, 1)
    }

    # Build backup folder path (parent of InternetAccess)
    $backupFolder = Split-Path -Path $internetAccessFolder -Parent

    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "=== EXPORT SUMMARY ===" -Level SUMMARY -Component "Summary"
    Write-LogMessage "Export completed successfully!" -Level SUCCESS -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "Backup folder: $backupFolder" -Level SUMMARY -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "Entra Internet Access (EIA):" -Level SUMMARY -Component "Summary"
    Write-LogMessage "  Web Content Filtering Policies:" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Total policies: $totalFilteringPolicies" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Total rules exported: $totalFilteringRules" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Policies with no rules: $filteringPoliciesWithNoRules" -Level SUMMARY -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "  TLS Inspection Policies:" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Total policies: $totalTlsPolicies" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Total rules exported: $totalTlsRules" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Policies with no rules: $tlsPoliciesWithNoRules" -Level SUMMARY -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    
    if ($shouldCreateSecurityProfilesCsv) {
        Write-LogMessage "  Security Profiles:" -Level SUMMARY -Component "Summary"
        Write-LogMessage "    Total profiles: $($securityProfiles.Count)" -Level SUMMARY -Component "Summary"
        Write-LogMessage "    Profiles exported: $($securityProfileRows.Count)" -Level SUMMARY -Component "Summary"
        Write-LogMessage "    Profiles with no valid policy links: $profilesWithNoLinks" -Level SUMMARY -Component "Summary"
        if ($IncludeConditionalAccessPolicies) {
            Write-LogMessage "    Profiles with linked CA policies: $profilesWithCA" -Level SUMMARY -Component "Summary"
        }
        Write-LogMessage " " -Level INFO -Component "Summary"
    }

    Write-LogMessage "  Performance:" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Graph API calls made: $graphApiCalls" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Cached lookups used: $cachedLookups" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Total duration: $durationSeconds seconds" -Level SUMMARY -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "  Warnings: $warningCount (see log file for details)" -Level SUMMARY -Component "Summary"
    Write-LogMessage "  Errors: $errorCount" -Level SUMMARY -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "Files created in InternetAccess\:" -Level SUMMARY -Component "Summary"
    Write-LogMessage "  - $policiesCsvFileName ($policiesCsvSizeKBFinal KB)" -Level SUMMARY -Component "Summary"
    if ($shouldCreateSecurityProfilesCsv) {
        Write-LogMessage "  - $securityProfilesCsvFileName ($securityProfilesCsvSizeKBFinal KB)" -Level SUMMARY -Component "Summary"
    }
    Write-LogMessage "  - $(Split-Path -Path $LogPath -Leaf) ($logSizeKB KB)" -Level SUMMARY -Component "Summary"
    #endregion

    # Display completion message to console
    Write-Host "`nExport completed successfully!" -ForegroundColor Green
    Write-Host "`nBackup folder: $backupFolder" -ForegroundColor Cyan
    Write-Host "`nEntra Internet Access (EIA):"
    Write-Host "  Exported: $totalFilteringPolicies Web Content Filtering Policies ($totalFilteringRules rules)"
    Write-Host "  Exported: $totalTlsPolicies TLS Inspection Policies ($totalTlsRules rules)"
    if ($shouldCreateSecurityProfilesCsv) {
        Write-Host "  Exported: $($securityProfileRows.Count) Security Profiles with policy links"
        if ($IncludeConditionalAccessPolicies) {
            Write-Host "  Exported: $profilesWithCA linked Conditional Access policies"
        }
    }
    if ($warningCount -gt 0) {
        Write-Host "  Warnings: $warningCount (see log file for details)" -ForegroundColor Yellow
    }
    if ($errorCount -gt 0) {
        Write-Host "  Errors: $errorCount" -ForegroundColor Red
    }
    Write-Host "`nFiles created in InternetAccess\:"
    Write-Host "  - $policiesCsvFileName ($policiesCsvSizeKBFinal KB)"
    if ($shouldCreateSecurityProfilesCsv) {
        Write-Host "  - $securityProfilesCsvFileName ($securityProfilesCsvSizeKBFinal KB)"
    }
    Write-Host "  - $(Split-Path -Path $LogPath -Leaf) ($logSizeKB KB)"
    Write-Host "`nTotal duration: $durationSeconds seconds" -ForegroundColor Gray
}
