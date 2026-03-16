function Convert-MDE2EIA {
    <#
    .SYNOPSIS
        Converts Microsoft Defender for Endpoint (MDE) web filtering configuration to Microsoft Entra Internet Access (EIA) format.

    .DESCRIPTION
        This function processes MDE Web Content Filtering (WCF) policies and URL/Domain indicators
        exported by Export-MDEWebFilteringConfig to generate CSV files ready for import into
        Microsoft Entra Internet Access (EIA) via Start-EntraInternetAccessProvisioning.

        The conversion process includes:
        - Transforming MDE WCF policies (blocked and audited web categories) into EIA web content filtering policies
        - Converting MDE custom URL/Domain indicators into EIA FQDN filtering policies
        - Logging and skipping MDE IP indicators (not supported as EIA destinations)
        - Mapping MDE web category names to EIA web category identifiers using a hardcoded mapping
        - Generating Security Profiles with Default and Override profiles based on device group scoping
        - Producing import-ready CSV files for EIA configuration

    .PARAMETER WcfPoliciesPath
        Path to MDE WCF Policies JSON file exported by Export-MDEWebFilteringConfig.
        At least one of WcfPoliciesPath or UrlIndicatorsPath must be provided.

    .PARAMETER IpIndicatorsPath
        Path to MDE IP Indicators JSON file exported by Export-MDEWebFilteringConfig.
        Not converted — used only for skip-and-log reporting.

    .PARAMETER UrlIndicatorsPath
        Path to MDE URL/Domain Indicators JSON file exported by Export-MDEWebFilteringConfig.

    .PARAMETER DeviceGroupsPath
        Path to MDE Device Groups JSON file exported by Export-MDEWebFilteringConfig.
        Optional — used for Entra group name resolution in override profiles.

    .PARAMETER OutputBasePath
        Base directory for output CSV files and log file.
        Default: Current directory.

    .PARAMETER IncludePolicyName
        WCF policy name patterns to include. Supports wildcards via -like. Case-insensitive.
        When specified, only WCF policies matching at least one pattern are processed.

    .PARAMETER ExcludePolicyName
        WCF policy name patterns to exclude. Supports wildcards via -like. Case-insensitive.
        Exclude wins over include when both match.

    .PARAMETER EnableDebugLogging
        Enable verbose debug logging for detailed processing information.

    .EXAMPLE
        Convert-MDE2EIA -WcfPoliciesPath "C:\MDE\wcf_policies.json" -UrlIndicatorsPath "C:\MDE\url_indicators.json"

        Converts MDE WCF policies and URL indicators from specified paths.

    .EXAMPLE
        Convert-MDE2EIA -WcfPoliciesPath "C:\MDE\wcf_policies.json" -IpIndicatorsPath "C:\MDE\ip_indicators.json" -UrlIndicatorsPath "C:\MDE\url_indicators.json" -DeviceGroupsPath "C:\MDE\device_groups.json" -OutputBasePath "C:\Output"

        Converts all MDE web filtering configuration with device group resolution.

    .EXAMPLE
        Convert-MDE2EIA -WcfPoliciesPath "C:\MDE\wcf_policies.json" -IncludePolicyName "Production*" -EnableDebugLogging

        Converts only WCF policies matching "Production*" with debug logging enabled.

    .NOTES
        Author: Andres Canello
        Version: 1.0
        Date: 2026-03-16

        Requirements:
        - MDE WCF policies and/or URL indicators JSON exports from Export-MDEWebFilteringConfig

        Known Limitations:
        - IP indicators are not converted (EIA does not support IP address destinations)
        - Device-group-to-user-group mapping requires manual review
        - MDE 'Warn' and 'AlertOnly' actions have no direct EIA equivalent
    #>

    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(HelpMessage = "Path to MDE WCF Policies JSON file exported by Export-MDEWebFilteringConfig. At least one of WcfPoliciesPath or UrlIndicatorsPath must be provided.")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$WcfPoliciesPath,

        [Parameter(HelpMessage = "Path to MDE IP Indicators JSON file exported by Export-MDEWebFilteringConfig. Not converted — used only for skip-and-log reporting.")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$IpIndicatorsPath,

        [Parameter(HelpMessage = "Path to MDE URL/Domain Indicators JSON file exported by Export-MDEWebFilteringConfig.")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$UrlIndicatorsPath,

        [Parameter(HelpMessage = "Path to MDE Device Groups JSON file exported by Export-MDEWebFilteringConfig. Optional — used for Entra group name resolution.")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$DeviceGroupsPath,

        [Parameter(HelpMessage = "Base directory for output files")]
        [ValidateScript({
            if (Test-Path $_ -PathType Container) { return $true }
            else { throw "Directory not found: $_" }
        })]
        [string]$OutputBasePath = $PWD,

        [Parameter(HelpMessage = "WCF policy name patterns to include. Supports wildcards. Case-insensitive.")]
        [string[]]$IncludePolicyName,

        [Parameter(HelpMessage = "WCF policy name patterns to exclude. Supports wildcards. Case-insensitive. Exclude wins over include.")]
        [string[]]$ExcludePolicyName,

        [Parameter(HelpMessage = "Enable verbose debug logging")]
        [switch]$EnableDebugLogging
    )

    Set-StrictMode -Version Latest

    #region Helper Functions

    function Test-PolicyNameFilter {
        param(
            [Parameter(Mandatory)]
            [string]$PolicyName,

            [string[]]$IncludePatterns,

            [string[]]$ExcludePatterns
        )

        # If include patterns specified, policy must match at least one
        if ($null -ne $IncludePatterns -and $IncludePatterns.Count -gt 0) {
            $included = $false
            foreach ($pattern in $IncludePatterns) {
                if ($PolicyName -like $pattern) {
                    $included = $true
                    break
                }
            }
            if (-not $included) {
                return $false
            }
        }

        # If exclude patterns specified, policy must not match any (exclude wins)
        if ($null -ne $ExcludePatterns -and $ExcludePatterns.Count -gt 0) {
            foreach ($pattern in $ExcludePatterns) {
                if ($PolicyName -like $pattern) {
                    return $false
                }
            }
        }

        return $true
    }

    function Resolve-ScopeKey {
        param(
            [Parameter(Mandatory)]
            $RbacGroupNames
        )

        # "All device groups" or single-element string array containing it → default scope
        if ($RbacGroupNames -eq "All device groups" -or
            ($RbacGroupNames -is [array] -and $RbacGroupNames.Count -eq 1 -and $RbacGroupNames[0] -eq "All device groups")) {
            return "DEFAULT"
        }

        # Specific device groups — sort for consistent key
        $groupNames = @($RbacGroupNames) | Sort-Object
        return ($groupNames -join ";")
    }

    function Resolve-MdeCategory {
        param(
            [Parameter(Mandatory)]
            [string]$CategoryName
        )

        if ($mdeCategoryMap.ContainsKey($CategoryName)) {
            $stats.CategoriesMapped++
            return @{
                EIACategory = $mdeCategoryMap[$CategoryName]
                IsMapped    = $true
            }
        }
        else {
            $stats.CategoriesUnmapped++
            Write-LogMessage "Unknown MDE category '$CategoryName' — not in hardcoded mapping" -Level "WARN" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            return @{
                EIACategory = "UNMAPPED:$CategoryName"
                IsMapped    = $false
            }
        }
    }

    function Add-ToScopeBucket {
        param(
            [Parameter(Mandatory)]
            [string]$ScopeKey,

            [Parameter(Mandatory)]
            [string]$PolicyName,

            [Parameter(Mandatory)]
            [string[]]$RbacGroupNames
        )

        if (-not $scopedPolicyBuckets.ContainsKey($ScopeKey)) {
            $groupNames = @($RbacGroupNames) | Sort-Object

            # Resolve Entra groups from device group assignments
            $entraGroups = @()
            foreach ($gName in $groupNames) {
                if ($deviceGroupEntraMap.ContainsKey($gName)) {
                    $entraGroups += $deviceGroupEntraMap[$gName]
                }
                else {
                    $entraGroups += "_Replace_Me"
                }
            }

            $scopedPolicyBuckets[$ScopeKey] = @{
                DeviceGroupNames = $groupNames
                EntraGroups      = $entraGroups | Select-Object -Unique
                Policies         = @()
            }
        }
        $scopedPolicyBuckets[$ScopeKey].Policies += $PolicyName
    }

    #endregion

    #region Initialization

    # Initialize logging
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:logPath = Join-Path $OutputBasePath "${timestamp}_Convert-MDE2EIA.log"
    $logPath = $script:logPath
    $script:EnableDebugLogging = $EnableDebugLogging

    Write-LogMessage "Starting MDE to EIA conversion" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Validate that at least one convertible input is provided
    $hasWcfPolicies = -not [string]::IsNullOrWhiteSpace($WcfPoliciesPath)
    $hasIpIndicators = -not [string]::IsNullOrWhiteSpace($IpIndicatorsPath)
    $hasUrlIndicators = -not [string]::IsNullOrWhiteSpace($UrlIndicatorsPath)
    $hasDeviceGroups = -not [string]::IsNullOrWhiteSpace($DeviceGroupsPath)

    if (-not $hasWcfPolicies -and -not $hasUrlIndicators) {
        Write-LogMessage "At least one of WcfPoliciesPath or UrlIndicatorsPath must be provided" -Level "ERROR" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        throw "At least one of WcfPoliciesPath or UrlIndicatorsPath must be provided"
    }

    Write-LogMessage "Input files:" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  WCF Policies: $(if ($hasWcfPolicies) { $WcfPoliciesPath } else { 'Not provided' })" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  IP Indicators: $(if ($hasIpIndicators) { $IpIndicatorsPath } else { 'Not provided' })" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  URL Indicators: $(if ($hasUrlIndicators) { $UrlIndicatorsPath } else { 'Not provided' })" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Device Groups: $(if ($hasDeviceGroups) { $DeviceGroupsPath } else { 'Not provided' })" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Output Path: $OutputBasePath" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Log policy name filters
    $hasPolicyFilter = ($null -ne $IncludePolicyName -and $IncludePolicyName.Count -gt 0) -or
                       ($null -ne $ExcludePolicyName -and $ExcludePolicyName.Count -gt 0)
    if ($hasPolicyFilter) {
        if ($null -ne $IncludePolicyName -and $IncludePolicyName.Count -gt 0) {
            Write-LogMessage "Policy name filter (include): $($IncludePolicyName -join ', ')" -Level "INFO" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
        if ($null -ne $ExcludePolicyName -and $ExcludePolicyName.Count -gt 0) {
            Write-LogMessage "Policy name filter (exclude): $($ExcludePolicyName -join ', ')" -Level "INFO" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
    }

    # Hardcoded MDE category name → EIA PascalCase mapping
    $mdeCategoryMap = @{
        "Chat"                            = "Chat"
        "Child Abuse Images"              = "ChildAbuseImages"
        "Criminal activity"               = "CriminalActivity"
        "Cults"                           = "Cults"
        "Download Sites"                  = "DownloadSites"
        "Gambling"                        = "Gambling"
        "Games"                           = "Games"
        "Hacking"                         = "Hacking"
        "Hate & intolerance"              = "HateAndIntolerance"
        "Illegal drug"                    = "IllegalDrug"
        "Illegal software"                = "IllegalSoftware"
        "Image sharing"                   = "ImageSharing"
        "Instant messaging"               = "InstantMessaging"
        "Newly registered domains"        = "NewlyRegisteredDomains"
        "Nudity"                          = "Nudity"
        "Parked Domains"                  = "ParkedDomains"
        "Peer-to-peer"                    = "PeerToPeer"
        "Pornography/Sexually explicit"   = "PornographyAndSexuallyExplicit"
        "Professional networking"         = "ProfessionalNetworking"
        "School cheating"                 = "Cheating"
        "Self-harm"                       = "SelfHarm"
        "Sex education"                   = "SexEducation"
        "Social networking"               = "SocialNetworking"
        "Streaming media & downloads"     = "StreamingMediaAndDownloads"
        "Tasteless"                       = "Tasteless"
        "Violence"                        = "Violence"
        "Weapons"                         = "Weapons"
        "Web-based email"                 = "WebBasedEmail"
    }

    # Initialize statistics
    $stats = @{
        WcfPoliciesProcessed         = 0
        WcfPoliciesSkippedByFilter   = 0
        CategoriesMapped             = 0
        CategoriesUnmapped           = 0
        IpIndicatorsSkipped          = 0
        UrlIndicatorsProcessed       = 0
        UrlIndicatorsSkippedDisabled = 0
        UrlIndicatorsSkippedExpired  = 0
        IndicatorsWarn               = 0
        IndicatorsAlertOnly          = 0
        PoliciesCreated              = 0
        SecurityProfilesCreated      = 0
    }

    # Collections for output
    $allPolicies = [System.Collections.ArrayList]::new()
    $securityProfiles = [System.Collections.ArrayList]::new()
    $defaultScopePolicies = @()
    $scopedPolicyBuckets = @{}

    # Device group → Entra group mapping (populated from device_groups.json)
    $deviceGroupEntraMap = @{}

    #endregion

    #region Phase 1: Data Loading

    Write-LogMessage "Phase 1: Loading input files..." -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Load WCF Policies
    $rawWcfPolicies = $null
    if ($hasWcfPolicies) {
        try {
            Write-LogMessage "Loading WCF policies from: $WcfPoliciesPath" -Level "INFO" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $rawWcfPolicies = Get-Content -Path $WcfPoliciesPath -Raw | ConvertFrom-Json
            Write-LogMessage "Loaded $(@($rawWcfPolicies).Count) WCF policies" -Level "INFO" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
        catch {
            Write-LogMessage "Failed to load WCF policies: $_" -Level "ERROR" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            throw "Failed to load WCF policies file: $WcfPoliciesPath"
        }
    }

    # Load IP Indicators
    $rawIpIndicators = $null
    if ($hasIpIndicators) {
        try {
            Write-LogMessage "Loading IP indicators from: $IpIndicatorsPath" -Level "INFO" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $rawIpIndicators = Get-Content -Path $IpIndicatorsPath -Raw | ConvertFrom-Json
            Write-LogMessage "Loaded $(@($rawIpIndicators).Count) IP indicators" -Level "INFO" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
        catch {
            Write-LogMessage "Failed to load IP indicators (non-fatal): $_" -Level "WARN" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $hasIpIndicators = $false
        }
    }

    # Load URL/Domain Indicators
    $rawUrlIndicators = $null
    if ($hasUrlIndicators) {
        try {
            Write-LogMessage "Loading URL/Domain indicators from: $UrlIndicatorsPath" -Level "INFO" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $rawUrlIndicators = Get-Content -Path $UrlIndicatorsPath -Raw | ConvertFrom-Json
            Write-LogMessage "Loaded $(@($rawUrlIndicators).Count) URL/Domain indicators" -Level "INFO" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
        catch {
            Write-LogMessage "Failed to load URL indicators: $_" -Level "ERROR" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            throw "Failed to load URL indicators file: $UrlIndicatorsPath"
        }
    }

    # Load Device Groups
    $rawDeviceGroups = $null
    if ($hasDeviceGroups) {
        try {
            Write-LogMessage "Loading device groups from: $DeviceGroupsPath" -Level "INFO" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $rawDeviceGroups = Get-Content -Path $DeviceGroupsPath -Raw | ConvertFrom-Json
            Write-LogMessage "Loaded $(@($rawDeviceGroups).Count) device groups" -Level "INFO" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
        catch {
            Write-LogMessage "Failed to load device groups (non-fatal): $_" -Level "WARN" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $hasDeviceGroups = $false
        }
    }

    # Build device group → Entra group lookup
    if ($rawDeviceGroups) {
        foreach ($group in @($rawDeviceGroups)) {
            if ($group.IsUnassignedMachineGroup) {
                Write-LogMessage "Skipping unassigned machine group: $($group.Name)" -Level "DEBUG" `
                    -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                continue
            }
            $groupName = if ([string]::IsNullOrEmpty($group.Name)) { "Unnamed-$($group.MachineGroupId)" } else { $group.Name }
            $entraGroups = @()
            if ($group.MachineGroupAssignments) {
                foreach ($assignment in @($group.MachineGroupAssignments)) {
                    if ($assignment.WcdAadGroup.DisplayName) {
                        $entraGroups += $assignment.WcdAadGroup.DisplayName
                    }
                }
            }
            $deviceGroupEntraMap[$groupName] = if ($entraGroups.Count -gt 0) { $entraGroups } else { @("_Replace_Me") }
            Write-LogMessage "Device group '$groupName' → Entra groups: $($deviceGroupEntraMap[$groupName] -join ', ')" -Level "INFO" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
    }

    Write-LogMessage "Phase 1 complete" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    #endregion

    #region Phase 2: WCF Policy Processing

    if ($hasWcfPolicies -and $rawWcfPolicies) {
        Write-LogMessage "Phase 2: Processing WCF policies..." -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

        foreach ($policy in @($rawWcfPolicies)) {
            # Apply policy name filter
            if (-not (Test-PolicyNameFilter -PolicyName $policy.PolicyName -IncludePatterns $IncludePolicyName -ExcludePatterns $ExcludePolicyName)) {
                Write-LogMessage "Skipping WCF policy '$($policy.PolicyName)': excluded by policy name filter" -Level "INFO" `
                    -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                $stats.WcfPoliciesSkippedByFilter++
                continue
            }

            $blockedCount = @($policy.BlockedCategories).Count
            $auditedCount = @($policy.AuditCategories).Count
            Write-LogMessage "Processing WCF policy '$($policy.PolicyName)': $blockedCount blocked, $auditedCount audited categories" -Level "INFO" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

            # Determine scope
            $scopeKey = Resolve-ScopeKey -RbacGroupNames $policy.RbacGroupNames

            # Sanitize policy name for EIA naming
            $policyNameClean = $policy.PolicyName -replace '\s+', '-' -replace '[^a-zA-Z0-9_-]', ''

            # Process BlockedCategories
            if ($policy.BlockedCategories -and @($policy.BlockedCategories).Count -gt 0) {
                $mappedCategories = @()
                $hasUnmapped = $false
                $reviewReasons = @()

                foreach ($catName in @($policy.BlockedCategories)) {
                    $result = Resolve-MdeCategory -CategoryName $catName
                    $mappedCategories += $result.EIACategory
                    if (-not $result.IsMapped) {
                        $hasUnmapped = $true
                        $reviewReasons += "Unmapped category: $catName"
                    }
                }

                $blockedPolicyName = "WCF-$policyNameClean-Blocked-Block"

                [void]$allPolicies.Add([PSCustomObject]@{
                    PolicyName       = $blockedPolicyName
                    PolicyType       = "WebContentFiltering"
                    PolicyAction     = "Block"
                    Description      = "Converted from MDE WCF policy: $($policy.PolicyName) (blocked categories)"
                    RuleType         = "webCategory"
                    RuleDestinations = $mappedCategories -join ";"
                    RuleName         = "BlockedCategories"
                    ReviewNeeded     = if ($hasUnmapped) { "Yes" } else { "No" }
                    ReviewDetails    = $reviewReasons -join "; "
                    Provision        = if ($hasUnmapped) { "no" } else { "yes" }
                })

                # Route to scope
                if ($scopeKey -eq "DEFAULT") {
                    $defaultScopePolicies += $blockedPolicyName
                }
                else {
                    Add-ToScopeBucket -ScopeKey $scopeKey -PolicyName $blockedPolicyName -RbacGroupNames @($policy.RbacGroupNames)
                }

                $stats.PoliciesCreated++
                Write-LogMessage "Created policy '$blockedPolicyName' with $($mappedCategories.Count) categories (scope: $scopeKey)" -Level "DEBUG" `
                    -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            }

            # Process AuditCategories
            if ($policy.AuditCategories -and @($policy.AuditCategories).Count -gt 0) {
                $mappedCategories = @()
                $reviewReasons = @("Original MDE action was 'Audit' (monitor only, no enforcement) — converted to Block")

                foreach ($catName in @($policy.AuditCategories)) {
                    $result = Resolve-MdeCategory -CategoryName $catName
                    $mappedCategories += $result.EIACategory
                    if (-not $result.IsMapped) {
                        $reviewReasons += "Unmapped category: $catName"
                    }
                }

                $auditedPolicyName = "WCF-$policyNameClean-Audited-Block"

                [void]$allPolicies.Add([PSCustomObject]@{
                    PolicyName       = $auditedPolicyName
                    PolicyType       = "WebContentFiltering"
                    PolicyAction     = "Block"
                    Description      = "Converted from MDE WCF policy: $($policy.PolicyName) (audited categories — originally monitor-only)"
                    RuleType         = "webCategory"
                    RuleDestinations = $mappedCategories -join ";"
                    RuleName         = "AuditedCategories"
                    ReviewNeeded     = "Yes"
                    ReviewDetails    = $reviewReasons -join "; "
                    Provision        = "no"
                })

                # Route to scope
                if ($scopeKey -eq "DEFAULT") {
                    $defaultScopePolicies += $auditedPolicyName
                }
                else {
                    Add-ToScopeBucket -ScopeKey $scopeKey -PolicyName $auditedPolicyName -RbacGroupNames @($policy.RbacGroupNames)
                }

                $stats.PoliciesCreated++
                Write-LogMessage "Created policy '$auditedPolicyName' with $($mappedCategories.Count) categories (scope: $scopeKey, ReviewNeeded=Yes)" -Level "DEBUG" `
                    -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            }

            $stats.WcfPoliciesProcessed++
        }

        Write-LogMessage "Phase 2 complete: $($stats.WcfPoliciesProcessed) WCF policies processed" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    else {
        Write-LogMessage "Phase 2: Skipped — WCF policies not provided" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    #endregion

    #region Phase 3: IP Indicator Logging

    if ($hasIpIndicators -and $rawIpIndicators) {
        Write-LogMessage "Phase 3: Processing IP indicators (skip-and-log only)..." -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

        $ipIndicators = @($rawIpIndicators)

        if ($ipIndicators.Count -gt 0) {
            Write-LogMessage "Found $($ipIndicators.Count) IP indicator(s) — these cannot be converted (EIA does not support IP address destinations)" -Level "WARN" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

            foreach ($indicator in $ipIndicators) {
                $stats.IpIndicatorsSkipped++
                $enabledLabel = if ($indicator.isEnabled) { "enabled" } else { "disabled" }
                Write-LogMessage "  IP indicator '$($indicator.title)' ($($indicator.indicatorValue), action: $($indicator.action), $enabledLabel) — skipped: EIA does not support IP address destinations" -Level "WARN" `
                    -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            }

            Write-LogMessage "ACTION REQUIRED: Review the $($ipIndicators.Count) skipped IP indicator(s) above and consider manually creating equivalent FQDN-based rules or alternative controls in EIA" -Level "WARN" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
        else {
            Write-LogMessage "No IP indicators found — nothing to skip" -Level "INFO" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }

        Write-LogMessage "Phase 3 complete" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    else {
        Write-LogMessage "Phase 3: Skipped — IP indicators not provided" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    #endregion

    #region Phase 4: URL/Domain Indicator Processing

    if ($hasUrlIndicators -and $rawUrlIndicators) {
        Write-LogMessage "Phase 4: Processing URL/Domain indicators..." -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

        $urlIndicators = @($rawUrlIndicators)

        # Group structure: (mappedAction × scopeKey) → list of FQDN entries + review info
        $fqdnGroups = @{}

        foreach ($indicator in $urlIndicators) {
            # Skip disabled
            if (-not $indicator.isEnabled) {
                $stats.UrlIndicatorsSkippedDisabled++
                Write-LogMessage "URL indicator '$($indicator.title)' (ID: $($indicator.indicatorId)) is disabled — skipping" -Level "DEBUG" `
                    -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                continue
            }

            # Skip expired
            if ($indicator.expirationTime) {
                $expiry = [datetime]::Parse($indicator.expirationTime)
                if ($expiry -lt (Get-Date)) {
                    $stats.UrlIndicatorsSkippedExpired++
                    Write-LogMessage "URL indicator '$($indicator.title)' (ID: $($indicator.indicatorId)) expired at $($indicator.expirationTime) — skipping" -Level "INFO" `
                        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                    continue
                }
            }

            # Map action
            $mappedAction = switch ($indicator.action) {
                "Block"     { "Block" }
                "Allow"     { "Allow" }
                "Warn"      { "Block" }
                "AlertOnly" { "Allow" }
            }
            $hasReview = $indicator.action -in @("Warn", "AlertOnly")
            $reviewDetail = switch ($indicator.action) {
                "Warn"      { "Original MDE action was 'Warn' (user bypass allowed) — converted to Block" }
                "AlertOnly" { "Original MDE action was 'AlertOnly' (monitor only, no enforcement) — converted to Allow" }
                default     { "" }
            }

            if ($indicator.action -eq "Warn") { $stats.IndicatorsWarn++ }
            if ($indicator.action -eq "AlertOnly") { $stats.IndicatorsAlertOnly++ }

            # Build FQDN entries
            $value = $indicator.indicatorValue
            $fqdnEntries = @()
            if ($value -match '/') {
                # Contains path — treat as URL, use as-is
                $fqdnEntries += $value
            }
            else {
                # Domain — apply dual FQDN pattern
                $fqdnEntries += $value
                $fqdnEntries += "*.$value"
            }

            # Determine scope
            $scopeKey = Resolve-ScopeKey -RbacGroupNames $indicator.rbacGroupNames

            # Group key
            $groupKey = "${mappedAction}|${scopeKey}"

            if (-not $fqdnGroups.ContainsKey($groupKey)) {
                $fqdnGroups[$groupKey] = @{
                    Action        = $mappedAction
                    ScopeKey      = $scopeKey
                    FqdnEntries   = @()
                    ReviewReasons = @()
                    HasReview     = $false
                }
            }

            $fqdnGroups[$groupKey].FqdnEntries += $fqdnEntries
            if ($hasReview) {
                $fqdnGroups[$groupKey].HasReview = $true
                $fqdnGroups[$groupKey].ReviewReasons += "$reviewDetail (indicator: $($indicator.title))"
            }

            $stats.UrlIndicatorsProcessed++
            Write-LogMessage "URL indicator '$($indicator.title)': $value → $mappedAction (scope: $scopeKey)" -Level "DEBUG" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }

        # Create policies from grouped indicators
        foreach ($groupKey in $fqdnGroups.Keys) {
            $group = $fqdnGroups[$groupKey]
            $action = $group.Action
            $scopeKey = $group.ScopeKey

            # Build policy name
            if ($scopeKey -eq "DEFAULT") {
                $indicatorPolicyName = "Indicators-FQDN-$action"
            }
            else {
                $scopeLabel = ($scopeKey -split ";")[0] -replace '\s+', '-' -replace '[^a-zA-Z0-9_-]', ''
                $indicatorPolicyName = "Indicators-FQDN-$scopeLabel-$action"
            }

            $uniqueReviewReasons = $group.ReviewReasons | Select-Object -Unique

            # Split by character limit
            $groups = Split-ByCharacterLimit -Entries $group.FqdnEntries -MaxLength 300 `
                -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

            for ($i = 0; $i -lt $groups.Count; $i++) {
                $ruleName = if ($i -eq 0) { "FQDNs" } else { "FQDNs-$($i + 1)" }

                [void]$allPolicies.Add([PSCustomObject]@{
                    PolicyName       = $indicatorPolicyName
                    PolicyType       = "WebContentFiltering"
                    PolicyAction     = $action
                    Description      = "Converted from MDE URL/Domain indicators ($action)"
                    RuleType         = "FQDN"
                    RuleDestinations = $groups[$i] -join ";"
                    RuleName         = $ruleName
                    ReviewNeeded     = if ($group.HasReview) { "Yes" } else { "No" }
                    ReviewDetails    = $uniqueReviewReasons -join "; "
                    Provision        = if ($group.HasReview) { "no" } else { "yes" }
                })
            }

            # Route to scope
            if ($scopeKey -eq "DEFAULT") {
                $defaultScopePolicies += $indicatorPolicyName
            }
            else {
                Add-ToScopeBucket -ScopeKey $scopeKey -PolicyName $indicatorPolicyName -RbacGroupNames ($scopeKey -split ";")
            }

            $stats.PoliciesCreated++
            Write-LogMessage "Created policy '$indicatorPolicyName' with $($group.FqdnEntries.Count) FQDN entries in $($groups.Count) rule(s) (scope: $scopeKey)" -Level "DEBUG" `
                -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }

        Write-LogMessage "Phase 4 complete: $($stats.UrlIndicatorsProcessed) URL/Domain indicators processed" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    else {
        Write-LogMessage "Phase 4: Skipped — URL/Domain indicators not provided" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    #endregion

    #region Phase 5: Security Profile Assembly

    Write-LogMessage "Phase 5: Assembling security profiles..." -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Create Default Security Profile
    $uniqueDefaultPolicies = $defaultScopePolicies | Select-Object -Unique

    if ($uniqueDefaultPolicies.Count -gt 0) {
        $linkPriority = 100
        $profileLinks = @()
        foreach ($pName in $uniqueDefaultPolicies) {
            $profileLinks += "${pName}:${linkPriority}"
            $linkPriority += 100
        }

        [void]$securityProfiles.Add([PSCustomObject]@{
            SecurityProfileName  = "Default-MDE"
            Priority             = 50000
            SecurityProfileLinks = $profileLinks -join ";"
            CADisplayName        = "CA-EIA-Default-MDE"
            EntraUsers           = ""
            EntraGroups          = "All Internet Access Users"
            Provision            = "yes"
        })

        $stats.SecurityProfilesCreated++
        Write-LogMessage "Created Default Security Profile with $($uniqueDefaultPolicies.Count) policy link(s)" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    else {
        Write-LogMessage "No policies for Default Security Profile — skipping default profile creation" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    # Create Override Security Profiles
    $overridePriority = 1000

    foreach ($scopeKey in $scopedPolicyBuckets.Keys) {
        $scopeData = $scopedPolicyBuckets[$scopeKey]

        $uniquePolicies = $scopeData.Policies | Select-Object -Unique

        # Build SecurityProfileLinks
        $linkPriority = 100
        $profileLinks = @()
        foreach ($pName in $uniquePolicies) {
            $profileLinks += "${pName}:${linkPriority}"
            $linkPriority += 100
        }

        # Generate profile name from device group names
        $groupLabel = ($scopeData.DeviceGroupNames | Select-Object -First 2) -join "-"
        $groupLabel = $groupLabel -replace '\s+', '-' -replace '[^a-zA-Z0-9_-]', ''
        $profileName = "Override-$groupLabel"

        [void]$securityProfiles.Add([PSCustomObject]@{
            SecurityProfileName  = $profileName
            Priority             = $overridePriority
            SecurityProfileLinks = $profileLinks -join ";"
            CADisplayName        = "CA-EIA-$profileName"
            EntraUsers           = ""
            EntraGroups          = $scopeData.EntraGroups -join ";"
            Provision            = "yes"
        })

        $overridePriority += 100
        $stats.SecurityProfilesCreated++
        Write-LogMessage "Created Override Security Profile '$profileName' with $($uniquePolicies.Count) policy link(s), Entra groups: $($scopeData.EntraGroups -join ', ')" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    Write-LogMessage "Phase 5 complete: $($stats.SecurityProfilesCreated) security profile(s) created" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    #endregion

    #region Phase 6: Export and Summary

    Write-LogMessage "Phase 6: Exporting output files..." -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Export Policies CSV
    $policiesCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_Policies.csv"
    $allPolicies | Export-Csv -Path $policiesCsvPath -NoTypeInformation -Encoding utf8BOM
    Write-LogMessage "Exported $($allPolicies.Count) policy rows to: $policiesCsvPath" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Export Security Profiles CSV
    $spCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_SecurityProfiles.csv"
    $securityProfiles | Export-Csv -Path $spCsvPath -NoTypeInformation -Encoding utf8BOM
    Write-LogMessage "Exported $($securityProfiles.Count) security profiles to: $spCsvPath" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Count policy subtypes
    $webCategoryPolicyCount = @($allPolicies | Where-Object { $_.RuleType -eq "webCategory" } | Select-Object -ExpandProperty PolicyName -Unique).Count
    $fqdnPolicyCount = @($allPolicies | Where-Object { $_.RuleType -eq "FQDN" } | Select-Object -ExpandProperty PolicyName -Unique).Count
    $defaultProfileCount = if ($uniqueDefaultPolicies.Count -gt 0) { 1 } else { 0 }
    $overrideCount = $stats.SecurityProfilesCreated - $defaultProfileCount

    # Generate Summary Statistics
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "=== CONVERSION SUMMARY ===" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    if ($hasWcfPolicies) {
        Write-LogMessage "WCF policies processed: $($stats.WcfPoliciesProcessed)" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        Write-LogMessage "WCF policies skipped by filter: $($stats.WcfPoliciesSkippedByFilter)" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    else {
        Write-LogMessage "WCF policies: N/A — not provided" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Categories mapped: $($stats.CategoriesMapped)" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Categories unmapped: $($stats.CategoriesUnmapped)" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "IP indicators skipped (not supported): $($stats.IpIndicatorsSkipped)" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    if ($hasUrlIndicators) {
        Write-LogMessage "URL/Domain indicators processed: $($stats.UrlIndicatorsProcessed)" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        Write-LogMessage "URL/Domain indicators skipped (disabled): $($stats.UrlIndicatorsSkippedDisabled)" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        Write-LogMessage "URL/Domain indicators skipped (expired): $($stats.UrlIndicatorsSkippedExpired)" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        Write-LogMessage "" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        Write-LogMessage "URL/Domain indicators with Warn action (-> Block + review): $($stats.IndicatorsWarn)" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        Write-LogMessage "URL/Domain indicators with AlertOnly action (-> Allow + review): $($stats.IndicatorsAlertOnly)" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    else {
        Write-LogMessage "URL/Domain indicators: N/A — not provided" -Level "INFO" `
            -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Policies created: $($stats.PoliciesCreated)" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - webCategory policies: $webCategoryPolicyCount" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - FQDN policies: $fqdnPolicyCount" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Security profiles created: $($stats.SecurityProfilesCreated)" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Default: $defaultProfileCount" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Overrides: $overrideCount" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Output files:" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Policies: $policiesCsvPath" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Security Profiles: $spCsvPath" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Log File: $logPath" -Level "INFO" `
        -Component "Convert-MDE2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Send usage telemetry (non-critical — do not let telemetry failures surface to user)
    try {
        Send-UsageTelemetry -EventName 'Convert-MDE2EIA' `
            -Properties @{
                HasWcfPolicies   = $hasWcfPolicies.ToString()
                HasIpIndicators  = $hasIpIndicators.ToString()
                HasUrlIndicators = $hasUrlIndicators.ToString()
                HasDeviceGroups  = $hasDeviceGroups.ToString()
                HasFilters       = ($PSBoundParameters.ContainsKey('IncludePolicyName') -or $PSBoundParameters.ContainsKey('ExcludePolicyName')).ToString()
            } `
            -Metrics @{
                WcfPoliciesProcessed         = $stats.WcfPoliciesProcessed
                WcfPoliciesSkippedByFilter   = $stats.WcfPoliciesSkippedByFilter
                CategoriesMapped             = $stats.CategoriesMapped
                CategoriesUnmapped           = $stats.CategoriesUnmapped
                IpIndicatorsSkipped          = $stats.IpIndicatorsSkipped
                UrlIndicatorsProcessed       = $stats.UrlIndicatorsProcessed
                UrlIndicatorsSkippedDisabled = $stats.UrlIndicatorsSkippedDisabled
                UrlIndicatorsSkippedExpired  = $stats.UrlIndicatorsSkippedExpired
                IndicatorsWarn               = $stats.IndicatorsWarn
                IndicatorsAlertOnly          = $stats.IndicatorsAlertOnly
                PoliciesCreated              = $stats.PoliciesCreated
                SecurityProfilesCreated      = $stats.SecurityProfilesCreated
            }
    }
    catch {
        # Telemetry is best-effort; do not fail the conversion
    }

    #endregion
}
