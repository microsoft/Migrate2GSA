function Convert-PANW2EIA {
    <#
    .SYNOPSIS
        Converts Palo Alto Networks (PANW) Panorama XML configuration to Microsoft Entra Internet Access (EIA) format.

    .DESCRIPTION
        This function processes Palo Alto Panorama XML exports containing security rules, URL filtering profiles,
        custom URL categories, and predefined PAN-DB category actions to generate CSV files ready for import
        into Microsoft Entra Internet Access (EIA) via Start-EntraInternetAccessProvisioning.

        The conversion process includes:
        - Parsing Panorama XML export (shared and device-group configurations)
        - Transforming PANW URL filtering profiles to EIA web content filtering policies
        - Converting PANW custom URL categories to EIA web content filtering policies (FQDN/URL rules)
        - Mapping PAN-DB predefined web categories to GSA web categories
        - Converting PANW security rules (with URL filtering profile references) to EIA security profiles
        - Flagging application-based rules for manual review
        - Generating import-ready CSV files for EIA configuration

    .PARAMETER PanoramaXmlPath
        Path to the Panorama XML export file.

    .PARAMETER CategoryMappingsPath
        Path to the PANW to GSA category mappings CSV file.
        Default: PANW2EIA-CategoryMappings.csv in script root directory.

    .PARAMETER AppMappingsPath
        Path to the App-ID to GSA application mappings CSV file. Optional.
        If not provided, application references are flagged for review.

    .PARAMETER DeviceGroupName
        Filter to a specific device-group name. If not specified, all device-groups are processed.

    .PARAMETER OutputBasePath
        Base directory for output CSV files and log file.
        Default: Current directory.

    .PARAMETER IncludePolicyName
        Wildcard patterns to include. Only matching security rules are processed.

    .PARAMETER ExcludePolicyName
        Wildcard patterns to exclude. Matching security rules are skipped. Exclude wins over include.

    .PARAMETER EnableDebugLogging
        Enable verbose debug logging for detailed processing information.

    .EXAMPLE
        Convert-PANW2EIA -PanoramaXmlPath "C:\PANW\panorama_config.xml" -CategoryMappingsPath "C:\Mappings\PANW2EIA-CategoryMappings.csv"

        Converts Panorama configuration using specified paths.

    .EXAMPLE
        Convert-PANW2EIA -PanoramaXmlPath "panorama.xml" -CategoryMappingsPath "PANW2EIA-CategoryMappings.csv" -DeviceGroupName "DG-Corporate"

        Converts only the DG-Corporate device-group.

    .EXAMPLE
        Convert-PANW2EIA -PanoramaXmlPath "panorama.xml" -CategoryMappingsPath "PANW2EIA-CategoryMappings.csv" -AppMappingsPath "PANW2EIA-AppMappings.csv" -EnableDebugLogging

        Converts with application mapping support and debug logging enabled.

    .NOTES
        Author: Wendy Badilla
        Version: 1.2
        Date: 2026-03-16

        Requirements:
        - Panorama XML configuration export
        - PANW to GSA category mappings CSV file
        - Optionally, PANW to GSA app mappings CSV file

        Known Limitations:
        - IP addresses not supported by EIA (logged and skipped)
        - Category Match type custom URL categories are not processed
        - CIDR ranges and port numbers not supported
        - Application filtering requires App Mappings CSV for endpoint-based conversion
    #>

    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Path to Panorama XML export file")]
        [ValidateScript({
            if (Test-Path $_ -PathType Leaf) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$PanoramaXmlPath,

        [Parameter(HelpMessage = "Path to PANW to GSA category mappings CSV file")]
        [ValidateScript({
            if (Test-Path $_ -PathType Leaf) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$CategoryMappingsPath = (Join-Path $PWD "PANW2EIA-CategoryMappings.csv"),

        [Parameter(HelpMessage = "Path to App-ID to GSA application mappings CSV file")]
        [ValidateScript({
            if (Test-Path $_ -PathType Leaf) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$AppMappingsPath,

        [Parameter(HelpMessage = "Filter to specific device-group name")]
        [string]$DeviceGroupName,

        [Parameter(HelpMessage = "Base directory for output files")]
        [ValidateScript({
            if (Test-Path $_ -PathType Container) { return $true }
            else { throw "Directory not found: $_" }
        })]
        [string]$OutputBasePath = $PWD,

        [Parameter(HelpMessage = "Wildcard patterns to include")]
        [string[]]$IncludePolicyName,

        [Parameter(HelpMessage = "Wildcard patterns to exclude")]
        [string[]]$ExcludePolicyName,

        [Parameter(HelpMessage = "Enable verbose debug logging")]
        [switch]$EnableDebugLogging
    )

    Set-StrictMode -Version Latest

    #region Helper Functions

    function Import-PanoramaXml {
        <#
        .SYNOPSIS
            Load and validate the Panorama XML export.
        #>
        param([string]$Path)

        try {
            $xmlContent = Get-Content -Path $Path -Raw -ErrorAction Stop
            $xmlDoc = [xml]$xmlContent
        }
        catch {
            throw "Failed to parse XML file '$Path': $_"
        }

        if ($null -eq $xmlDoc.config) {
            throw "Invalid Panorama XML: root element 'config' not found in '$Path'"
        }

        return $xmlDoc
    }

    function Get-PANWCustomUrlCategories {
        <#
        .SYNOPSIS
            Extract custom URL categories from shared and device-group scope.
        #>
        param(
            [System.Xml.XmlElement]$SharedNode,
            [System.Xml.XmlElement]$DeviceGroupNode
        )

        $categories = @{}

        # Collect from shared scope
        if ($null -ne $SharedNode) {
            $sharedCats = $SharedNode.SelectNodes("profiles/custom-url-category/entry")
            if ($null -ne $sharedCats) {
                foreach ($entry in $sharedCats) {
                    $name = $entry.GetAttribute("name")
                    $typeElement = $entry.SelectSingleNode("type")
                    $descElement = $entry.SelectSingleNode("description")
                    $listElement = $entry.SelectSingleNode("list")

                    $members = @()
                    if ($null -ne $listElement) {
                        $memberNodes = $listElement.SelectNodes("member")
                        if ($null -ne $memberNodes) {
                            foreach ($m in $memberNodes) {
                                $members += $m.InnerText
                            }
                        }
                    }

                    $categories[$name] = @{
                        Name        = $name
                        Type        = if ($null -ne $typeElement) { $typeElement.InnerText } else { "" }
                        Description = if ($null -ne $descElement) { $descElement.InnerText } else { "" }
                        Members     = $members
                    }
                }
            }
        }

        # Collect from device-group scope (overrides shared)
        if ($null -ne $DeviceGroupNode) {
            $dgCats = $DeviceGroupNode.SelectNodes("profiles/custom-url-category/entry")
            if ($null -ne $dgCats) {
                foreach ($entry in $dgCats) {
                    $name = $entry.GetAttribute("name")
                    $typeElement = $entry.SelectSingleNode("type")
                    $descElement = $entry.SelectSingleNode("description")
                    $listElement = $entry.SelectSingleNode("list")

                    $members = @()
                    if ($null -ne $listElement) {
                        $memberNodes = $listElement.SelectNodes("member")
                        if ($null -ne $memberNodes) {
                            foreach ($m in $memberNodes) {
                                $members += $m.InnerText
                            }
                        }
                    }

                    $categories[$name] = @{
                        Name        = $name
                        Type        = if ($null -ne $typeElement) { $typeElement.InnerText } else { "" }
                        Description = if ($null -ne $descElement) { $descElement.InnerText } else { "" }
                        Members     = $members
                    }
                }
            }
        }

        return $categories
    }

    function Get-PANWUrlFilteringProfiles {
        <#
        .SYNOPSIS
            Extract URL filtering profiles from shared and device-group scope.
        #>
        param(
            [System.Xml.XmlElement]$SharedNode,
            [System.Xml.XmlElement]$DeviceGroupNode
        )

        $profiles = @{}
        $actionNames = @('allow', 'block', 'alert', 'continue', 'override')

        # Helper to parse a single profile entry
        $parseProfile = {
            param($entry)
            $name = $entry.GetAttribute("name")
            $descElement = $entry.SelectSingleNode("description")
            $profileData = @{
                Name        = $name
                Description = if ($null -ne $descElement) { $descElement.InnerText } else { "" }
                Categories  = @{}
            }
            foreach ($actionName in $actionNames) {
                $actionNode = $entry.SelectSingleNode($actionName)
                $catMembers = @()
                if ($null -ne $actionNode) {
                    $memberNodes = $actionNode.SelectNodes("member")
                    if ($null -ne $memberNodes) {
                        foreach ($m in $memberNodes) {
                            $catMembers += $m.InnerText
                        }
                    }
                }
                $profileData.Categories[$actionName] = $catMembers
            }
            return $profileData
        }

        # Collect from shared scope
        if ($null -ne $SharedNode) {
            $sharedProfiles = $SharedNode.SelectNodes("profiles/url-filtering/entry")
            if ($null -ne $sharedProfiles) {
                foreach ($entry in $sharedProfiles) {
                    $profileData = & $parseProfile $entry
                    $profiles[$profileData.Name] = $profileData
                }
            }
        }

        # Collect from device-group scope (overrides shared)
        if ($null -ne $DeviceGroupNode) {
            $dgProfiles = $DeviceGroupNode.SelectNodes("profiles/url-filtering/entry")
            if ($null -ne $dgProfiles) {
                foreach ($entry in $dgProfiles) {
                    $profileData = & $parseProfile $entry
                    $profiles[$profileData.Name] = $profileData
                }
            }
        }

        return $profiles
    }

    function Get-PANWProfileGroups {
        <#
        .SYNOPSIS
            Build profile group -> URL filtering profile lookup table.
        #>
        param(
            [System.Xml.XmlElement]$SharedNode,
            [System.Xml.XmlElement]$DeviceGroupNode
        )

        $profileGroups = @{}

        # Helper to parse profile group entries
        $parseGroups = {
            param($parentNode, $xpath)
            if ($null -eq $parentNode) { return }
            $entries = $parentNode.SelectNodes($xpath)
            if ($null -eq $entries) { return }
            foreach ($entry in $entries) {
                $name = $entry.GetAttribute("name")
                $urlFilterMember = $entry.SelectSingleNode("url-filtering/member")
                if ($null -ne $urlFilterMember) {
                    $profileGroups[$name] = $urlFilterMember.InnerText
                }
            }
        }

        # Collect from shared scope
        & $parseGroups $SharedNode "profile-group/entry"

        # Collect from device-group scope (overrides shared)
        & $parseGroups $DeviceGroupNode "profile-group/entry"

        return $profileGroups
    }

    function Get-PANWSecurityRules {
        <#
        .SYNOPSIS
            Extract security rules from pre-rulebase and post-rulebase, maintaining order.
        #>
        param([System.Xml.XmlElement]$DeviceGroupNode)

        $rules = [System.Collections.ArrayList]::new()
        $order = 0

        foreach ($rulebaseType in @('pre-rulebase', 'post-rulebase')) {
            $rulesPath = "$rulebaseType/security/rules/entry"
            $ruleEntries = $DeviceGroupNode.SelectNodes($rulesPath)
            if ($null -eq $ruleEntries) { continue }

            foreach ($entry in $ruleEntries) {
                $name = $entry.GetAttribute("name")
                $actionNode = $entry.SelectSingleNode("action")
                $disabledNode = $entry.SelectSingleNode("disabled")
                $descNode = $entry.SelectSingleNode("description")

                # Extract source users
                $sourceUsers = @()
                $suNodes = $entry.SelectNodes("source-user/member")
                if ($null -ne $suNodes) {
                    foreach ($su in $suNodes) { $sourceUsers += $su.InnerText }
                }

                # Extract applications
                $applications = @()
                $appNodes = $entry.SelectNodes("application/member")
                if ($null -ne $appNodes) {
                    foreach ($app in $appNodes) { $applications += $app.InnerText }
                }

                $rule = @{
                    Name           = $name
                    Action         = if ($null -ne $actionNode) { $actionNode.InnerText } else { "" }
                    Disabled       = if ($null -ne $disabledNode -and $disabledNode.InnerText -eq 'yes') { $true } else { $false }
                    SourceUsers    = $sourceUsers
                    Applications   = $applications
                    ProfileSetting = $entry.SelectSingleNode("profile-setting")
                    Description    = if ($null -ne $descNode) { $descNode.InnerText } else { "" }
                    RulebaseType   = $rulebaseType
                    Order          = $order
                }

                [void]$rules.Add($rule)
                $order++
            }
        }

        return $rules
    }

    function Resolve-UrlFilteringProfile {
        <#
        .SYNOPSIS
            Given a security rule's profile-setting, resolve to the URL filtering profile name.
        #>
        param(
            [System.Xml.XmlElement]$ProfileSettingNode,
            [hashtable]$ProfileGroupsHashtable
        )

        if ($null -eq $ProfileSettingNode) { return $null }

        # Check for profile group reference
        $groupMember = $ProfileSettingNode.SelectSingleNode("group/member")
        if ($null -ne $groupMember) {
            $groupName = $groupMember.InnerText
            if ($ProfileGroupsHashtable.ContainsKey($groupName)) {
                return $ProfileGroupsHashtable[$groupName]
            }
            Write-LogMessage "Profile group '$groupName' not found in lookup table" -Level "WARN" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
            return $null
        }

        # Check for direct profile reference
        $directMember = $ProfileSettingNode.SelectSingleNode("profiles/url-filtering/member")
        if ($null -ne $directMember) {
            return $directMember.InnerText
        }

        return $null
    }

    function Test-PolicyNameFilter {
        <#
        .SYNOPSIS
            Evaluate whether a rule name should be processed based on include/exclude wildcard patterns.
        #>
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
                if ($PolicyName -like $pattern) { $included = $true; break }
            }
            if (-not $included) { return $false }
        }

        # If exclude patterns specified, policy must not match any (exclude wins)
        if ($null -ne $ExcludePatterns -and $ExcludePatterns.Count -gt 0) {
            foreach ($pattern in $ExcludePatterns) {
                if ($PolicyName -like $pattern) { return $false }
            }
        }

        return $true
    }

    #endregion Helper Functions

    #region Initialization

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:logPath = Join-Path $OutputBasePath "${timestamp}_Convert-PANW2EIA.log"
    $script:EnableDebugLogging = $EnableDebugLogging

    Write-LogMessage "===== Convert-PANW2EIA Started =====" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "Timestamp: $timestamp" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "Input files:" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Panorama XML: $PanoramaXmlPath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Category Mappings: $CategoryMappingsPath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    if ($PSBoundParameters.ContainsKey('AppMappingsPath')) {
        Write-LogMessage "  App Mappings: $AppMappingsPath" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    }
    else {
        Write-LogMessage "  App Mappings: (not provided)" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    }
    Write-LogMessage "  Output Path: $OutputBasePath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    if ($DeviceGroupName) {
        Write-LogMessage "  Device Group Filter: $DeviceGroupName" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    }

    # Initialize statistics
    $stats = @{
        SecurityRulesLoaded              = 0
        PreRulebaseRules                 = 0
        PostRulebaseRules                = 0
        RulesProcessed                   = 0
        RulesSkippedDisabled             = 0
        RulesSkippedDenyDropReset        = 0
        RulesSkippedNoUrlFilterOrApps    = 0
        RulesSkippedFiltered             = 0
        RulesWithApplicationRefs         = 0
        AppsMappedWithEndpoints          = 0
        AppsMappedWithoutEndpoints       = 0
        AppsUnmapped                     = 0
        UrlFilteringProfilesProcessed    = 0
        CustomCategoriesProcessed        = 0
        CustomCategoriesSkippedCatMatch  = 0
        CustomCategoriesSkippedEmpty     = 0
        PanDBCategoriesReferenced        = 0
        CategoriesMappedExact            = 0
        CategoriesMappedPartial          = 0
        CategoriesUnmapped               = 0
        FQDNsClassified                  = 0
        URLsClassified                   = 0
        IPsSkipped                       = 0
        IPv6Skipped                      = 0
        PoliciesCreated                  = 0
        CustomCategoryPolicies           = 0
        WebCategoryPolicies              = 0
        ApplicationPolicies              = 0
        PoliciesFlaggedForReview         = 0
        SecurityProfilesCreated          = 0
        DefaultProfileCount              = 0
        OverrideProfileCount             = 0
        RulesAggregated                  = 0
        PriorityConflictsResolved        = 0
        UnreferencedPoliciesRemoved      = 0
        DeviceGroupsProcessed            = 0
    }

    # Collections for output
    $policies = [System.Collections.ArrayList]::new()
    $securityProfiles = [System.Collections.ArrayList]::new()

    #endregion Initialization

    #region Phase 1: Data Loading

    Write-LogMessage "===== Phase 1: Data Loading and Validation =====" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    # 1.1 Load and parse XML
    Write-LogMessage "Loading Panorama XML from: $PanoramaXmlPath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    try {
        $xmlDoc = Import-PanoramaXml -Path $PanoramaXmlPath
    }
    catch {
        Write-LogMessage "Fatal error: $_" -Level "ERROR" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
        throw
    }

    # 1.2 Load category mappings
    Write-LogMessage "Loading category mappings from: $CategoryMappingsPath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    try {
        $categoryMappingsRaw = Import-Csv -Path $CategoryMappingsPath -ErrorAction Stop
        $categoryMappingsHashtable = @{}
        foreach ($row in $categoryMappingsRaw) {
            $categoryMappingsHashtable[$row.PANWCategory.ToLower()] = @{
                GSACategory  = $row.GSACategory
                MappingNotes = if ($row.PSObject.Properties['MappingNotes']) { $row.MappingNotes } else { "" }
            }
        }
        Write-LogMessage "Loaded $($categoryMappingsHashtable.Count) category mappings" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    }
    catch {
        $errorMsg = "Failed to load category mappings: $_"
        Write-LogMessage $errorMsg -Level "ERROR" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
        throw $errorMsg
    }

    # 1.3 Load app mappings (optional)
    $appMappingsHashtable = @{}
    $hasAppMappings = $false

    if ($PSBoundParameters.ContainsKey('AppMappingsPath')) {
        Write-LogMessage "Loading app mappings from: $AppMappingsPath" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

        try {
            $appMappingsRaw = Import-Csv -Path $AppMappingsPath -ErrorAction Stop
            foreach ($row in $appMappingsRaw) {
                $appMappingsHashtable[$row.PANWAppName.ToLower()] = @{
                    GSAAppName   = if ($row.PSObject.Properties['GSAAppName']) { $row.GSAAppName } else { "" }
                    MatchType    = if ($row.PSObject.Properties['MatchType']) { $row.MatchType } else { "" }
                    GSAEndpoints = if ($row.PSObject.Properties['GSAEndpoints']) { $row.GSAEndpoints } else { "" }
                }
            }
            $hasAppMappings = $true
            Write-LogMessage "Loaded $($appMappingsHashtable.Count) app mappings" -Level "INFO" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
        }
        catch {
            $errorMsg = "Failed to load app mappings: $_"
            Write-LogMessage $errorMsg -Level "ERROR" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
            throw $errorMsg
        }
    }
    else {
        Write-LogMessage "No app mappings file provided; application references will be flagged for review" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    }

    # 1.4 Determine scope - enumerate device-groups
    $sharedNode = $xmlDoc.config.shared
    if ($null -ne $sharedNode) {
        Write-LogMessage "Shared objects section found" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    }
    else {
        Write-LogMessage "No shared objects section found" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    }

    $deviceGroupEntries = $xmlDoc.config.SelectNodes("devices/entry/device-group/entry")
    if ($null -eq $deviceGroupEntries -or $deviceGroupEntries.Count -eq 0) {
        $errorMsg = "No device-groups found in Panorama XML"
        Write-LogMessage $errorMsg -Level "ERROR" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
        throw $errorMsg
    }

    # Filter device-groups if specified
    $deviceGroupsToProcess = [System.Collections.ArrayList]::new()

    foreach ($dgEntry in $deviceGroupEntries) {
        $dgName = $dgEntry.GetAttribute("name")
        if ($DeviceGroupName) {
            if ($dgName -eq $DeviceGroupName) {
                [void]$deviceGroupsToProcess.Add($dgEntry)
            }
        }
        else {
            [void]$deviceGroupsToProcess.Add($dgEntry)
        }
    }

    if ($DeviceGroupName -and $deviceGroupsToProcess.Count -eq 0) {
        $errorMsg = "Specified device-group '$DeviceGroupName' not found in Panorama XML"
        Write-LogMessage $errorMsg -Level "ERROR" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
        throw $errorMsg
    }

    $dgNames = $deviceGroupsToProcess | ForEach-Object { $_.GetAttribute("name") }
    Write-LogMessage "Device-groups to process: $($dgNames -join ', ')" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    # 1.5 Build object collections across all device-groups
    $allCustomCategories = @{}
    $allUrlFilteringProfiles = @{}
    $allProfileGroups = @{}
    $allSecurityRules = [System.Collections.ArrayList]::new()

    foreach ($dgEntry in $deviceGroupsToProcess) {
        $dgName = $dgEntry.GetAttribute("name")
        Write-LogMessage "Processing device-group: $dgName" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

        # Custom URL categories
        $dgCategories = Get-PANWCustomUrlCategories -SharedNode $sharedNode -DeviceGroupNode $dgEntry
        foreach ($key in $dgCategories.Keys) {
            $allCustomCategories[$key] = $dgCategories[$key]
        }

        # URL filtering profiles
        $dgProfiles = Get-PANWUrlFilteringProfiles -SharedNode $sharedNode -DeviceGroupNode $dgEntry
        foreach ($key in $dgProfiles.Keys) {
            $allUrlFilteringProfiles[$key] = $dgProfiles[$key]
        }

        # Profile groups
        $dgProfileGroups = Get-PANWProfileGroups -SharedNode $sharedNode -DeviceGroupNode $dgEntry
        foreach ($key in $dgProfileGroups.Keys) {
            $allProfileGroups[$key] = $dgProfileGroups[$key]
        }

        # Security rules
        $dgRules = Get-PANWSecurityRules -DeviceGroupNode $dgEntry
        foreach ($rule in $dgRules) {
            [void]$allSecurityRules.Add($rule)
        }

        $stats.DeviceGroupsProcessed++
    }

    # Log counts
    $urlListCategories = @($allCustomCategories.Values | Where-Object { $_.Type -eq 'URL List' })
    $catMatchCategories = @($allCustomCategories.Values | Where-Object { $_.Type -eq 'Category Match' })
    $stats.CustomCategoriesSkippedCatMatch = $catMatchCategories.Count

    Write-LogMessage "Total custom URL categories: $($allCustomCategories.Count) (URL List: $($urlListCategories.Count), Category Match: $($catMatchCategories.Count))" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "Total URL filtering profiles: $($allUrlFilteringProfiles.Count)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "Total profile groups: $($allProfileGroups.Count)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    $stats.SecurityRulesLoaded = $allSecurityRules.Count
    $stats.PreRulebaseRules = @($allSecurityRules | Where-Object { $_.RulebaseType -eq 'pre-rulebase' }).Count
    $stats.PostRulebaseRules = @($allSecurityRules | Where-Object { $_.RulebaseType -eq 'post-rulebase' }).Count

    Write-LogMessage "Total security rules: $($stats.SecurityRulesLoaded) (pre: $($stats.PreRulebaseRules), post: $($stats.PostRulebaseRules))" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    if ($catMatchCategories.Count -gt 0) {
        foreach ($cat in $catMatchCategories) {
            Write-LogMessage "Skipping Category Match type custom URL category: $($cat.Name)" -Level "INFO" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
        }
    }

    # Build custom categories hashtable for lookup (URL List type only)
    $customCategoriesHashtable = @{}
    foreach ($cat in $urlListCategories) {
        $customCategoriesHashtable[$cat.Name] = $cat
    }

    # Custom category policies tracking
    $customCategoryPoliciesHashtable = @{}

    #endregion Phase 1: Data Loading

    #region Phase 2: Custom URL Category Processing

    Write-LogMessage "===== Phase 2: Custom URL Category Processing =====" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    foreach ($catName in $customCategoriesHashtable.Keys) {
        $category = $customCategoriesHashtable[$catName]

        # Skip empty categories
        if ($category.Members.Count -eq 0) {
            Write-LogMessage "Skipping custom URL category '$catName': no members" -Level "WARN" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
            $stats.CustomCategoriesSkippedEmpty++
            continue
        }

        Write-LogMessage "Processing custom URL category: $catName ($($category.Members.Count) members)" -Level "DEBUG" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

        # Deduplicate entries (case-insensitive)
        $uniqueMembers = @($category.Members | Group-Object -Property { $_.ToLower() } | ForEach-Object { $_.Group[0] })
        $duplicateCount = $category.Members.Count - $uniqueMembers.Count
        if ($duplicateCount -gt 0) {
            Write-LogMessage "Removed $duplicateCount duplicate entries from category '$catName'" -Level "DEBUG" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
        }

        # Clean destinations
        $cleanedDestinations = @()
        foreach ($member in $uniqueMembers) {
            $cleaned = ConvertTo-CleanDestination -Destination $member -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
            if ($null -ne $cleaned) {
                $cleanedDestinations += $cleaned
            }
        }

        # Deduplicate after cleaning
        $preDedupeCount = $cleanedDestinations.Count
        $cleanedDestinations = @($cleanedDestinations | Group-Object -Property { $_.ToLower() } | ForEach-Object { $_.Group[0] })
        $postCleanDuplicates = $preDedupeCount - $cleanedDestinations.Count
        if ($postCleanDuplicates -gt 0) {
            Write-LogMessage "Removed $postCleanDuplicates duplicate entries after cleaning for category '$catName'" -Level "DEBUG" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
        }

        if ($cleanedDestinations.Count -eq 0) {
            Write-LogMessage "No valid destinations after cleaning for category '$catName'" -Level "WARN" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
            $stats.CustomCategoriesSkippedEmpty++
            continue
        }

        # Classify destinations
        $classifiedDestinations = @{
            'FQDN' = [System.Collections.ArrayList]::new()
            'URL'  = [System.Collections.ArrayList]::new()
        }

        foreach ($dest in $cleanedDestinations) {
            $type = Get-DestinationType -Destination $dest

            switch ($type) {
                'ipv4' {
                    Write-LogMessage "Skipping IPv4 address '$dest' in category '$catName' (not supported by EIA)" -Level "WARN" `
                        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
                    $stats.IPsSkipped++
                }
                'ipv6' {
                    Write-LogMessage "Skipping IPv6 address '$dest' in category '$catName' (not supported)" -Level "WARN" `
                        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
                    $stats.IPv6Skipped++
                }
                'URL' {
                    [void]$classifiedDestinations['URL'].Add($dest)
                    $stats.URLsClassified++
                }
                'FQDN' {
                    [void]$classifiedDestinations['FQDN'].Add($dest)
                    $stats.FQDNsClassified++
                }
            }
        }

        if ($classifiedDestinations['FQDN'].Count -eq 0 -and $classifiedDestinations['URL'].Count -eq 0) {
            Write-LogMessage "No FQDN/URL destinations remaining for category '$catName' after classification" -Level "WARN" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
            $stats.CustomCategoriesSkippedEmpty++
            continue
        }

        $policyName = "$catName-Block"
        $policyDescription = if ($category.Description) { $category.Description } else { "Converted from PANW custom URL category: $catName" }

        # Process FQDNs grouped by base domain
        if ($classifiedDestinations['FQDN'].Count -gt 0) {
            $fqdnsByBaseDomain = @{}
            foreach ($fqdn in $classifiedDestinations['FQDN']) {
                $baseDomain = Get-BaseDomain -Domain $fqdn
                if (-not $fqdnsByBaseDomain.ContainsKey($baseDomain)) {
                    $fqdnsByBaseDomain[$baseDomain] = [System.Collections.ArrayList]::new()
                }
                [void]$fqdnsByBaseDomain[$baseDomain].Add($fqdn)
            }

            foreach ($baseDomain in $fqdnsByBaseDomain.Keys) {
                $groups = Split-ByCharacterLimit -Entries @($fqdnsByBaseDomain[$baseDomain]) -MaxLength 300

                for ($i = 0; $i -lt $groups.Count; $i++) {
                    $ruleName = if ($i -eq 0) { $baseDomain } else { "$baseDomain-$($i + 1)" }

                    $policyEntry = [PSCustomObject]@{
                        PolicyName    = $policyName
                        PolicyType    = "WebContentFiltering"
                        PolicyAction  = "Block"
                        Description   = $policyDescription
                        RuleType      = "FQDN"
                        RuleDestinations = $groups[$i] -join ";"
                        RuleName      = $ruleName
                        ReviewNeeded  = "No"
                        ReviewDetails = ""
                        Provision     = "Yes"
                    }
                    [void]$policies.Add($policyEntry)
                }
            }
        }

        # Process URLs grouped by base domain
        if ($classifiedDestinations['URL'].Count -gt 0) {
            $urlsByBaseDomain = @{}
            foreach ($url in $classifiedDestinations['URL']) {
                $baseDomain = Get-BaseDomain -Domain $url
                if (-not $urlsByBaseDomain.ContainsKey($baseDomain)) {
                    $urlsByBaseDomain[$baseDomain] = [System.Collections.ArrayList]::new()
                }
                [void]$urlsByBaseDomain[$baseDomain].Add($url)
            }

            foreach ($baseDomain in $urlsByBaseDomain.Keys) {
                $groups = Split-ByCharacterLimit -Entries @($urlsByBaseDomain[$baseDomain]) -MaxLength 300

                for ($i = 0; $i -lt $groups.Count; $i++) {
                    $ruleName = if ($i -eq 0) { $baseDomain } else { "$baseDomain-$($i + 1)" }

                    $policyEntry = [PSCustomObject]@{
                        PolicyName    = $policyName
                        PolicyType    = "WebContentFiltering"
                        PolicyAction  = "Block"
                        Description   = $policyDescription
                        RuleType      = "URL"
                        RuleDestinations = $groups[$i] -join ";"
                        RuleName      = $ruleName
                        ReviewNeeded  = "No"
                        ReviewDetails = ""
                        Provision     = "Yes"
                    }
                    [void]$policies.Add($policyEntry)
                }
            }
        }

        # Track custom category policy
        $customCategoryPoliciesHashtable[$catName] = @{
            BlockPolicyName = $policyName
            AllowPolicyName = $null
            BaseName        = $catName
        }

        $stats.CustomCategoriesProcessed++
    }

    Write-LogMessage "Custom categories processed: $($stats.CustomCategoriesProcessed), skipped (empty): $($stats.CustomCategoriesSkippedEmpty), skipped (Category Match): $($stats.CustomCategoriesSkippedCatMatch)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    #endregion Phase 2: Custom URL Category Processing

    #region Phase 3: URL Filtering Profile Processing

    Write-LogMessage "===== Phase 3: URL Filtering Profile Processing =====" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    # Track custom category references per profile for Phase 4
    $profileCustomCategoryRefs = @{}

    foreach ($profileName in $allUrlFilteringProfiles.Keys) {
        $profile = $allUrlFilteringProfiles[$profileName]
        $profileCustomCategoryRefs[$profileName] = [System.Collections.ArrayList]::new()

        Write-LogMessage "Processing URL filtering profile: $profileName" -Level "DEBUG" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

        foreach ($actionName in @('allow', 'block', 'alert', 'continue', 'override')) {
            $categories = $profile.Categories[$actionName]
            if ($null -eq $categories -or $categories.Count -eq 0) { continue }

            # Separate custom URL category references from PAN-DB predefined categories
            $predefinedCategories = [System.Collections.ArrayList]::new()

            foreach ($catRef in $categories) {
                if ($customCategoriesHashtable.ContainsKey($catRef)) {
                    # Custom URL category reference - track for Phase 4
                    [void]$profileCustomCategoryRefs[$profileName].Add(@{
                        CustomCategoryName = $catRef
                        Action             = $actionName
                    })
                }
                else {
                    # PAN-DB predefined category
                    [void]$predefinedCategories.Add($catRef)
                }
            }

            # Process predefined categories - create web category policy per action
            if ($predefinedCategories.Count -gt 0) {
                $mappedGSACategories = [System.Collections.ArrayList]::new()
                $unmappedCategories = [System.Collections.ArrayList]::new()
                $partialMappings = [System.Collections.ArrayList]::new()

                foreach ($pandbCat in $predefinedCategories) {
                    $stats.PanDBCategoriesReferenced++
                    $mapping = $categoryMappingsHashtable[$pandbCat.ToLower()]

                    if ($null -eq $mapping) {
                        # Category not in mapping file
                        [void]$mappedGSACategories.Add("UNMAPPED:$pandbCat")
                        [void]$unmappedCategories.Add($pandbCat)
                        $stats.CategoriesUnmapped++
                        Write-LogMessage "PAN-DB category '$pandbCat' not found in mapping file" -Level "WARN" `
                            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
                    }
                    elseif ([string]::IsNullOrWhiteSpace($mapping.GSACategory) -or $mapping.GSACategory -eq "Unmapped") {
                        # Mapping exists but no GSA category value
                        [void]$mappedGSACategories.Add("UNMAPPED:$pandbCat")
                        [void]$unmappedCategories.Add($pandbCat)
                        $stats.CategoriesUnmapped++
                        Write-LogMessage "PAN-DB category '$pandbCat' has no GSA mapping (empty/Unmapped)" -Level "WARN" `
                            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
                    }
                    elseif ($mapping.MappingNotes -like '*Partial*') {
                        # Partial mapping - exclude from RuleDestinations, add to ReviewDetails
                        [void]$partialMappings.Add("$pandbCat -> $($mapping.GSACategory)")
                        $stats.CategoriesMappedPartial++
                        Write-LogMessage "PAN-DB category '$pandbCat' has partial mapping to '$($mapping.GSACategory)' - excluded for review" -Level "DEBUG" `
                            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
                    }
                    else {
                        # Exact mapping
                        [void]$mappedGSACategories.Add($mapping.GSACategory)
                        $stats.CategoriesMappedExact++
                    }
                }

                # Determine EIA action and review flags
                $eiaAction = switch ($actionName) {
                    'allow'    { "Allow" }
                    'block'    { "Block" }
                    'alert'    { "Allow" }
                    'continue' { "Allow" }
                    'override' { "Allow" }
                }

                $reviewNeeded = $false
                $reviewReasons = [System.Collections.ArrayList]::new()

                if ($actionName -in @('alert', 'continue', 'override')) {
                    $reviewNeeded = $true
                    [void]$reviewReasons.Add("PANW '$actionName' action requires review - mapped to Allow")
                }
                if ($partialMappings.Count -gt 0) {
                    $reviewNeeded = $true
                    [void]$reviewReasons.Add("Partial mappings require review: $($partialMappings -join '; ')")
                }
                if ($unmappedCategories.Count -gt 0) {
                    $reviewNeeded = $true
                    [void]$reviewReasons.Add("Unmapped categories: $($unmappedCategories -join ', ')")
                }

                # Build policy name with action suffix
                $actionSuffix = switch ($actionName) {
                    'allow'    { "Allow" }
                    'block'    { "Block" }
                    'alert'    { "Alert" }
                    'continue' { "Continue" }
                    'override' { "Override" }
                }

                $webCatPolicyName = "$profileName-WebCategories-$actionSuffix"

                # Only create policy if there are mapped categories or unmapped placeholders
                if ($mappedGSACategories.Count -gt 0) {
                    $policyEntry = [PSCustomObject]@{
                        PolicyName       = $webCatPolicyName
                        PolicyType       = "WebContentFiltering"
                        PolicyAction     = $eiaAction
                        Description      = if ($profile.Description) { "$($profile.Description) - $actionSuffix categories" } else { "Converted from $profileName URL filtering profile ($actionSuffix)" }
                        RuleType         = "webCategory"
                        RuleDestinations = $mappedGSACategories -join ";"
                        RuleName         = "WebCategories"
                        ReviewNeeded     = if ($reviewNeeded) { "Yes" } else { "No" }
                        ReviewDetails    = $reviewReasons -join "; "
                        Provision        = if ($reviewNeeded) { "No" } else { "Yes" }
                    }
                    [void]$policies.Add($policyEntry)
                    $stats.WebCategoryPolicies++

                    if ($reviewNeeded) { $stats.PoliciesFlaggedForReview++ }
                }
            }
        }

        # Handle custom category references - create Allow versions when needed
        foreach ($catRef in $profileCustomCategoryRefs[$profileName]) {
            $catName = $catRef.CustomCategoryName
            $action = $catRef.Action
            $policyInfo = $customCategoryPoliciesHashtable[$catName]

            if ($null -eq $policyInfo) { continue }

            if ($action -eq 'allow' -and $null -eq $policyInfo.AllowPolicyName) {
                # Create Allow version by duplicating Block policy entries
                $allowPolicyName = "$catName-Allow"
                $blockPolicies = $policies | Where-Object { $_.PolicyName -eq $policyInfo.BlockPolicyName }

                foreach ($blockPolicy in $blockPolicies) {
                    $allowPolicy = [PSCustomObject]@{
                        PolicyName       = $allowPolicyName
                        PolicyType       = $blockPolicy.PolicyType
                        PolicyAction     = "Allow"
                        Description      = $blockPolicy.Description
                        RuleType         = $blockPolicy.RuleType
                        RuleDestinations = $blockPolicy.RuleDestinations
                        RuleName         = $blockPolicy.RuleName
                        ReviewNeeded     = $blockPolicy.ReviewNeeded
                        ReviewDetails    = $blockPolicy.ReviewDetails
                        Provision        = if ($blockPolicy.ReviewNeeded -eq "Yes") { "No" } else { "Yes" }
                    }
                    [void]$policies.Add($allowPolicy)
                }

                $policyInfo.AllowPolicyName = $allowPolicyName
                Write-LogMessage "Created Allow version of custom category policy: $allowPolicyName" -Level "DEBUG" `
                    -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
            }
        }

        $stats.UrlFilteringProfilesProcessed++
    }

    Write-LogMessage "URL filtering profiles processed: $($stats.UrlFilteringProfilesProcessed)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    #endregion Phase 3: URL Filtering Profile Processing

    #region Phase 4: Security Rule Processing

    Write-LogMessage "===== Phase 4: Security Rule Processing =====" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    $policiesForAggregation = [System.Collections.ArrayList]::new()
    $applicationPoliciesCreated = @{}

    foreach ($rule in $allSecurityRules) {
        # 4.1 Filter: skip disabled rules
        if ($rule.Disabled) {
            $stats.RulesSkippedDisabled++
            Write-LogMessage "Skipping disabled rule: $($rule.Name)" -Level "DEBUG" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
            continue
        }

        # Filter: skip non-allow rules
        if ($rule.Action -ne 'allow') {
            $stats.RulesSkippedDenyDropReset++
            Write-LogMessage "Skipping rule '$($rule.Name)' with action '$($rule.Action)'" -Level "DEBUG" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
            continue
        }

        # Apply include/exclude name filter
        if (-not (Test-PolicyNameFilter -PolicyName $rule.Name -IncludePatterns $IncludePolicyName -ExcludePatterns $ExcludePolicyName)) {
            $stats.RulesSkippedFiltered++
            Write-LogMessage "Skipping rule '$($rule.Name)' (filtered by IncludePolicyName/ExcludePolicyName)" -Level "DEBUG" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
            continue
        }

        # 4.2 Resolve URL filtering profile
        $urlFilterProfileName = Resolve-UrlFilteringProfile -ProfileSettingNode $rule.ProfileSetting -ProfileGroupsHashtable $allProfileGroups

        # Check for application references
        $hasApps = ($rule.Applications.Count -gt 0 -and -not ($rule.Applications.Count -eq 1 -and $rule.Applications[0] -eq 'any'))

        # Skip if no URL filtering profile AND no application references
        if ($null -eq $urlFilterProfileName -and -not $hasApps) {
            $stats.RulesSkippedNoUrlFilterOrApps++
            Write-LogMessage "Skipping rule '$($rule.Name)': no URL filtering profile and no application references" -Level "DEBUG" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
            continue
        }

        Write-LogMessage "Processing rule: $($rule.Name) (rulebase: $($rule.RulebaseType))" -Level "DEBUG" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

        # 4.3 Extract users and groups
        $emails = [System.Collections.ArrayList]::new()
        $groups = [System.Collections.ArrayList]::new()
        $needsReview = $false
        $reviewReasons = [System.Collections.ArrayList]::new()

        foreach ($sourceUser in $rule.SourceUsers) {
            if ($sourceUser -eq 'any') {
                [void]$groups.Add("Replace_with_All_IA_Users_Group")
            }
            elseif ($sourceUser -eq 'unknown' -or $sourceUser -eq 'pre-logon') {
                Write-LogMessage "Skipping source-user '$sourceUser' in rule '$($rule.Name)'" -Level "WARN" `
                    -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
            }
            elseif ($sourceUser -match '@') {
                [void]$emails.Add($sourceUser)
            }
            elseif ($sourceUser -match '\\') {
                [void]$groups.Add($sourceUser)
                $needsReview = $true
                if ("Review source-user format" -notin $reviewReasons) {
                    [void]$reviewReasons.Add("Review source-user format")
                }
            }
            else {
                [void]$groups.Add($sourceUser)
            }
        }

        # Default assignment if no valid users/groups
        if ($emails.Count -eq 0 -and $groups.Count -eq 0) {
            [void]$groups.Add("Replace_with_All_IA_Users_Group")
        }

        # 4.4 Process application references
        $applicationPolicyNames = [System.Collections.ArrayList]::new()

        if ($hasApps) {
            $stats.RulesWithApplicationRefs++
            $unmappedApps = [System.Collections.ArrayList]::new()

            if ($hasAppMappings) {
                foreach ($appName in $rule.Applications) {
                    if ($appName -eq 'any') { continue }

                    $appMapping = $appMappingsHashtable[$appName.ToLower()]

                    if ($null -ne $appMapping -and -not [string]::IsNullOrWhiteSpace($appMapping.GSAAppName)) {
                        if (-not [string]::IsNullOrWhiteSpace($appMapping.GSAEndpoints)) {
                            # Mapped with endpoints - create FQDN policy
                            $appPolicyName = "$($appMapping.GSAAppName)-Allow"

                            if (-not $applicationPoliciesCreated.ContainsKey($appPolicyName)) {
                                # Parse endpoints
                                $endpoints = $appMapping.GSAEndpoints -split '\s*;\s*' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                                $expandedEndpoints = [System.Collections.ArrayList]::new()

                                foreach ($endpoint in $endpoints) {
                                    $cleanEndpoint = ConvertTo-CleanDestination -Destination $endpoint -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
                                    if ($null -ne $cleanEndpoint) {
                                        $epType = Get-DestinationType -Destination $cleanEndpoint
                                        if ($epType -eq 'FQDN') {
                                            # Apply dual FQDN pattern
                                            if ($cleanEndpoint -notlike '*.*.*' -or $cleanEndpoint -notlike '*`**') {
                                                [void]$expandedEndpoints.Add($cleanEndpoint)
                                                if (-not $cleanEndpoint.StartsWith('*.')) {
                                                    [void]$expandedEndpoints.Add("*.$cleanEndpoint")
                                                }
                                            }
                                            else {
                                                [void]$expandedEndpoints.Add($cleanEndpoint)
                                            }
                                        }
                                        elseif ($epType -eq 'URL') {
                                            [void]$expandedEndpoints.Add($cleanEndpoint)
                                        }
                                        elseif ($epType -eq 'ipv4' -or $epType -eq 'ipv6') {
                                            Write-LogMessage "Skipping IP endpoint '$cleanEndpoint' for app '$appName'" -Level "WARN" `
                                                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
                                        }
                                    }
                                }

                                # Deduplicate
                                $expandedEndpoints = [System.Collections.ArrayList]@($expandedEndpoints | Group-Object -Property { $_.ToLower() } | ForEach-Object { $_.Group[0] })

                                if ($expandedEndpoints.Count -gt 0) {
                                    # Group by base domain and split
                                    $epByBaseDomain = @{}
                                    foreach ($ep in $expandedEndpoints) {
                                        $bd = Get-BaseDomain -Domain $ep
                                        if (-not $epByBaseDomain.ContainsKey($bd)) {
                                            $epByBaseDomain[$bd] = [System.Collections.ArrayList]::new()
                                        }
                                        [void]$epByBaseDomain[$bd].Add($ep)
                                    }

                                    foreach ($bd in $epByBaseDomain.Keys) {
                                        $epGroups = Split-ByCharacterLimit -Entries @($epByBaseDomain[$bd]) -MaxLength 300
                                        for ($gi = 0; $gi -lt $epGroups.Count; $gi++) {
                                            $epRuleName = if ($gi -eq 0) { $bd } else { "$bd-$($gi + 1)" }

                                            $appPolicyEntry = [PSCustomObject]@{
                                                PolicyName       = $appPolicyName
                                                PolicyType       = "WebContentFiltering"
                                                PolicyAction     = "Allow"
                                                Description      = "Application endpoints for $($appMapping.GSAAppName)"
                                                RuleType         = "FQDN"
                                                RuleDestinations = $epGroups[$gi] -join ";"
                                                RuleName         = $epRuleName
                                                ReviewNeeded     = "No"
                                                ReviewDetails    = ""
                                                Provision        = "Yes"
                                            }
                                            [void]$policies.Add($appPolicyEntry)
                                        }
                                    }
                                }

                                $applicationPoliciesCreated[$appPolicyName] = $true
                                $stats.AppsMappedWithEndpoints++
                                $stats.ApplicationPolicies++
                            }

                            [void]$applicationPolicyNames.Add($appPolicyName)
                        }
                        else {
                            # Mapped without endpoints - create placeholder
                            $appPolicyName = "$($appMapping.GSAAppName)-Allow"

                            if (-not $applicationPoliciesCreated.ContainsKey($appPolicyName)) {
                                $appPolicyEntry = [PSCustomObject]@{
                                    PolicyName       = $appPolicyName
                                    PolicyType       = "WebContentFiltering"
                                    PolicyAction     = "Allow"
                                    Description      = "Application endpoints for $($appMapping.GSAAppName)"
                                    RuleType         = "FQDN"
                                    RuleDestinations = "PLACEHOLDER_$($appMapping.GSAAppName)"
                                    RuleName         = "placeholder"
                                    ReviewNeeded     = "Yes"
                                    ReviewDetails    = "Application '$($appMapping.GSAAppName)' mapped but no endpoints available"
                                    Provision        = "No"
                                }
                                [void]$policies.Add($appPolicyEntry)
                                $applicationPoliciesCreated[$appPolicyName] = $true
                                $stats.AppsMappedWithoutEndpoints++
                                $stats.ApplicationPolicies++
                                $stats.PoliciesFlaggedForReview++
                            }

                            [void]$applicationPolicyNames.Add($appPolicyName)
                        }
                    }
                    else {
                        # Unmapped app
                        [void]$unmappedApps.Add($appName)
                        $stats.AppsUnmapped++
                        Write-LogMessage "Unmapped application '$appName' in rule '$($rule.Name)'" -Level "WARN" `
                            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
                    }
                }
            }
            else {
                # No app mappings file
                $filteredApps = @($rule.Applications | Where-Object { $_ -ne 'any' })
                $unmappedApps = [System.Collections.ArrayList]::new()
                foreach ($fa in $filteredApps) { [void]$unmappedApps.Add($fa) }
                Write-LogMessage "Applications referenced in rule '$($rule.Name)' (no mapping file): $($unmappedApps -join ', ')" -Level "INFO" `
                    -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
            }

            if ($unmappedApps.Count -gt 0) {
                $needsReview = $true
                if ($hasAppMappings) {
                    [void]$reviewReasons.Add("Unmapped applications: $($unmappedApps -join ', ')")
                }
                else {
                    [void]$reviewReasons.Add("Applications referenced (no mapping file): $($unmappedApps -join ', ')")
                }
            }
        }

        # 4.5 Build policy links
        $policyLinks = [System.Collections.ArrayList]::new()

        if ($null -ne $urlFilterProfileName -and $allUrlFilteringProfiles.ContainsKey($urlFilterProfileName)) {
            $resolvedProfile = $allUrlFilteringProfiles[$urlFilterProfileName]

            # Add web category policy links
            foreach ($actionName in @('allow', 'block', 'alert', 'continue', 'override')) {
                $actionSuffix = switch ($actionName) {
                    'allow'    { "Allow" }
                    'block'    { "Block" }
                    'alert'    { "Alert" }
                    'continue' { "Continue" }
                    'override' { "Override" }
                }

                $webCatPolicyName = "$urlFilterProfileName-WebCategories-$actionSuffix"
                # Check if this policy actually exists
                $policyExists = $policies | Where-Object { $_.PolicyName -eq $webCatPolicyName } | Select-Object -First 1
                if ($null -ne $policyExists) {
                    [void]$policyLinks.Add($webCatPolicyName)
                }
            }

            # Add custom category policy links
            if ($profileCustomCategoryRefs.ContainsKey($urlFilterProfileName)) {
                foreach ($catRef in $profileCustomCategoryRefs[$urlFilterProfileName]) {
                    $catName = $catRef.CustomCategoryName
                    $catAction = $catRef.Action
                    $policyInfo = $customCategoryPoliciesHashtable[$catName]

                    if ($null -eq $policyInfo) { continue }

                    if ($catAction -eq 'allow') {
                        if ($null -ne $policyInfo.AllowPolicyName) {
                            [void]$policyLinks.Add($policyInfo.AllowPolicyName)
                        }
                    }
                    elseif ($catAction -in @('block', 'alert', 'continue', 'override')) {
                        [void]$policyLinks.Add($policyInfo.BlockPolicyName)
                    }
                }
            }
        }

        # Add application policy links
        foreach ($appPolicyName in $applicationPolicyNames) {
            [void]$policyLinks.Add($appPolicyName)
        }

        # Skip rule if no policy links were collected
        if ($policyLinks.Count -eq 0) {
            Write-LogMessage "No policy links generated for rule '$($rule.Name)' - skipping" -Level "WARN" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
            $stats.RulesSkippedNoUrlFilterOrApps++
            continue
        }

        # 4.6 Collect for aggregation
        $policyInfo = @{
            RuleName      = $rule.Name
            Emails        = [string[]]$emails.ToArray()
            Groups        = [string[]]$groups.ToArray()
            PolicyLinks   = [string[]]$policyLinks.ToArray()
            NeedsReview   = $needsReview
            ReviewReasons = [string[]]$reviewReasons.ToArray()
        }

        [void]$policiesForAggregation.Add($policyInfo)
        $stats.RulesProcessed++
    }

    Write-LogMessage "Rules processed: $($stats.RulesProcessed), disabled: $($stats.RulesSkippedDisabled), deny/drop/reset: $($stats.RulesSkippedDenyDropReset), no URL filter/apps: $($stats.RulesSkippedNoUrlFilterOrApps), filtered: $($stats.RulesSkippedFiltered)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    # Check if any rules were processed
    if ($policiesForAggregation.Count -eq 0) {
        $errorMsg = "No processable rules found (no enabled allow rules with URL filtering profile or application references)"
        Write-LogMessage $errorMsg -Level "ERROR" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
        throw $errorMsg
    }

    # 4.7 Aggregate by user/group assignment
    Write-LogMessage "Aggregating policies by user/group assignment..." -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    $allUsersPolicies = [System.Collections.ArrayList]::new()
    $userGroupPolicies = @{}

    foreach ($policyInfo in $policiesForAggregation) {
        if ($policyInfo.Groups -contains "Replace_with_All_IA_Users_Group") {
            [void]$allUsersPolicies.Add($policyInfo)
            continue
        }

        $combinedKey = ConvertTo-UserGroupKey -Emails $policyInfo.Emails -Groups $policyInfo.Groups

        if (-not $userGroupPolicies.ContainsKey($combinedKey)) {
            $userGroupPolicies[$combinedKey] = [System.Collections.ArrayList]::new()
        }

        [void]$userGroupPolicies[$combinedKey].Add($policyInfo)
    }

    Write-LogMessage "Found $($allUsersPolicies.Count) rules for 'All users'" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "Found $($userGroupPolicies.Count) unique user/group assignment sets" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    # Create Override security profiles for specific user/group sets
    $profileIndex = 1

    foreach ($key in $userGroupPolicies.Keys) {
        $policiesGroup = $userGroupPolicies[$key]

        $aggregatedLinks = [System.Collections.ArrayList]::new()
        $ruleNames = [System.Collections.ArrayList]::new()
        $aggregatedReviewReasons = [System.Collections.ArrayList]::new()
        $profileNeedsReview = $false

        $profileEmails = $policiesGroup[0].Emails
        $profileGroups = $policiesGroup[0].Groups

        foreach ($pInfo in $policiesGroup) {
            foreach ($link in $pInfo.PolicyLinks) {
                [void]$aggregatedLinks.Add($link)
            }
            [void]$ruleNames.Add($pInfo.RuleName)
            if ($pInfo.NeedsReview) {
                $profileNeedsReview = $true
                foreach ($reason in $pInfo.ReviewReasons) {
                    if ($reason -notin $aggregatedReviewReasons) {
                        [void]$aggregatedReviewReasons.Add($reason)
                    }
                }
            }
        }

        # Deduplicate policy links
        $uniqueLinks = @($aggregatedLinks | Select-Object -Unique)

        # Order: Allow policies first (alphabetically), then Block policies (alphabetically)
        $allowLinks = @($uniqueLinks | Where-Object { $_ -like "*-Allow" } | Sort-Object)
        $blockLinks = @($uniqueLinks | Where-Object { $_ -like "*-Block" } | Sort-Object)
        $otherLinks = @($uniqueLinks | Where-Object { $_ -notlike "*-Allow" -and $_ -notlike "*-Block" } | Sort-Object)
        $orderedLinks = $allowLinks + $blockLinks + $otherLinks

        $securityProfile = [PSCustomObject]@{
            SecurityProfileName = "SecurityProfile-{0:D3}" -f $profileIndex
            Priority            = 1000 + (($profileIndex - 1) * 100)
            SecurityProfileLinks = ($orderedLinks -join ';')
            CADisplayName       = "SecurityProfile-{0:D3}" -f $profileIndex
            EntraUsers          = ($profileEmails -join ';')
            EntraGroups         = ($profileGroups -join ';')
            Description         = "Aggregated from $($policiesGroup.Count) security rules"
            Provision           = "Yes"
            Notes               = ($ruleNames -join ', ')
        }
        [void]$securityProfiles.Add($securityProfile)
        $stats.OverrideProfileCount++
        $stats.RulesAggregated += $policiesGroup.Count

        $profileIndex++
    }

    # Create Default security profile for All-Users
    if ($allUsersPolicies.Count -gt 0) {
        $allLinks = [System.Collections.ArrayList]::new()
        $allRuleNames = [System.Collections.ArrayList]::new()

        foreach ($pInfo in $allUsersPolicies) {
            foreach ($link in $pInfo.PolicyLinks) {
                [void]$allLinks.Add($link)
            }
            [void]$allRuleNames.Add($pInfo.RuleName)
        }

        $uniqueLinks = @($allLinks | Select-Object -Unique)
        $allowLinks = @($uniqueLinks | Where-Object { $_ -like "*-Allow" } | Sort-Object)
        $blockLinks = @($uniqueLinks | Where-Object { $_ -like "*-Block" } | Sort-Object)
        $otherLinks = @($uniqueLinks | Where-Object { $_ -notlike "*-Allow" -and $_ -notlike "*-Block" } | Sort-Object)
        $orderedLinks = $allowLinks + $blockLinks + $otherLinks

        $securityProfile = [PSCustomObject]@{
            SecurityProfileName  = "SecurityProfile-All-Users"
            Priority             = 50000
            SecurityProfileLinks = ($orderedLinks -join ';')
            CADisplayName        = "SecurityProfile-All-Users"
            EntraUsers           = ""
            EntraGroups          = "Replace_with_All_IA_Users_Group"
            Description          = "Aggregated from $($allUsersPolicies.Count) security rules"
            Provision            = "Yes"
            Notes                = ($allRuleNames -join ', ')
        }
        [void]$securityProfiles.Add($securityProfile)
        $stats.DefaultProfileCount++
        $stats.RulesAggregated += $allUsersPolicies.Count
    }

    $stats.SecurityProfilesCreated = $securityProfiles.Count
    Write-LogMessage "Created $($stats.SecurityProfilesCreated) security profiles ($($stats.OverrideProfileCount) override, $($stats.DefaultProfileCount) default)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    # 4.8 Priority conflict resolution
    Write-LogMessage "Resolving priority conflicts..." -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    $priorityTracker = @{}
    foreach ($secProfile in $securityProfiles) {
        while ($priorityTracker.ContainsKey($secProfile.Priority)) {
            Write-LogMessage "Priority conflict at $($secProfile.Priority) for '$($secProfile.SecurityProfileName)', incrementing" -Level "DEBUG" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
            $secProfile.Priority++
            $stats.PriorityConflictsResolved++
        }
        $priorityTracker[$secProfile.Priority] = $secProfile.SecurityProfileName
    }

    # 4.9 Cleanup unreferenced policies
    Write-LogMessage "Cleaning up unreferenced policies..." -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    $referencedPolicies = @{}
    foreach ($secProfile in $securityProfiles) {
        $policyNames = $secProfile.SecurityProfileLinks -split ';'
        foreach ($pName in $policyNames) {
            $referencedPolicies[$pName] = $true
        }
    }

    $originalPolicyCount = $policies.Count
    $policies = [System.Collections.ArrayList]@($policies | Where-Object {
        $referencedPolicies.ContainsKey($_.PolicyName)
    })

    $removedPolicies = $originalPolicyCount - $policies.Count
    $stats.UnreferencedPoliciesRemoved = $removedPolicies

    if ($removedPolicies -gt 0) {
        Write-LogMessage "Removed $removedPolicies unreferenced policy rows" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    }
    else {
        Write-LogMessage "No unreferenced policies to remove" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    }

    $stats.PoliciesCreated = ($policies | Select-Object -ExpandProperty PolicyName -Unique).Count

    #endregion Phase 4: Security Rule Processing

    #region Phase 5: Export and Summary

    Write-LogMessage "===== Phase 5: Export and Summary =====" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    # 5.1 Export Policies CSV
    try {
        $policiesCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_Policies.csv"
        $policies | Export-Csv -Path $policiesCsvPath -NoTypeInformation -Encoding utf8BOM
        Write-LogMessage "Exported $($policies.Count) policy rows to: $policiesCsvPath" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    }
    catch {
        $errorMsg = "Fatal error exporting policies CSV: $_"
        Write-LogMessage $errorMsg -Level "ERROR" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
        throw $errorMsg
    }

    # 5.2 Export Security Profiles CSV with priority suffixes
    try {
        $spCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_SecurityProfiles.csv"

        $securityProfilesForExport = $securityProfiles | ForEach-Object {
            $profile = $_ | Select-Object *
            $spLinks = $_.SecurityProfileLinks -split ';'
            $formattedLinks = [System.Collections.ArrayList]::new()
            $linkPriority = 100
            foreach ($link in $spLinks) {
                if (-not [string]::IsNullOrWhiteSpace($link)) {
                    [void]$formattedLinks.Add("${link}:${linkPriority}")
                    $linkPriority += 100
                }
            }
            $profile.SecurityProfileLinks = $formattedLinks -join ';'
            $profile
        }

        $securityProfilesForExport | Export-Csv -Path $spCsvPath -NoTypeInformation -Encoding utf8BOM
        Write-LogMessage "Exported $($securityProfiles.Count) security profiles to: $spCsvPath" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    }
    catch {
        $errorMsg = "Fatal error exporting security profiles CSV: $_"
        Write-LogMessage $errorMsg -Level "ERROR" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
        throw $errorMsg
    }

    # 5.3 Generate Summary Statistics
    Write-LogMessage "" -Level "INFO" -LogPath $script:logPath
    Write-LogMessage "===== CONVERSION SUMMARY =====" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "Input: $PanoramaXmlPath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "Device Groups processed: $($stats.DeviceGroupsProcessed)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "" -Level "INFO" -LogPath $script:logPath
    Write-LogMessage "Security rules loaded: $($stats.SecurityRulesLoaded)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Pre-rulebase rules: $($stats.PreRulebaseRules)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Post-rulebase rules: $($stats.PostRulebaseRules)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "Rules processed (enabled + allow + URL filter or apps): $($stats.RulesProcessed)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "Rules skipped (disabled): $($stats.RulesSkippedDisabled)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "Rules skipped (deny/drop/reset): $($stats.RulesSkippedDenyDropReset)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "Rules skipped (no URL filter profile and no apps): $($stats.RulesSkippedNoUrlFilterOrApps)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "Rules skipped (filtered by IncludePolicyName/ExcludePolicyName): $($stats.RulesSkippedFiltered)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "Rules with application references: $($stats.RulesWithApplicationRefs)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Applications mapped (with endpoints): $($stats.AppsMappedWithEndpoints)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Applications mapped (without endpoints): $($stats.AppsMappedWithoutEndpoints)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Applications unmapped: $($stats.AppsUnmapped)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "" -Level "INFO" -LogPath $script:logPath
    Write-LogMessage "URL Filtering Profiles processed: $($stats.UrlFilteringProfilesProcessed)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "Custom URL Categories processed: $($stats.CustomCategoriesProcessed)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Categories skipped (Category Match type): $($stats.CustomCategoriesSkippedCatMatch)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Categories skipped (empty): $($stats.CustomCategoriesSkippedEmpty)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "PAN-DB categories referenced: $($stats.PanDBCategoriesReferenced)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Mapped to GSA (exact): $($stats.CategoriesMappedExact)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Partial mappings (excluded, review needed): $($stats.CategoriesMappedPartial)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Unmapped: $($stats.CategoriesUnmapped)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "" -Level "INFO" -LogPath $script:logPath
    Write-LogMessage "Destinations classified:" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  FQDNs: $($stats.FQDNsClassified)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  URLs: $($stats.URLsClassified)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Skipped (IP addresses - not supported by EIA): $($stats.IPsSkipped)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Skipped (IPv6/invalid): $($stats.IPv6Skipped)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "" -Level "INFO" -LogPath $script:logPath
    Write-LogMessage "Policies created: $($stats.PoliciesCreated)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Custom category policies: $($stats.CustomCategoryPolicies)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Web category policies: $($stats.WebCategoryPolicies)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Application policies: $($stats.ApplicationPolicies)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Policies flagged for review: $($stats.PoliciesFlaggedForReview)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "Security profiles created: $($stats.SecurityProfilesCreated)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Default profile (All-Users): $($stats.DefaultProfileCount)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Override profiles (specific user/group): $($stats.OverrideProfileCount)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Rules aggregated: $($stats.RulesAggregated)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "Priority conflicts resolved: $($stats.PriorityConflictsResolved)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "Unreferenced policy rows removed: $($stats.UnreferencedPoliciesRemoved)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "" -Level "INFO" -LogPath $script:logPath
    Write-LogMessage "Output files:" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Policies: $policiesCsvPath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Security Profiles: $spCsvPath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "  Log File: $($script:logPath)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging
    Write-LogMessage "" -Level "INFO" -LogPath $script:logPath
    Write-LogMessage "===== Convert-PANW2EIA Completed Successfully =====" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:EnableDebugLogging

    #endregion Phase 5: Export and Summary

    # Send usage telemetry
    Send-UsageTelemetry -EventName 'Convert-PANW2EIA' `
        -Properties @{
            EnableDebugLogging = $EnableDebugLogging.ToString()
            HasAppMappings     = $hasAppMappings.ToString()
            DeviceGroupFilter  = if ($DeviceGroupName) { "Yes" } else { "No" }
        } `
        -Metrics @{
            SecurityRulesLoaded          = $stats.SecurityRulesLoaded
            RulesProcessed               = $stats.RulesProcessed
            RulesSkippedDisabled         = $stats.RulesSkippedDisabled
            RulesSkippedDenyDropReset    = $stats.RulesSkippedDenyDropReset
            RulesWithApplicationRefs     = $stats.RulesWithApplicationRefs
            UrlFilteringProfilesProcessed = $stats.UrlFilteringProfilesProcessed
            CustomCategoriesProcessed    = $stats.CustomCategoriesProcessed
            PanDBCategoriesReferenced    = $stats.PanDBCategoriesReferenced
            CategoriesMappedExact        = $stats.CategoriesMappedExact
            CategoriesMappedPartial      = $stats.CategoriesMappedPartial
            CategoriesUnmapped           = $stats.CategoriesUnmapped
            FQDNsClassified              = $stats.FQDNsClassified
            URLsClassified               = $stats.URLsClassified
            IPsSkipped                   = $stats.IPsSkipped
            PoliciesCreated              = $stats.PoliciesCreated
            SecurityProfilesCreated      = $stats.SecurityProfilesCreated
            UnreferencedPoliciesRemoved  = $stats.UnreferencedPoliciesRemoved
            DeviceGroupsProcessed        = $stats.DeviceGroupsProcessed
        }
}
