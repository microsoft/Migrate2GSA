function Convert-PANW2EIA-OLD {
    <#
    .SYNOPSIS
        Converts Palo Alto Networks (PANW) Panorama configuration to Microsoft Entra Internet Access (EIA) format.

    .DESCRIPTION
        This function processes Palo Alto Panorama XML exports containing security rules, URL filtering profiles,
        custom URL categories, and predefined PAN-DB category actions to generate CSV files ready for import
        into Microsoft Entra Internet Access (EIA) via Start-EntraInternetAccessProvisioning.

        The conversion process includes:
        - Parsing Panorama XML with shared and device-group configurations
        - Transforming PANW URL filtering profiles to EIA web content filtering policies
        - Converting PANW custom URL categories to EIA web content filtering policies (FQDN/URL rules)
        - Mapping PAN-DB predefined web categories to GSA (Global Secure Access) web categories
        - Converting PANW security rules (with URL filtering profile references) to EIA security profiles
        - Flagging application-based rules for manual review (no direct EIA equivalent)
        - Generating import-ready CSV files for EIA configuration

    .PARAMETER PanoramaXmlPath
        Path to the Panorama XML configuration export file.

    .PARAMETER CategoryMappingsPath
        Path to the PANW to EIA category mappings CSV file.
        Default: PANW2EIA-CategoryMappings.csv in current directory

    .PARAMETER DeviceGroupName
        Filter to a specific device-group name. If not specified, all device-groups are processed.

    .PARAMETER OutputBasePath
        Base directory for output CSV files and log file.
        Default: Current directory

    .PARAMETER EnableDebugLogging
        Enable verbose debug logging for detailed processing information.

    .EXAMPLE
        Convert-PANW2EIA -PanoramaXmlPath "C:\Exports\panorama.xml"

        Converts Panorama configuration using default category mappings in the current directory.

    .EXAMPLE
        Convert-PANW2EIA -PanoramaXmlPath "C:\Exports\panorama.xml" -DeviceGroupName "DG-Corporate" -OutputBasePath "C:\Output"

        Converts only the DG-Corporate device-group and saves output to C:\Output.

    .EXAMPLE
        Convert-PANW2EIA -PanoramaXmlPath "C:\Exports\panorama.xml" -EnableDebugLogging

        Converts Panorama configuration with detailed debug logging enabled.

    .NOTES
        Author: Wendy Badilla
        Version: 1.0
        Date: 2026-03-02

        Requirements:
        - Panorama XML configuration export
        - PANW to EIA category mappings CSV file

        Known Limitations:
        - 300-character limit per Destinations field (except webCategory type)
        - IPv6 addresses not supported
        - CIDR ranges not supported for IP addresses
        - Port numbers not supported
        - Application filtering has no direct EIA equivalent (flagged for review)
        - Category Match type custom URL categories are not processed
    #>

    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Path to Panorama XML configuration export")]
        [ValidateScript({
            if (Test-Path $_) {
                if ($_ -match '\.xml$') { return $true }
                else { throw "File must have .xml extension: $_" }
            }
            else { throw "File not found: $_" }
        })]
        [string]$PanoramaXmlPath,

        [Parameter(HelpMessage = "Path to PANW to EIA category mappings CSV file")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$CategoryMappingsPath = (Join-Path $PWD "PANW2EIA-CategoryMappings.csv"),

        [Parameter(HelpMessage = "Filter to specific device-group name")]
        [string]$DeviceGroupName,

        [Parameter(HelpMessage = "Base directory for output files")]
        [ValidateScript({
            if (Test-Path $_ -PathType Container) { return $true }
            else { throw "Directory not found: $_" }
        })]
        [string]$OutputBasePath = $PWD,

        [Parameter(HelpMessage = "Enable verbose debug logging")]
        [switch]$EnableDebugLogging
    )

    Set-StrictMode -Version Latest

    #region Helper Functions

    function Import-PanoramaXml {
        <#
        .SYNOPSIS
            Load and validate a Panorama XML export, returning the parsed XML document.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [string]$Path
        )

        try {
            Write-LogMessage "Loading Panorama XML from: $Path" -Level "INFO" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:debugEnabled
            $xmlContent = Get-Content -Path $Path -Raw -ErrorAction Stop
            $xmlDoc = [xml]$xmlContent
        }
        catch {
            Write-LogMessage "Failed to parse XML file: $_" -Level "ERROR" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:debugEnabled
            throw "Failed to parse Panorama XML file: $Path - $_"
        }

        # Validate root element
        if ($null -eq $xmlDoc.config) {
            # Check if config is nested
            $configNode = $xmlDoc.SelectSingleNode("//config")
            if ($null -eq $configNode) {
                Write-LogMessage "Invalid Panorama XML: no <config> element found" -Level "ERROR" `
                    -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:debugEnabled
                throw "Invalid Panorama XML export: no <config> element found in $Path"
            }
        }

        Write-LogMessage "Successfully parsed Panorama XML" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:debugEnabled

        return $xmlDoc
    }

    function Get-PANWCustomUrlCategories {
        <#
        .SYNOPSIS
            Extract custom URL categories from shared and device-group scope.
        .DESCRIPTION
            Returns a hashtable of category name to category data (members array, description, type).
            Device-group entries override shared entries with the same name.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [xml]$XmlDoc,
            [Parameter()]
            [string[]]$DeviceGroups,
            [Parameter()]
            [string]$Scope = "all"
        )

        $categories = @{}

        # Collect from shared scope
        $sharedCategories = $XmlDoc.SelectNodes("/config/shared/profiles/custom-url-category/entry")
        if ($null -eq $sharedCategories -or $sharedCategories.Count -eq 0) {
            # Fallback: check directly under shared (some PAN-OS versions)
            $sharedCategories = $XmlDoc.SelectNodes("/config/shared/custom-url-category/entry")
        }
        if ($null -ne $sharedCategories) {
            foreach ($entry in $sharedCategories) {
                $name = $entry.GetAttribute("name")
                $type = if ($entry.type) { $entry.type } else { "URL List" }
                $description = if ($entry.description) { $entry.description } else { "" }
                $members = @()

                if ($type -eq "URL List" -and $null -ne $entry.list) {
                    $memberNodes = $entry.SelectNodes("list/member")
                    if ($null -ne $memberNodes) {
                        foreach ($member in $memberNodes) {
                            $members += $member.InnerText
                        }
                    }
                }

                $categories[$name] = @{
                    Name        = $name
                    Type        = $type
                    Description = $description
                    Members     = $members
                    Source      = "shared"
                }

                Write-LogMessage "Found shared custom URL category: $name (type: $type, members: $($members.Count))" -Level "DEBUG" `
                    -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:debugEnabled
            }
        }

        # Collect from each device-group scope (overrides shared)
        foreach ($dgName in $DeviceGroups) {
            $dgCategories = $XmlDoc.SelectNodes("/config/devices/entry/device-group/entry[@name='$dgName']/profiles/custom-url-category/entry")
            if ($null -eq $dgCategories -or $dgCategories.Count -eq 0) {
                # Fallback: check directly under device-group (some PAN-OS versions)
                $dgCategories = $XmlDoc.SelectNodes("/config/devices/entry/device-group/entry[@name='$dgName']/custom-url-category/entry")
            }
            if ($null -ne $dgCategories) {
                foreach ($entry in $dgCategories) {
                    $name = $entry.GetAttribute("name")
                    $type = if ($entry.type) { $entry.type } else { "URL List" }
                    $description = if ($entry.description) { $entry.description } else { "" }
                    $members = @()

                    if ($type -eq "URL List" -and $null -ne $entry.list) {
                        $memberNodes = $entry.SelectNodes("list/member")
                        if ($null -ne $memberNodes) {
                            foreach ($member in $memberNodes) {
                                $members += $member.InnerText
                            }
                        }
                    }

                    if ($categories.ContainsKey($name)) {
                        Write-LogMessage "Device-group '$dgName' overrides shared custom URL category: $name" -Level "DEBUG" `
                            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:debugEnabled
                    }

                    $categories[$name] = @{
                        Name        = $name
                        Type        = $type
                        Description = $description
                        Members     = $members
                        Source      = "device-group:$dgName"
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
        .DESCRIPTION
            Returns a hashtable of profile name to profile data (categories per action).
        #>
        param(
            [Parameter(Mandatory = $true)]
            [xml]$XmlDoc,
            [Parameter()]
            [string[]]$DeviceGroups
        )

        $profiles = @{}
        $actionNames = @('allow', 'block', 'alert', 'continue', 'override')

        # Collect from shared scope
        $sharedProfiles = $XmlDoc.SelectNodes("/config/shared/profiles/url-filtering/entry")
        if ($null -ne $sharedProfiles) {
            foreach ($entry in $sharedProfiles) {
                $name = $entry.GetAttribute("name")
                $description = if ($entry.description) { $entry.description } else { "" }
                $categoryActions = @{}

                foreach ($action in $actionNames) {
                    $categoryActions[$action] = @()
                    $actionNode = $entry.SelectSingleNode($action)
                    if ($null -ne $actionNode) {
                        $memberNodes = $actionNode.SelectNodes("member")
                        if ($null -ne $memberNodes) {
                            foreach ($member in $memberNodes) {
                                $categoryActions[$action] += $member.InnerText
                            }
                        }
                    }
                }

                $profiles[$name] = @{
                    Name            = $name
                    Description     = $description
                    CategoryActions = $categoryActions
                    Source          = "shared"
                }

                Write-LogMessage "Found shared URL filtering profile: $name" -Level "DEBUG" `
                    -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:debugEnabled
            }
        }

        # Collect from each device-group scope (overrides shared)
        foreach ($dgName in $DeviceGroups) {
            $dgProfiles = $XmlDoc.SelectNodes("/config/devices/entry/device-group/entry[@name='$dgName']/profiles/url-filtering/entry")
            if ($null -ne $dgProfiles) {
                foreach ($entry in $dgProfiles) {
                    $name = $entry.GetAttribute("name")
                    $description = if ($entry.description) { $entry.description } else { "" }
                    $categoryActions = @{}

                    foreach ($action in $actionNames) {
                        $categoryActions[$action] = @()
                        $actionNode = $entry.SelectSingleNode($action)
                        if ($null -ne $actionNode) {
                            $memberNodes = $actionNode.SelectNodes("member")
                            if ($null -ne $memberNodes) {
                                foreach ($member in $memberNodes) {
                                    $categoryActions[$action] += $member.InnerText
                                }
                            }
                        }
                    }

                    if ($profiles.ContainsKey($name)) {
                        Write-LogMessage "Device-group '$dgName' overrides shared URL filtering profile: $name" -Level "DEBUG" `
                            -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:debugEnabled
                    }

                    $profiles[$name] = @{
                        Name            = $name
                        Description     = $description
                        CategoryActions = $categoryActions
                        Source          = "device-group:$dgName"
                    }
                }
            }
        }

        return $profiles
    }

    function Get-PANWProfileGroups {
        <#
        .SYNOPSIS
            Build profile group to URL filtering profile lookup table.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [xml]$XmlDoc,
            [Parameter()]
            [string[]]$DeviceGroups
        )

        $profileGroups = @{}

        # Collect from shared scope
        $sharedGroups = $XmlDoc.SelectNodes("/config/shared/profile-group/entry")
        if ($null -ne $sharedGroups) {
            foreach ($entry in $sharedGroups) {
                $name = $entry.GetAttribute("name")
                $urlFilterMember = $entry.SelectSingleNode("url-filtering/member")
                if ($null -ne $urlFilterMember) {
                    $profileGroups[$name] = $urlFilterMember.InnerText
                    Write-LogMessage "Found shared profile group: $name -> $($urlFilterMember.InnerText)" -Level "DEBUG" `
                        -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:debugEnabled
                }
            }
        }

        # Collect from each device-group scope (overrides shared)
        foreach ($dgName in $DeviceGroups) {
            $dgGroups = $XmlDoc.SelectNodes("/config/devices/entry/device-group/entry[@name='$dgName']/profile-group/entry")
            if ($null -ne $dgGroups) {
                foreach ($entry in $dgGroups) {
                    $name = $entry.GetAttribute("name")
                    $urlFilterMember = $entry.SelectSingleNode("url-filtering/member")
                    if ($null -ne $urlFilterMember) {
                        if ($profileGroups.ContainsKey($name)) {
                            Write-LogMessage "Device-group '$dgName' overrides shared profile group: $name" -Level "DEBUG" `
                                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:debugEnabled
                        }
                        $profileGroups[$name] = $urlFilterMember.InnerText
                    }
                }
            }
        }

        return $profileGroups
    }

    function Get-PANWSecurityRules {
        <#
        .SYNOPSIS
            Extract security rules from pre-rulebase and post-rulebase, maintaining order.
        .DESCRIPTION
            Returns an array of rule objects with properties for processing.
            Pre-rulebase rules are processed first, then post-rulebase.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [xml]$XmlDoc,
            [Parameter()]
            [string[]]$DeviceGroups
        )

        $rules = @()
        $orderCounter = 1

        foreach ($dgName in $DeviceGroups) {
            # Process pre-rulebase first
            foreach ($rulebaseType in @('pre-rulebase', 'post-rulebase')) {
                $ruleNodes = $XmlDoc.SelectNodes("/config/devices/entry/device-group/entry[@name='$dgName']/$rulebaseType/security/rules/entry")
                if ($null -ne $ruleNodes) {
                    foreach ($entry in $ruleNodes) {
                        $name = $entry.GetAttribute("name")
                        $action = if ($entry.action) { $entry.action } else { "deny" }
                        $disabled = if ($entry.disabled) { $entry.disabled } else { "no" }
                        $description = if ($entry.description) { $entry.description } else { "" }

                        # Extract source users
                        $sourceUsers = @()
                        $sourceUserNodes = $entry.SelectNodes("source-user/member")
                        if ($null -ne $sourceUserNodes) {
                            foreach ($member in $sourceUserNodes) {
                                $sourceUsers += $member.InnerText
                            }
                        }

                        # Extract applications
                        $applications = @()
                        $appNodes = $entry.SelectNodes("application/member")
                        if ($null -ne $appNodes) {
                            foreach ($member in $appNodes) {
                                $applications += $member.InnerText
                            }
                        }

                        # Extract profile setting
                        $profileSetting = $entry.SelectSingleNode("profile-setting")

                        $rules += [PSCustomObject]@{
                            Name            = $name
                            Action          = $action
                            Disabled        = $disabled
                            SourceUsers     = $sourceUsers
                            Applications    = $applications
                            ProfileSetting  = $profileSetting
                            Description     = $description
                            RulebaseType    = $rulebaseType
                            DeviceGroup     = $dgName
                            Order           = $orderCounter
                        }

                        $orderCounter++
                    }
                }
            }
        }

        return $rules
    }

    function Resolve-UrlFilteringProfile {
        <#
        .SYNOPSIS
            Given a security rule's profile-setting XML node, resolve to the URL filtering profile name.
        #>
        param(
            [Parameter()]
            [System.Xml.XmlNode]$ProfileSettingNode,
            [Parameter(Mandatory = $true)]
            [hashtable]$ProfileGroupsLookup
        )

        if ($null -eq $ProfileSettingNode) {
            return $null
        }

        # Check for group reference
        $groupMember = $ProfileSettingNode.SelectSingleNode("group/member")
        if ($null -ne $groupMember) {
            $groupName = $groupMember.InnerText
            if ($ProfileGroupsLookup.ContainsKey($groupName)) {
                $profileName = $ProfileGroupsLookup[$groupName]
                Write-LogMessage "Resolved profile group '$groupName' to URL filtering profile '$profileName'" -Level "DEBUG" `
                    -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:debugEnabled
                return $profileName
            }
            else {
                Write-LogMessage "Profile group '$groupName' not found in lookup table" -Level "WARN" `
                    -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:debugEnabled
                return $null
            }
        }

        # Check for direct profile reference
        $urlFilterMember = $ProfileSettingNode.SelectSingleNode("profiles/url-filtering/member")
        if ($null -ne $urlFilterMember) {
            $profileName = $urlFilterMember.InnerText
            Write-LogMessage "Found direct URL filtering profile reference: $profileName" -Level "DEBUG" `
                -Component "Convert-PANW2EIA" -LogPath $script:logPath -EnableDebugLogging:$script:debugEnabled
            return $profileName
        }

        return $null
    }

    #endregion

    #region Initialization

    # Initialize logging
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:logPath = Join-Path $OutputBasePath "${timestamp}_Convert-PANW2EIA.log"
    $script:debugEnabled = $EnableDebugLogging

    Write-LogMessage "Starting PANW to EIA conversion" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Input files:" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Panorama XML: $PanoramaXmlPath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Category Mappings: $CategoryMappingsPath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Output Path: $OutputBasePath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    if ($DeviceGroupName) {
        Write-LogMessage "  Device Group Filter: $DeviceGroupName" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    # Initialize statistics
    $stats = @{
        SecurityRulesLoaded         = 0
        PreRulebaseRules            = 0
        PostRulebaseRules           = 0
        RulesProcessed              = 0
        RulesSkippedDisabled        = 0
        RulesSkippedDenyDropReset   = 0
        RulesSkippedNoUrlFilter     = 0
        RulesWithApplications       = 0
        UrlFilteringProfilesProcessed = 0
        CustomCategoriesProcessed   = 0
        CustomCategoriesSkippedCategoryMatch = 0
        CustomCategoriesSkippedEmpty = 0
        PanDBCategoriesReferenced   = 0
        PanDBCategoriesMapped       = 0
        PanDBCategoriesUnmapped     = 0
        FQDNsClassified             = 0
        URLsClassified              = 0
        IPsClassified               = 0
        EntriesSkippedIPv6          = 0
        EntriesSkippedInvalid       = 0
        PoliciesCreated             = 0
        CustomCategoryPolicies      = 0
        WebCategoryPolicies         = 0
        PoliciesFlaggedForReview    = 0
        SecurityProfilesCreated     = 0
        PriorityConflictsResolved   = 0
        GroupsSplitForCharLimit     = 0
        TotalFQDNsInPolicies        = 0
        TotalURLsInPolicies         = 0
        TotalRulesInPolicies        = 0
        DeviceGroupsProcessed       = 0
    }

    # Collections for output
    $policies = [System.Collections.ArrayList]::new()
    $securityProfiles = [System.Collections.ArrayList]::new()

    #endregion

    #region Phase 1: Data Loading

    Write-LogMessage "Phase 1: Loading and validating input files..." -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # 1.1 / 1.2: Load and parse XML
    $xmlDoc = Import-PanoramaXml -Path $PanoramaXmlPath

    # 1.3: Determine scope - enumerate device-groups
    $deviceGroupNodes = $xmlDoc.SelectNodes("/config/devices/entry/device-group/entry")
    $allDeviceGroups = @()
    if ($null -ne $deviceGroupNodes) {
        foreach ($dgNode in $deviceGroupNodes) {
            $allDeviceGroups += $dgNode.GetAttribute("name")
        }
    }

    if ($allDeviceGroups.Count -eq 0) {
        Write-LogMessage "No device-groups found in Panorama XML" -Level "ERROR" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        throw "No device-groups found in Panorama XML export"
    }

    Write-LogMessage "Found $($allDeviceGroups.Count) device-group(s): $($allDeviceGroups -join ', ')" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Filter to specific device-group if specified
    $targetDeviceGroups = $allDeviceGroups
    if ($DeviceGroupName) {
        if ($DeviceGroupName -notin $allDeviceGroups) {
            Write-LogMessage "Specified device-group '$DeviceGroupName' not found. Available: $($allDeviceGroups -join ', ')" -Level "ERROR" `
                -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            throw "Device-group '$DeviceGroupName' not found in Panorama XML export"
        }
        $targetDeviceGroups = @($DeviceGroupName)
        Write-LogMessage "Filtering to device-group: $DeviceGroupName" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    $stats.DeviceGroupsProcessed = $targetDeviceGroups.Count

    # Check for shared section
    $sharedNode = $xmlDoc.SelectSingleNode("/config/shared")
    if ($null -ne $sharedNode) {
        Write-LogMessage "Shared configuration section found" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    else {
        Write-LogMessage "No shared configuration section found" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    # 1.4: Build object collections
    Write-LogMessage "Building object collections..." -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    $customCategoriesHashtable = Get-PANWCustomUrlCategories -XmlDoc $xmlDoc -DeviceGroups $targetDeviceGroups
    Write-LogMessage "Collected $($customCategoriesHashtable.Count) custom URL categories" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    $urlFilteringProfiles = Get-PANWUrlFilteringProfiles -XmlDoc $xmlDoc -DeviceGroups $targetDeviceGroups
    Write-LogMessage "Collected $($urlFilteringProfiles.Count) URL filtering profiles" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    $profileGroupsLookup = Get-PANWProfileGroups -XmlDoc $xmlDoc -DeviceGroups $targetDeviceGroups
    Write-LogMessage "Collected $($profileGroupsLookup.Count) profile groups" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    $securityRules = Get-PANWSecurityRules -XmlDoc $xmlDoc -DeviceGroups $targetDeviceGroups
    $stats.SecurityRulesLoaded = $securityRules.Count
    $stats.PreRulebaseRules = @($securityRules | Where-Object { $_.RulebaseType -eq 'pre-rulebase' }).Count
    $stats.PostRulebaseRules = @($securityRules | Where-Object { $_.RulebaseType -eq 'post-rulebase' }).Count
    Write-LogMessage "Collected $($securityRules.Count) security rules (pre: $($stats.PreRulebaseRules), post: $($stats.PostRulebaseRules))" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # 1.5: Build lookup tables
    Write-LogMessage "Loading category mappings from: $CategoryMappingsPath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    try {
        $categoryMappings = Import-Csv -Path $CategoryMappingsPath -ErrorAction Stop
        Write-LogMessage "Loaded $($categoryMappings.Count) category mappings" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    catch {
        Write-LogMessage "Failed to load category mappings: $_" -Level "ERROR" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        throw "Failed to load category mappings file: $CategoryMappingsPath"
    }

    $categoryMappingsHashtable = @{}
    foreach ($mapping in $categoryMappings) {
        $categoryMappingsHashtable[$mapping.PANWCategory.ToLower()] = $mapping
    }

    # Custom category policies tracking hashtable (populated in Phase 2)
    $customCategoryPoliciesHashtable = @{}

    # Profile-level custom category references tracking (populated in Phase 3)
    $profileCustomCategoryRefs = @{}

    # Track all policies created per profile for Phase 4
    $profilePoliciesHashtable = @{}

    #endregion

    #region Phase 2: Custom URL Category Processing

    Write-LogMessage "Phase 2: Processing custom URL categories..." -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    foreach ($categoryName in $customCategoriesHashtable.Keys) {
        $category = $customCategoriesHashtable[$categoryName]

        # Skip Category Match type
        if ($category.Type -eq "Category Match") {
            Write-LogMessage "Skipping Category Match type custom URL category: $categoryName" -Level "INFO" `
                -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $stats.CustomCategoriesSkippedCategoryMatch++
            continue
        }

        # Skip non-URL List types
        if ($category.Type -ne "URL List") {
            Write-LogMessage "Skipping unsupported custom URL category type '$($category.Type)': $categoryName" -Level "WARN" `
                -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            continue
        }

        Write-LogMessage "Processing custom URL category: $categoryName" -Level "DEBUG" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

        $allMembers = $category.Members

        # Skip empty categories
        if ($null -eq $allMembers -or $allMembers.Count -eq 0) {
            Write-LogMessage "Custom URL category '$categoryName' has no members - skipping" -Level "WARN" `
                -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $stats.CustomCategoriesSkippedEmpty++
            continue
        }

        # Deduplicate (case-insensitive)
        $uniqueMembers = @($allMembers | Group-Object -Property { $_.ToLower() } | ForEach-Object { $_.Group[0] })
        $duplicateCount = $allMembers.Count - $uniqueMembers.Count
        if ($duplicateCount -gt 0) {
            Write-LogMessage "Removed $duplicateCount duplicate entries from category $categoryName" -Level "DEBUG" `
                -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }

        # Clean destinations
        $cleanedDestinations = @()
        foreach ($member in $uniqueMembers) {
            $cleaned = ConvertTo-CleanDestination -Destination $member -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            if ($null -ne $cleaned) {
                $cleanedDestinations += $cleaned
            }
            else {
                $stats.EntriesSkippedInvalid++
            }
        }

        # Deduplicate again after cleaning
        $preDedupeCount = $cleanedDestinations.Count
        $cleanedDestinations = @($cleanedDestinations | Group-Object -Property { $_.ToLower() } | ForEach-Object { $_.Group[0] })
        $postCleanDuplicates = $preDedupeCount - $cleanedDestinations.Count
        if ($postCleanDuplicates -gt 0) {
            Write-LogMessage "Removed $postCleanDuplicates duplicate entries after cleaning for category $categoryName" -Level "DEBUG" `
                -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }

        if ($cleanedDestinations.Count -eq 0) {
            Write-LogMessage "No valid destinations after cleaning for category: $categoryName" -Level "WARN" `
                -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $stats.CustomCategoriesSkippedEmpty++
            continue
        }

        # Classify destinations
        $classifiedDestinations = @{
            'FQDN'      = [System.Collections.ArrayList]::new()
            'URL'        = [System.Collections.ArrayList]::new()
            'ipAddress'  = [System.Collections.ArrayList]::new()
        }

        foreach ($dest in $cleanedDestinations) {
            $type = Get-DestinationType -Destination $dest

            switch ($type) {
                'ipv4' {
                    if (Test-ValidIPv4Address -IpAddress $dest) {
                        [void]$classifiedDestinations['ipAddress'].Add($dest)
                        $stats.IPsClassified++
                    }
                    else {
                        Write-LogMessage "Invalid IPv4 address: $dest" -Level "WARN" `
                            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                        $stats.EntriesSkippedInvalid++
                    }
                }
                'ipv6' {
                    Write-LogMessage "Skipping IPv6 address (not supported): $dest" -Level "WARN" `
                        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                    $stats.EntriesSkippedIPv6++
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

        # Create policy entries
        $policyName = "$categoryName-Block"

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
                Write-LogMessage "Processing base domain '$baseDomain' with $($fqdnsByBaseDomain[$baseDomain].Count) FQDNs" -Level "DEBUG" `
                    -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

                $groups = Split-ByCharacterLimit -Entries @($fqdnsByBaseDomain[$baseDomain]) -MaxLength 300

                if ($groups.Count -gt 1) { $stats.GroupsSplitForCharLimit++ }

                for ($i = 0; $i -lt $groups.Count; $i++) {
                    $ruleName = if ($i -eq 0) { $baseDomain } else { "$baseDomain-$($i + 1)" }

                    $policyEntry = [PSCustomObject]@{
                        PolicyName       = $policyName
                        PolicyType       = "WebContentFiltering"
                        PolicyAction     = "Block"
                        Description      = if ($category.Description) { $category.Description } else { "Converted from PANW custom URL category: $categoryName" }
                        RuleType         = "FQDN"
                        RuleDestinations = $groups[$i] -join ";"
                        RuleName         = $ruleName
                        ReviewNeeded     = "No"
                        ReviewDetails    = ""
                        Provision        = "Yes"
                    }

                    [void]$policies.Add($policyEntry)
                    $stats.TotalRulesInPolicies++
                    $stats.TotalFQDNsInPolicies += $groups[$i].Count
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

                if ($groups.Count -gt 1) { $stats.GroupsSplitForCharLimit++ }

                for ($i = 0; $i -lt $groups.Count; $i++) {
                    $ruleName = if ($i -eq 0) { $baseDomain } else { "$baseDomain-$($i + 1)" }

                    $policyEntry = [PSCustomObject]@{
                        PolicyName       = $policyName
                        PolicyType       = "WebContentFiltering"
                        PolicyAction     = "Block"
                        Description      = if ($category.Description) { $category.Description } else { "Converted from PANW custom URL category: $categoryName" }
                        RuleType         = "URL"
                        RuleDestinations = $groups[$i] -join ";"
                        RuleName         = $ruleName
                        ReviewNeeded     = "No"
                        ReviewDetails    = ""
                        Provision        = "Yes"
                    }

                    [void]$policies.Add($policyEntry)
                    $stats.TotalRulesInPolicies++
                    $stats.TotalURLsInPolicies += $groups[$i].Count
                }
            }
        }

        # Process IP addresses (not grouped by domain)
        if ($classifiedDestinations['ipAddress'].Count -gt 0) {
            $groups = Split-ByCharacterLimit -Entries @($classifiedDestinations['ipAddress']) -MaxLength 300

            if ($groups.Count -gt 1) { $stats.GroupsSplitForCharLimit++ }

            for ($i = 0; $i -lt $groups.Count; $i++) {
                $ruleName = if ($i -eq 0) { "IPs" } else { "IPs-$($i + 1)" }

                $policyEntry = [PSCustomObject]@{
                    PolicyName       = $policyName
                    PolicyType       = "WebContentFiltering"
                    PolicyAction     = "Block"
                    Description      = if ($category.Description) { $category.Description } else { "Converted from PANW custom URL category: $categoryName" }
                    RuleType         = "ipAddress"
                    RuleDestinations = $groups[$i] -join ";"
                    RuleName         = $ruleName
                    ReviewNeeded     = "No"
                    ReviewDetails    = ""
                    Provision        = "Yes"
                }

                [void]$policies.Add($policyEntry)
                $stats.TotalRulesInPolicies++
            }
        }

        # Track this custom category policy
        $customCategoryPoliciesHashtable[$categoryName] = @{
            BlockPolicyName = $policyName
            AllowPolicyName = $null
            BaseName        = $categoryName
        }

        $stats.CustomCategoriesProcessed++
    }

    Write-LogMessage "Custom categories processed: $($stats.CustomCategoriesProcessed), skipped (Category Match): $($stats.CustomCategoriesSkippedCategoryMatch), skipped (empty): $($stats.CustomCategoriesSkippedEmpty)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    #endregion

    #region Phase 3: URL Filtering Profile Processing

    Write-LogMessage "Phase 3: Processing URL filtering profiles..." -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    foreach ($profileName in $urlFilteringProfiles.Keys) {
        $profile = $urlFilteringProfiles[$profileName]
        $profilePolicies = [System.Collections.ArrayList]::new()

        Write-LogMessage "Processing URL filtering profile: $profileName" -Level "DEBUG" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

        # Track custom category references per profile
        $profileCustomCatRefs = [System.Collections.ArrayList]::new()

        foreach ($action in @('allow', 'block', 'alert', 'continue', 'override')) {
            $categories = $profile.CategoryActions[$action]
            if ($null -eq $categories -or $categories.Count -eq 0) {
                continue
            }

            # Separate custom from predefined categories
            $predefinedCategories = @()
            $customCategories = @()

            foreach ($catName in $categories) {
                if ($customCategoriesHashtable.ContainsKey($catName)) {
                    $customCategories += $catName
                    # Track custom category reference with its action
                    [void]$profileCustomCatRefs.Add([PSCustomObject]@{
                        CustomCategoryName = $catName
                        Action             = $action
                    })
                }
                else {
                    $predefinedCategories += $catName
                }
            }

            # Process predefined categories - create web category policy
            if ($predefinedCategories.Count -gt 0) {
                $mappedCategories = [System.Collections.ArrayList]::new()
                $unmappedList = [System.Collections.ArrayList]::new()
                $hasUnmapped = $false

                foreach ($pandbCategory in $predefinedCategories) {
                    $stats.PanDBCategoriesReferenced++
                    $mapping = $categoryMappingsHashtable[$pandbCategory.ToLower()]

                    if ($null -eq $mapping) {
                        # Category not found in mapping file
                        [void]$mappedCategories.Add("${pandbCategory}_Unmapped")
                        [void]$unmappedList.Add($pandbCategory)
                        $hasUnmapped = $true
                        $stats.PanDBCategoriesUnmapped++
                        Write-LogMessage "PAN-DB category '$pandbCategory' not found in mapping file" -Level "WARN" `
                            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                    }
                    elseif ([string]::IsNullOrWhiteSpace($mapping.GSACategory) -or $mapping.GSACategory -eq "Unmapped") {
                        # Mapping exists but no GSA category or explicitly Unmapped
                        [void]$mappedCategories.Add("${pandbCategory}_Unmapped")
                        [void]$unmappedList.Add($pandbCategory)
                        $hasUnmapped = $true
                        $stats.PanDBCategoriesUnmapped++
                        Write-LogMessage "PAN-DB category '$pandbCategory' has no matching GSA category" -Level "WARN" `
                            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                    }
                    else {
                        [void]$mappedCategories.Add($mapping.GSACategory)
                        $stats.PanDBCategoriesMapped++
                    }
                }

                # Determine EIA action and review flags based on PANW action
                $eiaAction = "Block"
                $reviewNeeded = "No"
                $reviewDetails = ""
                $provision = "Yes"
                $actionSuffix = ""

                switch ($action) {
                    'allow' {
                        $eiaAction = "Allow"
                        $actionSuffix = "Allow"
                    }
                    'block' {
                        $eiaAction = "Block"
                        $actionSuffix = "Block"
                    }
                    'alert' {
                        $eiaAction = "Block"
                        $reviewNeeded = "Yes"
                        $reviewDetails = "PANW 'alert' action requires review - mapped to Block"
                        $provision = "No"
                        $actionSuffix = "Alert"
                    }
                    'continue' {
                        $eiaAction = "Block"
                        $reviewNeeded = "Yes"
                        $reviewDetails = "PANW 'continue' action requires review - mapped to Block"
                        $provision = "No"
                        $actionSuffix = "Continue"
                    }
                    'override' {
                        $eiaAction = "Block"
                        $reviewNeeded = "Yes"
                        $reviewDetails = "PANW 'override' action requires review - mapped to Block"
                        $provision = "No"
                        $actionSuffix = "Override"
                    }
                }

                # Add unmapped review details
                if ($hasUnmapped) {
                    $unmappedDetail = "Unmapped categories found: $($unmappedList -join ', ')"
                    if ($reviewDetails) {
                        $reviewDetails = "$reviewDetails; $unmappedDetail"
                    }
                    else {
                        $reviewDetails = $unmappedDetail
                    }
                    $reviewNeeded = "Yes"
                    $provision = "No"
                }

                $webCatPolicyName = "$profileName-WebCategories-$actionSuffix"

                $policyEntry = [PSCustomObject]@{
                    PolicyName       = $webCatPolicyName
                    PolicyType       = "WebContentFiltering"
                    PolicyAction     = $eiaAction
                    Description      = "$($actionSuffix) categories from $profileName profile"
                    RuleType         = "webCategory"
                    RuleDestinations = $mappedCategories -join ";"
                    RuleName         = "WebCategories"
                    ReviewNeeded     = $reviewNeeded
                    ReviewDetails    = $reviewDetails
                    Provision        = $provision
                }

                [void]$policies.Add($policyEntry)
                [void]$profilePolicies.Add($webCatPolicyName)
                $stats.TotalRulesInPolicies++
                $stats.WebCategoryPolicies++

                if ($reviewNeeded -eq "Yes") {
                    $stats.PoliciesFlaggedForReview++
                }
            }

            # Handle custom categories referenced with Allow action - may need Allow version
            foreach ($customCat in $customCategories) {
                if ($action -eq 'allow') {
                    $catPolicyInfo = $customCategoryPoliciesHashtable[$customCat]
                    if ($null -ne $catPolicyInfo -and $null -eq $catPolicyInfo.AllowPolicyName) {
                        # Create Allow version by duplicating Block policy entries
                        $allowPolicyName = "$($catPolicyInfo.BaseName)-Allow"
                        $blockPolicies = $policies | Where-Object { $_.PolicyName -eq $catPolicyInfo.BlockPolicyName }

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
                            $stats.TotalRulesInPolicies++

                            if ($allowPolicy.RuleType -eq 'FQDN') {
                                $stats.TotalFQDNsInPolicies += ($allowPolicy.RuleDestinations -split ';').Count
                            }
                            elseif ($allowPolicy.RuleType -eq 'URL') {
                                $stats.TotalURLsInPolicies += ($allowPolicy.RuleDestinations -split ';').Count
                            }
                        }

                        $catPolicyInfo.AllowPolicyName = $allowPolicyName
                        Write-LogMessage "Created Allow version of custom category policy: $allowPolicyName" -Level "DEBUG" `
                            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                    }
                }
            }
        }

        # Store profile custom category references for Phase 4
        $profileCustomCategoryRefs[$profileName] = $profileCustomCatRefs

        # Store profile policies for Phase 4
        $profilePoliciesHashtable[$profileName] = $profilePolicies

        $stats.UrlFilteringProfilesProcessed++
    }

    Write-LogMessage "URL filtering profiles processed: $($stats.UrlFilteringProfilesProcessed)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    #endregion

    #region Phase 4: Security Rule Processing

    Write-LogMessage "Phase 4: Processing security rules..." -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    $disabledRuleNames = [System.Collections.ArrayList]::new()

    foreach ($rule in $securityRules) {
        # 4.1: Filter - skip disabled rules
        if ($rule.Disabled -eq "yes") {
            [void]$disabledRuleNames.Add($rule.Name)
            $stats.RulesSkippedDisabled++
            continue
        }

        # Skip non-allow actions
        if ($rule.Action -ne "allow") {
            Write-LogMessage "Skipping rule '$($rule.Name)' with action '$($rule.Action)' (not allow)" -Level "DEBUG" `
                -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $stats.RulesSkippedDenyDropReset++
            continue
        }

        # 4.2: Resolve URL filtering profile
        $resolvedProfileName = Resolve-UrlFilteringProfile -ProfileSettingNode $rule.ProfileSetting -ProfileGroupsLookup $profileGroupsLookup

        if ($null -eq $resolvedProfileName) {
            Write-LogMessage "Skipping rule '$($rule.Name)' - no URL filtering profile found" -Level "DEBUG" `
                -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $stats.RulesSkippedNoUrlFilter++
            continue
        }

        # Validate the resolved profile exists
        if (-not $urlFilteringProfiles.ContainsKey($resolvedProfileName)) {
            Write-LogMessage "URL filtering profile '$resolvedProfileName' referenced by rule '$($rule.Name)' not found" -Level "WARN" `
                -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $stats.RulesSkippedNoUrlFilter++
            continue
        }

        Write-LogMessage "Processing rule: $($rule.Name) (profile: $resolvedProfileName)" -Level "DEBUG" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

        # 4.3: Extract users and groups
        $entraUsers = [System.Collections.ArrayList]::new()
        $entraGroups = [System.Collections.ArrayList]::new()
        $needsReview = $false
        $reviewReasons = [System.Collections.ArrayList]::new()

        if ($null -eq $rule.SourceUsers -or $rule.SourceUsers.Count -eq 0) {
            [void]$entraGroups.Add("Replace_with_All_IA_Users_Group")
        }
        else {
            foreach ($sourceUser in $rule.SourceUsers) {
                switch -Regex ($sourceUser) {
                    '^any$' {
                        [void]$entraGroups.Add("Replace_with_All_IA_Users_Group")
                    }
                    '^unknown$' {
                        Write-LogMessage "Skipping 'unknown' source-user in rule '$($rule.Name)'" -Level "WARN" `
                            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                    }
                    '^pre-logon$' {
                        Write-LogMessage "Skipping 'pre-logon' source-user in rule '$($rule.Name)'" -Level "WARN" `
                            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                    }
                    '@' {
                        # Email format
                        [void]$entraUsers.Add($sourceUser)
                    }
                    '\\' {
                        # domain\user format - add to groups, flag for review
                        [void]$entraGroups.Add($sourceUser)
                        if ("Review source-user format" -notin $reviewReasons) {
                            [void]$reviewReasons.Add("Review source-user format")
                        }
                        $needsReview = $true
                    }
                    default {
                        # Treat as group name
                        [void]$entraGroups.Add($sourceUser)
                    }
                }
            }
        }

        # Default if no valid users/groups remain
        if ($entraUsers.Count -eq 0 -and $entraGroups.Count -eq 0) {
            [void]$entraGroups.Add("Replace_with_All_IA_Users_Group")
        }

        # 4.4: Detect application references
        $hasNonAnyApps = $false
        if ($null -ne $rule.Applications -and $rule.Applications.Count -gt 0) {
            $nonAnyApps = @($rule.Applications | Where-Object { $_ -ne "any" })
            if ($nonAnyApps.Count -gt 0) {
                $hasNonAnyApps = $true
                $needsReview = $true
                [void]$reviewReasons.Add("Applications referenced: $($nonAnyApps -join ', ')")
                $stats.RulesWithApplications++
                Write-LogMessage "Rule '$($rule.Name)' has application references: $($nonAnyApps -join ', ')" -Level "INFO" `
                    -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            }
        }

        # 4.5: Build policy links
        $policyLinks = [System.Collections.ArrayList]::new()

        # Add web category policies from the profile
        if ($profilePoliciesHashtable.ContainsKey($resolvedProfileName)) {
            foreach ($profilePolicyName in $profilePoliciesHashtable[$resolvedProfileName]) {
                [void]$policyLinks.Add($profilePolicyName)
            }
        }

        # Add custom category policies referenced in the profile
        if ($profileCustomCategoryRefs.ContainsKey($resolvedProfileName)) {
            foreach ($catRef in $profileCustomCategoryRefs[$resolvedProfileName]) {
                $catPolicyInfo = $customCategoryPoliciesHashtable[$catRef.CustomCategoryName]
                if ($null -ne $catPolicyInfo) {
                    switch ($catRef.Action) {
                        'allow' {
                            if ($null -ne $catPolicyInfo.AllowPolicyName) {
                                if ($catPolicyInfo.AllowPolicyName -notin $policyLinks) {
                                    [void]$policyLinks.Add($catPolicyInfo.AllowPolicyName)
                                }
                            }
                        }
                        { $_ -in @('block', 'alert', 'continue', 'override') } {
                            if ($catPolicyInfo.BlockPolicyName -notin $policyLinks) {
                                [void]$policyLinks.Add($catPolicyInfo.BlockPolicyName)
                            }
                        }
                    }
                }
            }
        }

        # Format policy links with priorities
        $formattedLinks = @()
        $linkPriority = 100
        foreach ($link in $policyLinks) {
            $formattedLinks += "${link}:${linkPriority}"
            $linkPriority += 100
        }

        # 4.6: Create security profile
        $securityProfile = [PSCustomObject]@{
            SecurityProfileName  = $rule.Name
            Priority             = $rule.Order * 100
            SecurityProfileLinks = $formattedLinks -join ";"
            CADisplayName        = "CA-$($rule.Name)"
            EntraUsers           = $entraUsers -join ";"
            EntraGroups          = $entraGroups -join ";"
            Provision            = "Yes"
        }

        [void]$securityProfiles.Add($securityProfile)
        $stats.RulesProcessed++
    }

    # Log disabled rule names at DEBUG level
    if ($disabledRuleNames.Count -gt 0) {
        Write-LogMessage "Disabled rules ($($disabledRuleNames.Count)): $($disabledRuleNames -join ', ')" -Level "DEBUG" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        Write-LogMessage "Skipped $($disabledRuleNames.Count) disabled rules" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    # Check for no processable rules
    if ($securityProfiles.Count -eq 0) {
        Write-LogMessage "No processable security rules found (enabled + allow + URL filter)" -Level "ERROR" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        throw "No processable security rules found. Ensure at least one enabled rule with action 'allow' and a URL filtering profile exists."
    }

    Write-LogMessage "Rules processed: $($stats.RulesProcessed), skipped disabled: $($stats.RulesSkippedDisabled), skipped deny/drop/reset: $($stats.RulesSkippedDenyDropReset), skipped no URL filter: $($stats.RulesSkippedNoUrlFilter)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # 4.7: Resolve priority conflicts
    Write-LogMessage "Resolving priority conflicts..." -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    $priorityTracker = @{}

    foreach ($secProfile in $securityProfiles) {
        while ($priorityTracker.ContainsKey($secProfile.Priority)) {
            Write-LogMessage "Priority conflict at $($secProfile.Priority) for '$($secProfile.SecurityProfileName)', incrementing" -Level "INFO" `
                -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $secProfile.Priority++
            $stats.PriorityConflictsResolved++
        }
        $priorityTracker[$secProfile.Priority] = $secProfile.SecurityProfileName
    }

    # 4.8: Cleanup unreferenced policies
    Write-LogMessage "Cleaning up unreferenced policies..." -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    $referencedPolicies = @{}
    foreach ($secProfile in $securityProfiles) {
        $linkEntries = $secProfile.SecurityProfileLinks -split ';'
        foreach ($linkEntry in $linkEntries) {
            $policyNameFromLink = $linkEntry -replace ':\d+$', ''
            $referencedPolicies[$policyNameFromLink] = $true
        }
    }

    $originalPolicyCount = $policies.Count
    $policies = [System.Collections.ArrayList]@($policies | Where-Object {
        # Keep web category policies (they are always referenced via profile)
        if ($_.RuleType -eq 'webCategory') {
            return $true
        }

        # Keep custom category policies that are referenced
        if ($referencedPolicies.ContainsKey($_.PolicyName)) {
            return $true
        }

        # Remove unreferenced custom category policy
        return $false
    })

    $removedPolicies = $originalPolicyCount - $policies.Count
    if ($removedPolicies -gt 0) {
        Write-LogMessage "Removed $removedPolicies unreferenced policies" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    $stats.PoliciesCreated = $policies.Count
    $stats.CustomCategoryPolicies = @($policies | Where-Object { $_.RuleType -ne 'webCategory' } | Select-Object -Property PolicyName -Unique).Count
    $stats.SecurityProfilesCreated = $securityProfiles.Count

    #endregion

    #region Phase 5: Export and Summary

    Write-LogMessage "Phase 5: Exporting results..." -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Export Policies CSV
    $policiesCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_Policies.csv"
    $policies | Export-Csv -Path $policiesCsvPath -NoTypeInformation -Encoding utf8BOM
    Write-LogMessage "Exported $($policies.Count) policy entries to: $policiesCsvPath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Export Security Profiles CSV
    $spCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_SecurityProfiles.csv"
    $securityProfiles | Export-Csv -Path $spCsvPath -NoTypeInformation -Encoding utf8BOM
    Write-LogMessage "Exported $($securityProfiles.Count) security profiles to: $spCsvPath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Generate summary
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "=== CONVERSION SUMMARY ===" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Input: $PanoramaXmlPath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Device Groups processed: $($stats.DeviceGroupsProcessed)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Security rules loaded: $($stats.SecurityRulesLoaded)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Pre-rulebase rules: $($stats.PreRulebaseRules)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Post-rulebase rules: $($stats.PostRulebaseRules)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Rules processed (enabled + allow + URL filter): $($stats.RulesProcessed)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Rules skipped (disabled): $($stats.RulesSkippedDisabled)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Rules skipped (deny/drop/reset): $($stats.RulesSkippedDenyDropReset)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Rules skipped (no URL filter profile): $($stats.RulesSkippedNoUrlFilter)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Rules with application references (flagged): $($stats.RulesWithApplications)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "URL Filtering Profiles processed: $($stats.UrlFilteringProfilesProcessed)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Custom URL Categories processed: $($stats.CustomCategoriesProcessed)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Categories skipped (Category Match type): $($stats.CustomCategoriesSkippedCategoryMatch)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Categories skipped (empty): $($stats.CustomCategoriesSkippedEmpty)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "PAN-DB categories referenced: $($stats.PanDBCategoriesReferenced)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Mapped to GSA: $($stats.PanDBCategoriesMapped)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Unmapped: $($stats.PanDBCategoriesUnmapped)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Destinations classified:" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  FQDNs: $($stats.FQDNsClassified)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  URLs: $($stats.URLsClassified)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  IP addresses: $($stats.IPsClassified)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Skipped (IPv6/invalid): $($stats.EntriesSkippedIPv6 + $stats.EntriesSkippedInvalid)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Policies created: $($stats.PoliciesCreated)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Custom category policies: $($stats.CustomCategoryPolicies)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Web category policies: $($stats.WebCategoryPolicies)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  Policies flagged for review: $($stats.PoliciesFlaggedForReview)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Security profiles created: $($stats.SecurityProfilesCreated)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Priority conflicts resolved: $($stats.PriorityConflictsResolved)" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Global Secure Access limits validation
    Write-LogMessage "=== GLOBAL SECURE ACCESS LIMITS VALIDATION ===" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    $limits = @{
        MaxPolicies        = 100
        MaxRules           = 1000
        MaxFQDNs           = 8000
        MaxSecurityProfiles = 256
    }

    $uniquePolicies = ($policies | Select-Object -Property PolicyName -Unique).Count
    $totalFQDNsAndURLs = $stats.TotalFQDNsInPolicies + $stats.TotalURLsInPolicies

    Write-LogMessage "Current configuration:" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Web content filtering policies: $uniquePolicies (Limit: $($limits.MaxPolicies))" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Rules across all policies: $($stats.TotalRulesInPolicies) (Limit: $($limits.MaxRules))" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Total FQDNs and URLs: $totalFQDNsAndURLs (Limit: $($limits.MaxFQDNs))" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Security profiles: $($stats.SecurityProfilesCreated) (Limit: $($limits.MaxSecurityProfiles))" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    $hasWarnings = $false

    if ($uniquePolicies -gt $limits.MaxPolicies) {
        $hasWarnings = $true
        $overage = $uniquePolicies - $limits.MaxPolicies
        Write-LogMessage "WARNING: Web content filtering policies ($uniquePolicies) exceeds the limit of $($limits.MaxPolicies) by $overage policies" -Level "WARN" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    if ($stats.TotalRulesInPolicies -gt $limits.MaxRules) {
        $hasWarnings = $true
        $overage = $stats.TotalRulesInPolicies - $limits.MaxRules
        Write-LogMessage "WARNING: Total rules ($($stats.TotalRulesInPolicies)) exceeds the limit of $($limits.MaxRules) by $overage rules" -Level "WARN" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    if ($totalFQDNsAndURLs -gt $limits.MaxFQDNs) {
        $hasWarnings = $true
        $overage = $totalFQDNsAndURLs - $limits.MaxFQDNs
        Write-LogMessage "WARNING: Total FQDNs and URLs ($totalFQDNsAndURLs) exceeds the limit of $($limits.MaxFQDNs) by $overage entries" -Level "WARN" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    if ($stats.SecurityProfilesCreated -gt $limits.MaxSecurityProfiles) {
        $hasWarnings = $true
        $overage = $stats.SecurityProfilesCreated - $limits.MaxSecurityProfiles
        Write-LogMessage "WARNING: Security profiles ($($stats.SecurityProfilesCreated)) exceeds the limit of $($limits.MaxSecurityProfiles) by $overage profiles" -Level "WARN" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    if (-not $hasWarnings) {
        Write-LogMessage "All limits are within Global Secure Access boundaries." -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    else {
        Write-LogMessage "" -Level "INFO" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        Write-LogMessage "Action required: Please review and reduce the configuration to meet Global Secure Access limits before importing." -Level "WARN" `
            -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Output files:" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Policies: $policiesCsvPath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Security Profiles: $spCsvPath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Log File: $logPath" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Conversion completed successfully" -Level "INFO" `
        -Component "Convert-PANW2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    #endregion
}
