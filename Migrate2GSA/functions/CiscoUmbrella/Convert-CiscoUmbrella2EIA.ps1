function Convert-CiscoUmbrella2EIA {
    <#
    .SYNOPSIS
        Converts Cisco Umbrella DNS and Web policy configuration to Microsoft Entra Internet Access (EIA) format.

    .DESCRIPTION
        This function processes Cisco Umbrella DNS policies, web policies (including proxy rulesets),
        destination lists, category settings, and application mappings to generate CSV files ready for
        import into Microsoft Entra Internet Access (EIA) via Start-EntraInternetAccessProvisioning.

        The conversion process includes:
        - Transforming Umbrella DNS and/or web policies into EIA web content filtering policies
        - Converting Umbrella web categories to EIA web categories using a provided mapping file
        - Converting Umbrella application-based rules to EIA FQDN-based policies using an app mapping file
        - Resolving destination lists to FQDN rules with dual-entry pattern (domain.com;*.domain.com)
        - Generating Security Profiles with Default and Override profiles based on identity scoping
        - Producing import-ready CSV files for EIA configuration

    .PARAMETER DnsPoliciesPath
        Path to Cisco Umbrella DNS Policies JSON export. At least one of DnsPoliciesPath or WebPoliciesPath must be provided.

    .PARAMETER WebPoliciesPath
        Path to Cisco Umbrella Web Policies JSON export. At least one of DnsPoliciesPath or WebPoliciesPath must be provided.

    .PARAMETER DestinationListsPath
        Path to Cisco Umbrella Destination Lists JSON export.
        Default: destination_lists.json in current directory

    .PARAMETER CategorySettingsPath
        Path to Cisco Umbrella Category Settings JSON export. Required when DnsPoliciesPath is provided.
        Default: category_settings.json in current directory

    .PARAMETER CategoryMappingsPath
        Path to Umbrella to EIA category mappings CSV file.
        Default: CiscoUmbrella2EIA-CategoryMappings.csv in current directory

    .PARAMETER AppMappingsPath
        Path to Umbrella to EIA application mappings CSV file. Required when WebPoliciesPath is provided.
        The CSV must contain columns: UmbrellaAppId, UmbrellaAppName, GSAAppName, MatchType, GSAEndpoints.
        Default: CiscoUmbrella2EIA-AppMappings.csv in current directory

    .PARAMETER OutputBasePath
        Base directory for output CSV and log files.
        Default: Current directory

    .PARAMETER EnableDebugLogging
        Enable verbose debug logging for detailed processing information.

    .PARAMETER IncludePolicyName
        One or more policy name patterns to include. Supports wildcards (e.g., '*Finance*', 'Corp-*').
        Case-insensitive. When specified, only DNS and Web policies matching at least one pattern are processed.
        Both exact names and wildcard patterns are supported via -like matching.

    .PARAMETER ExcludePolicyName
        One or more policy name patterns to exclude. Supports wildcards (e.g., '*test*', '*dev*').
        Case-insensitive. When specified, matching DNS and Web policies are skipped.
        If both IncludePolicyName and ExcludePolicyName are specified, exclude takes precedence.

    .EXAMPLE
        Convert-CiscoUmbrella2EIA -DnsPoliciesPath ".\dns_policies.json" -WebPoliciesPath ".\web_policies.json"

        Converts both DNS and web policies using default paths for supporting files.

    .EXAMPLE
        Convert-CiscoUmbrella2EIA -DnsPoliciesPath ".\dns_policies.json"

        Converts DNS policies only.

    .EXAMPLE
        Convert-CiscoUmbrella2EIA -WebPoliciesPath ".\web_policies.json" -OutputBasePath "C:\Output" -EnableDebugLogging

        Converts web policies only with debug logging, output to C:\Output.

    .EXAMPLE
        Convert-CiscoUmbrella2EIA -DnsPoliciesPath ".\dns.json" -IncludePolicyName "Default Policy for users","Default policy for admins"

        Converts only the two named policies (case-insensitive exact match).

    .EXAMPLE
        Convert-CiscoUmbrella2EIA -DnsPoliciesPath ".\dns.json" -IncludePolicyName "*Finance*","Corp-*"

        Converts only policies whose names contain 'Finance' or start with 'Corp-'.

    .EXAMPLE
        Convert-CiscoUmbrella2EIA -WebPoliciesPath ".\web.json" -ExcludePolicyName "*test*","*dev*"

        Converts all web policies except those with 'test' or 'dev' in their names.

    .EXAMPLE
        Convert-CiscoUmbrella2EIA -DnsPoliciesPath ".\dns.json" -WebPoliciesPath ".\web.json" -IncludePolicyName "Corp-*" -ExcludePolicyName "Corp-Staging*"

        Converts all Corp- policies except Corp-Staging ones (exclude wins over include).

    .NOTES
        Author: Andres Canello
        Version: 1.0
        Date: 2026-03-06

        Requirements:
        - At least one of dns_policies.json or web_policies.json
        - destination_lists.json
        - category_settings.json (when using DNS policies)
        - CiscoUmbrella2EIA-CategoryMappings.csv
        - CiscoUmbrella2EIA-AppMappings.csv (when using Web policies)

        Known Limitations:
        - DNS policy identity assignment not available — all DNS policies assumed to apply to all users
        - Warn/isolate actions converted to Block with review flag
        - 300-character limit per FQDN RuleDestinations field
        - Application controls converted to FQDN-based rules (lossy conversion)
    #>

    [CmdletBinding(SupportsShouldProcess = $false)]
    param(
        [Parameter(HelpMessage = "Path to Cisco Umbrella DNS Policies JSON export. At least one of DnsPoliciesPath or WebPoliciesPath must be provided.")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$DnsPoliciesPath,

        [Parameter(HelpMessage = "Path to Cisco Umbrella Web Policies JSON export. At least one of DnsPoliciesPath or WebPoliciesPath must be provided.")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$WebPoliciesPath,

        [Parameter(HelpMessage = "Path to Cisco Umbrella Destination Lists JSON export")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$DestinationListsPath = (Join-Path $PWD "destination_lists.json"),

        [Parameter(HelpMessage = "Path to Cisco Umbrella Category Settings JSON export")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$CategorySettingsPath = (Join-Path $PWD "category_settings.json"),

        [Parameter(HelpMessage = "Path to Umbrella to EIA category mappings CSV file")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$CategoryMappingsPath = (Join-Path $PWD "CiscoUmbrella2EIA-CategoryMappings.csv"),

        [Parameter(HelpMessage = "Path to Umbrella to EIA application mappings CSV file")]
        [ValidateScript({
            if (Test-Path $_) { return $true }
            else { throw "File not found: $_" }
        })]
        [string]$AppMappingsPath = (Join-Path $PWD "CiscoUmbrella2EIA-AppMappings.csv"),

        [Parameter(HelpMessage = "Base directory for output files")]
        [ValidateScript({
            if (Test-Path $_ -PathType Container) { return $true }
            else { throw "Directory not found: $_" }
        })]
        [string]$OutputBasePath = $PWD,

        [Parameter(HelpMessage = "Policy name patterns to include. Supports wildcards. Case-insensitive.")]
        [string[]]$IncludePolicyName,

        [Parameter(HelpMessage = "Policy name patterns to exclude. Supports wildcards. Case-insensitive. Exclude wins over include.")]
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

    function Assert-ImportedCsvSchema {
        param(
            [Parameter(Mandatory)]
            [string]$CsvName,

            [AllowNull()]
            [object[]]$CsvRows,

            [Parameter(Mandatory)]
            [string[]]$RequiredColumns
        )

        if (@($CsvRows).Count -eq 0) {
            throw "$CsvName is empty"
        }

        $detectedColumns = @($CsvRows[0].PSObject.Properties.Name)
        $missingColumns = @($RequiredColumns | Where-Object { $detectedColumns -notcontains $_ })

        if ($missingColumns.Count -gt 0) {
            $detectedColumnsText = if ($detectedColumns.Count -gt 0) {
                $detectedColumns -join ', '
            }
            else {
                '<none>'
            }

            throw "Invalid ${CsvName}: missing required columns ($($missingColumns -join ', ')). Found columns: $detectedColumnsText"
        }
    }

    function ConvertTo-DualFqdnEntries {
        param([string]$Domain)

        $cleanDomain = $Domain.Trim().TrimEnd('.')

        if ([string]::IsNullOrWhiteSpace($cleanDomain)) { return @() }

        # If already a wildcard, return as-is
        if ($cleanDomain.StartsWith('*.')) {
            return @($cleanDomain)
        }

        return @($cleanDomain, "*.$cleanDomain")
    }

    function Resolve-CategoryMapping {
        param(
            [Parameter(Mandatory = $true)]
            [string]$CategoryName,

            [Parameter(Mandatory = $true)]
            [hashtable]$CategoryMappingsHashtable
        )

        $mapping = $CategoryMappingsHashtable[$CategoryName.ToLower()]

        if ($null -eq $mapping) {
            return @{
                GSACategory = "UNMAPPED:$CategoryName"
                IsMapped    = $false
                MappingType = 'NoMappingRow'
                LogMessage  = "Category '$CategoryName' not found in mapping file"
            }
        }

        if ([string]::IsNullOrWhiteSpace($mapping.GSACategory)) {
            return @{
                GSACategory = "UNMAPPED:$CategoryName"
                IsMapped    = $false
                MappingType = 'NoGSAValue'
                LogMessage  = "Category '$CategoryName' found in mapping file but GSACategory is empty, flagging for manual review"
            }
        }

        return @{
            GSACategory = $mapping.GSACategory
            IsMapped    = $true
            MappingType = 'Success'
            LogMessage  = "Category '$CategoryName' mapped to '$($mapping.GSACategory)'"
        }
    }

    function Resolve-AppMapping {
        param(
            [Parameter(Mandatory = $true)]
            [int]$AppId,

            [Parameter(Mandatory = $true)]
            [string]$AppName,

            [Parameter(Mandatory = $true)]
            [hashtable]$AppMappingsHashtable
        )

        $mapping = $AppMappingsHashtable[$AppId]

        if ($null -eq $mapping) {
            return @{
                GSAAppName  = $null
                Endpoints   = @()
                MatchType   = 'NotInFile'
                IsMapped    = $false
                LogMessage  = "Application '$AppName' (ID: $AppId) not found in app mapping file"
            }
        }

        if ([string]::IsNullOrWhiteSpace($mapping.GSAAppName) -or [string]::IsNullOrWhiteSpace($mapping.MatchType)) {
            return @{
                GSAAppName  = $null
                Endpoints   = @()
                MatchType   = 'NoMatch'
                IsMapped    = $false
                LogMessage  = "Application '$AppName' (ID: $AppId) found in mapping file but has no GSA match"
            }
        }

        $endpoints = @()
        if (-not [string]::IsNullOrWhiteSpace($mapping.GSAEndpoints)) {
            $endpoints = @($mapping.GSAEndpoints -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        }

        return @{
            GSAAppName  = $mapping.GSAAppName
            Endpoints   = $endpoints
            MatchType   = $mapping.MatchType
            IsMapped    = $true
            LogMessage  = "Application '$AppName' mapped to '$($mapping.GSAAppName)' ($($mapping.MatchType))"
        }
    }

    function Get-IdentityScopeKey {
        param(
            [array]$IdentityIds,
            [hashtable]$IdentityLookup
        )

        $resolvedNames = @()
        foreach ($id in $IdentityIds) {
            $identity = $IdentityLookup[$id]
            if ($null -ne $identity) {
                $resolvedNames += $identity.label
            }
            else {
                $resolvedNames += "Unknown_$id"
            }
        }

        return ($resolvedNames | Sort-Object) -join ";"
    }

    #endregion

    #region Initialization

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logPath = Join-Path $OutputBasePath "${timestamp}_Convert-CiscoUmbrella2EIA.log"
    $script:logPath = $logPath
    $script:EnableDebugLogging = $EnableDebugLogging

    Write-LogMessage "Convert-CiscoUmbrella2EIA started at $(Get-Date)" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Runtime validation: at least one of DnsPoliciesPath or WebPoliciesPath must be provided
    $hasDnsPolicies = -not [string]::IsNullOrWhiteSpace($DnsPoliciesPath)
    $hasWebPolicies = -not [string]::IsNullOrWhiteSpace($WebPoliciesPath)

    if (-not $hasDnsPolicies -and -not $hasWebPolicies) {
        Write-LogMessage "Neither DnsPoliciesPath nor WebPoliciesPath was provided. At least one is required." -Level "ERROR" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        throw "At least one of DnsPoliciesPath or WebPoliciesPath must be provided."
    }

    $inputMode = if ($hasDnsPolicies -and $hasWebPolicies) { "DNS + Web" }
                 elseif ($hasDnsPolicies) { "DNS only" }
                 else { "Web only" }
    Write-LogMessage "Input mode: $inputMode" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Log policy name filter if active
    $hasPolicyFilter = ($null -ne $IncludePolicyName -and $IncludePolicyName.Count -gt 0) -or ($null -ne $ExcludePolicyName -and $ExcludePolicyName.Count -gt 0)
    if ($hasPolicyFilter) {
        if ($null -ne $IncludePolicyName -and $IncludePolicyName.Count -gt 0) {
            Write-LogMessage "Policy name filter (include): $($IncludePolicyName -join ', ')" -Level "INFO" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
        if ($null -ne $ExcludePolicyName -and $ExcludePolicyName.Count -gt 0) {
            Write-LogMessage "Policy name filter (exclude): $($ExcludePolicyName -join ', ')" -Level "INFO" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
    }

    # Statistics tracking
    $stats = @{
        DnsPoliciesProcessed          = 0
        WebPoliciesProcessed          = 0
        WebRulesProcessed             = 0
        WebRulesSkippedDisabled       = 0
        CategoriesMapped              = 0
        UnmappedCategories_MissingInFile = 0
        UnmappedCategories_NoGSAValue = 0
        AppsMatchedExact              = 0
        AppsMatchedApproximate        = 0
        AppsUnmatched_NoMatch         = 0
        AppsUnmatched_NotInFile        = 0
        DestinationListsResolved      = 0
        TotalFqdnEntries              = 0
        IdentityScopesAll             = 0
        IdentityScopesSpecific        = 0
        UniqueIdentitySets            = 0
        PolicyRowsCreated             = 0
        PoliciesMergedDedup           = 0
        SecurityProfilesCreated       = 0
        RulesSplitForCharLimit        = 0
        DnsPoliciesSkippedByFilter    = 0
        WebPoliciesSkippedByFilter    = 0
    }

    # Collections for output
    $allPolicies = [System.Collections.ArrayList]::new()
    $identityScopedRules = @{}   # key = sorted identity set hash, value = { Groups, Users, Policies }
    $defaultScopePolicies = [System.Collections.ArrayList]::new()   # policy names for the Default Security Profile

    #endregion

    #region Phase 1: Data Loading

    Write-LogMessage "Phase 1: Loading input files..." -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Load DNS Policies (conditional)
    $dnsPolicies = $null
    if ($hasDnsPolicies) {
        try {
            Write-LogMessage "Loading DNS policies from: $DnsPoliciesPath" -Level "INFO" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $dnsPolicies = Get-Content -Path $DnsPoliciesPath -Raw | ConvertFrom-Json
            Write-LogMessage "Loaded $(@($dnsPolicies).Count) DNS policies" -Level "INFO" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
        catch {
            Write-LogMessage "Failed to load DNS policies: $_" -Level "ERROR" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            throw "Failed to load DNS policies file: $DnsPoliciesPath"
        }
    }

    # Load Web Policies (conditional)
    $webPolicies = $null
    if ($hasWebPolicies) {
        try {
            Write-LogMessage "Loading web policies from: $WebPoliciesPath" -Level "INFO" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $webPolicies = Get-Content -Path $WebPoliciesPath -Raw | ConvertFrom-Json
            Write-LogMessage "Loaded $(@($webPolicies).Count) web policies" -Level "INFO" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
        catch {
            Write-LogMessage "Failed to load web policies: $_" -Level "ERROR" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            throw "Failed to load web policies file: $WebPoliciesPath"
        }
    }

    # Load Destination Lists (always required)
    $destinationLists = $null
    try {
        Write-LogMessage "Loading destination lists from: $DestinationListsPath" -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        $destinationLists = Get-Content -Path $DestinationListsPath -Raw | ConvertFrom-Json
        Write-LogMessage "Loaded $(@($destinationLists).Count) destination lists" -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    catch {
        Write-LogMessage "Failed to load destination lists: $_" -Level "ERROR" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        throw "Failed to load destination lists file: $DestinationListsPath"
    }

    # Load Category Settings (required when DNS policies provided)
    $categorySettings = $null
    if ($hasDnsPolicies) {
        try {
            Write-LogMessage "Loading category settings from: $CategorySettingsPath" -Level "INFO" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $categorySettings = Get-Content -Path $CategorySettingsPath -Raw | ConvertFrom-Json
            Write-LogMessage "Loaded $(@($categorySettings).Count) category settings" -Level "INFO" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
        catch {
            Write-LogMessage "Failed to load category settings: $_" -Level "ERROR" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            throw "Failed to load category settings file: $CategorySettingsPath"
        }
    }

    # Load Category Mappings (always required)
    $categoryMappings = $null
    try {
        Write-LogMessage "Loading category mappings from: $CategoryMappingsPath" -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        $categoryMappings = Import-Csv -Path $CategoryMappingsPath -ErrorAction Stop
        Assert-ImportedCsvSchema -CsvName 'category mappings CSV' -CsvRows $categoryMappings -RequiredColumns @('UmbrellaCategory', 'GSACategory')
        Write-LogMessage "Loaded $($categoryMappings.Count) category mappings" -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    catch {
        Write-LogMessage "Failed to load category mappings: $_" -Level "ERROR" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        throw "Failed to load category mappings file '$CategoryMappingsPath': $($_.Exception.Message)"
    }

    # Load App Mappings (required when Web policies provided)
    $appMappings = $null
    if ($hasWebPolicies) {
        try {
            Write-LogMessage "Loading app mappings from: $AppMappingsPath" -Level "INFO" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            $appMappings = Import-Csv -Path $AppMappingsPath -ErrorAction Stop
            Assert-ImportedCsvSchema -CsvName 'app mappings CSV' -CsvRows $appMappings -RequiredColumns @('UmbrellaAppId', 'UmbrellaAppName', 'GSAAppName', 'MatchType', 'GSAEndpoints')
            Write-LogMessage "Loaded $($appMappings.Count) app mappings" -Level "INFO" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
        catch {
            Write-LogMessage "Failed to load app mappings: $_" -Level "ERROR" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            throw "Failed to load app mappings file '$AppMappingsPath': $($_.Exception.Message)"
        }
    }

    # Build lookup tables
    Write-LogMessage "Building lookup tables..." -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Destination lists: id -> list object
    $destinationListsHashtable = @{}
    foreach ($list in @($destinationLists)) {
        $destinationListsHashtable[$list.id] = $list
    }

    # Category settings: id -> setting object (when DNS policies provided)
    $categorySettingsHashtable = @{}
    if ($hasDnsPolicies -and $null -ne $categorySettings) {
        foreach ($setting in @($categorySettings)) {
            $categorySettingsHashtable[$setting.id] = $setting
        }
    }

    # Category mappings: UmbrellaCategory (lowercase) -> full row object
    $categoryMappingsHashtable = @{}
    $categoryMappingRowNumber = 1
    foreach ($mapping in $categoryMappings) {
        $umbrellaCategory = [string]$mapping.UmbrellaCategory

        if ([string]::IsNullOrWhiteSpace($umbrellaCategory)) {
            throw "Invalid category mappings CSV: row $($categoryMappingRowNumber + 1) has an empty UmbrellaCategory value."
        }

        $categoryKey = $umbrellaCategory.ToLower()
        if ($categoryMappingsHashtable.ContainsKey($categoryKey)) {
            throw "Invalid category mappings CSV: duplicate UmbrellaCategory '$umbrellaCategory' found at row $($categoryMappingRowNumber + 1)."
        }

        $categoryMappingsHashtable[$categoryKey] = $mapping
        $categoryMappingRowNumber++
    }

    # App mappings: UmbrellaAppId (int) -> CSV row object
    $appMappingsHashtable = @{}
    if ($hasWebPolicies -and $null -ne $appMappings) {
        $appMappingRowNumber = 1
        foreach ($row in $appMappings) {
            $parsedAppId = 0
            $umbrellaAppId = [string]$row.UmbrellaAppId

            if ([string]::IsNullOrWhiteSpace($umbrellaAppId)) {
                throw "Invalid app mappings CSV: row $($appMappingRowNumber + 1) has an empty UmbrellaAppId value."
            }

            if (-not [int]::TryParse($umbrellaAppId, [ref]$parsedAppId)) {
                throw "Invalid app mappings CSV: row $($appMappingRowNumber + 1) has a non-numeric UmbrellaAppId value '$umbrellaAppId'."
            }

            if ($appMappingsHashtable.ContainsKey($parsedAppId)) {
                throw "Invalid app mappings CSV: duplicate UmbrellaAppId '$parsedAppId' found at row $($appMappingRowNumber + 1)."
            }

            $appMappingsHashtable[$parsedAppId] = $row
            $appMappingRowNumber++
        }
    }

    Write-LogMessage "Lookup tables built: $($destinationListsHashtable.Count) destination lists, $($categorySettingsHashtable.Count) category settings, $($categoryMappingsHashtable.Count) category mappings, $($appMappingsHashtable.Count) app mappings" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Validate that at least some policies were loaded
    $totalPolicies = 0
    if ($hasDnsPolicies) { $totalPolicies += @($dnsPolicies).Count }
    if ($hasWebPolicies) { $totalPolicies += @($webPolicies).Count }
    if ($totalPolicies -eq 0) {
        Write-LogMessage "No policies found in the provided files." -Level "ERROR" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        throw "No policies found in the provided policy files."
    }

    #endregion

    #region Phase 2: DNS Policy Processing

    if ($hasDnsPolicies) {
        Write-LogMessage "Phase 2: Processing DNS policies..." -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

        foreach ($dnsPolicy in @($dnsPolicies)) {
            # Apply policy name filter
            if (-not (Test-PolicyNameFilter -PolicyName $dnsPolicy.name -IncludePatterns $IncludePolicyName -ExcludePatterns $ExcludePolicyName)) {
                Write-LogMessage "Skipping DNS policy '$($dnsPolicy.name)': excluded by policy name filter" -Level "INFO" `
                    -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                $stats.DnsPoliciesSkippedByFilter++
                continue
            }

            Write-LogMessage "Processing DNS policy: $($dnsPolicy.name) (priority: $($dnsPolicy.priority), identityCount: $($dnsPolicy.identityCount))" -Level "INFO" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

            # Process categorySetting
            if ($null -ne $dnsPolicy.categorySetting -and $null -ne $dnsPolicy.categorySetting.id) {
                $categorySettingId = $dnsPolicy.categorySetting.id
                $categorySetting = $categorySettingsHashtable[$categorySettingId]

                if ($null -ne $categorySetting -and $null -ne $categorySetting.categories -and @($categorySetting.categories).Count -gt 0) {
                    $mappedCategories = [System.Collections.ArrayList]::new()
                    $hasUnmapped = $false
                    $reviewReasons = [System.Collections.ArrayList]::new()

                    foreach ($category in $categorySetting.categories) {
                        $mappingResult = Resolve-CategoryMapping -CategoryName $category.name -CategoryMappingsHashtable $categoryMappingsHashtable

                        if ($mappingResult.IsMapped) {
                            [void]$mappedCategories.Add($mappingResult.GSACategory)
                            $stats.CategoriesMapped++
                        }
                        else {
                            [void]$mappedCategories.Add($mappingResult.GSACategory)
                            $hasUnmapped = $true
                            [void]$reviewReasons.Add($mappingResult.LogMessage)
                            if ($mappingResult.MappingType -eq 'NoMappingRow') {
                                $stats.UnmappedCategories_MissingInFile++
                            }
                            else {
                                $stats.UnmappedCategories_NoGSAValue++
                            }
                            Write-LogMessage "DNS policy '$($dnsPolicy.name)': $($mappingResult.LogMessage)" -Level "WARN" `
                                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                        }
                    }

                    $policyNameClean = $dnsPolicy.name -replace '\s+', '' -replace '[^a-zA-Z0-9_-]', ''
                    $policyName = "DNS-$policyNameClean-Categories-Block"

                    $policyEntry = [PSCustomObject]@{
                        PolicyName       = $policyName
                        PolicyType       = "WebContentFiltering"
                        PolicyAction     = "Block"
                        Description      = "Converted from Umbrella DNS policy: $($dnsPolicy.name)"
                        RuleType         = "webCategory"
                        RuleDestinations = $mappedCategories -join ";"
                        RuleName         = "WebCategories"
                        ReviewNeeded     = if ($hasUnmapped) { "Yes" } else { "No" }
                        ReviewDetails    = $reviewReasons -join "; "
                        Provision        = if ($hasUnmapped) { "no" } else { "yes" }
                    }

                    [void]$allPolicies.Add($policyEntry)
                    [void]$defaultScopePolicies.Add($policyName)
                }
                else {
                    Write-LogMessage "DNS policy '$($dnsPolicy.name)': Category setting ID $categorySettingId has no categories or not found" -Level "DEBUG" `
                        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                }
            }

            # Process domainlists
            if ($null -ne $dnsPolicy.domainlists) {
                foreach ($domainlistRef in $dnsPolicy.domainlists) {
                    $fullList = $destinationListsHashtable[$domainlistRef.id]

                    if ($null -eq $fullList -or $null -eq $fullList.destinations -or @($fullList.destinations).Count -eq 0) {
                        Write-LogMessage "Domain list $($domainlistRef.name) (ID: $($domainlistRef.id)) has no destinations, skipping" -Level "WARN" `
                            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                        continue
                    }

                    # Build FQDN entries with dual pattern
                    $fqdnEntries = [System.Collections.ArrayList]::new()
                    foreach ($dest in $fullList.destinations) {
                        if ($dest.type -eq "domain") {
                            $dualEntries = ConvertTo-DualFqdnEntries -Domain $dest.destination
                            foreach ($entry in $dualEntries) {
                                [void]$fqdnEntries.Add($entry)
                            }
                        }
                    }

                    if ($fqdnEntries.Count -eq 0) {
                        Write-LogMessage "Domain list $($domainlistRef.name): No valid domain entries after processing" -Level "WARN" `
                            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                        continue
                    }

                    $stats.DestinationListsResolved++
                    $stats.TotalFqdnEntries += $fqdnEntries.Count

                    $action = if ($domainlistRef.access -eq "allow") { "Allow" } else { "Block" }
                    $actionSuffix = if ($domainlistRef.access -eq "allow") { "Allow" } else { "Block" }
                    $listNameClean = $domainlistRef.name -replace '\s+', '' -replace '[^a-zA-Z0-9_-]', ''
                    $policyNameClean = $dnsPolicy.name -replace '\s+', '' -replace '[^a-zA-Z0-9_-]', ''
                    $policyName = "DNS-$policyNameClean-$listNameClean-$actionSuffix"

                    # Split by character limit if needed
                    $groups = Split-ByCharacterLimit -Entries @($fqdnEntries) -MaxLength 300

                    if ($groups.Count -gt 1) { $stats.RulesSplitForCharLimit++ }

                    for ($i = 0; $i -lt $groups.Count; $i++) {
                        $ruleName = if ($i -eq 0) { "FQDNs" } else { "FQDNs-$($i + 1)" }

                        $policyEntry = [PSCustomObject]@{
                            PolicyName       = $policyName
                            PolicyType       = "WebContentFiltering"
                            PolicyAction     = $action
                            Description      = "Converted from Umbrella DNS policy: $($dnsPolicy.name), list: $($domainlistRef.name)"
                            RuleType         = "FQDN"
                            RuleDestinations = $groups[$i] -join ";"
                            RuleName         = $ruleName
                            ReviewNeeded     = "No"
                            ReviewDetails    = ""
                            Provision        = "yes"
                        }

                        [void]$allPolicies.Add($policyEntry)
                    }

                    [void]$defaultScopePolicies.Add($policyName)
                }
            }

            # Log warnings for bypassed settings
            if ($dnsPolicy.PSObject.Properties.Name -contains 'securitySetting' -and $null -ne $dnsPolicy.securitySetting) {
                Write-LogMessage "DNS policy '$($dnsPolicy.name)': Security settings detected. Threat Intelligence policies should be configured in Entra Internet Access." -Level "WARN" `
                    -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            }
            if ($dnsPolicy.PSObject.Properties.Name -contains 'fileInspectionSetting' -and $null -ne $dnsPolicy.fileInspectionSetting) {
                Write-LogMessage "DNS policy '$($dnsPolicy.name)': File inspection settings detected. File Policies should be configured in Entra Internet Access." -Level "WARN" `
                    -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            }
            if ($dnsPolicy.PSObject.Properties.Name -contains 'settingGroupBypassInspectionGroup' -and $null -ne $dnsPolicy.settingGroupBypassInspectionGroup) {
                Write-LogMessage "DNS policy '$($dnsPolicy.name)': TLS inspection bypass settings detected. TLS Inspection Policy should be reviewed and configured in Entra Internet Access." -Level "WARN" `
                    -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            }

            $stats.DnsPoliciesProcessed++
        }

        Write-LogMessage "DNS policies processed: $($stats.DnsPoliciesProcessed)" -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    else {
        Write-LogMessage "Phase 2: Skipped — DNS policies not provided" -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    #endregion

    #region Phase 3: Web Policy Processing

    if ($hasWebPolicies) {
        Write-LogMessage "Phase 3: Processing web policies..." -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

        foreach ($webPolicy in @($webPolicies)) {
            # Apply policy name filter
            if (-not (Test-PolicyNameFilter -PolicyName $webPolicy.name -IncludePatterns $IncludePolicyName -ExcludePatterns $ExcludePolicyName)) {
                Write-LogMessage "Skipping web policy '$($webPolicy.name)': excluded by policy name filter" -Level "INFO" `
                    -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                $stats.WebPoliciesSkippedByFilter++
                continue
            }

            Write-LogMessage "Processing web policy: $($webPolicy.name) (ID: $($webPolicy.id), priority: $($webPolicy.priority))" -Level "INFO" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

            # Build extradata lookup tables for this web policy
            $identityLookup = @{}
            if ($null -ne $webPolicy.proxyRuleset -and $null -ne $webPolicy.proxyRuleset.extradata) {
                if ($null -ne $webPolicy.proxyRuleset.extradata.identities) {
                    foreach ($identity in $webPolicy.proxyRuleset.extradata.identities) {
                        $identityLookup[$identity.id] = $identity
                    }
                }
            }

            $appLookup = @{}
            if ($null -ne $webPolicy.proxyRuleset -and $null -ne $webPolicy.proxyRuleset.extradata) {
                if ($null -ne $webPolicy.proxyRuleset.extradata.applications) {
                    foreach ($app in $webPolicy.proxyRuleset.extradata.applications) {
                        $appLookup[$app.id] = $app
                    }
                }
            }

            $categoryLookup = @{}
            if ($null -ne $webPolicy.proxyRuleset -and $null -ne $webPolicy.proxyRuleset.extradata) {
                if ($null -ne $webPolicy.proxyRuleset.extradata.categories) {
                    foreach ($cat in $webPolicy.proxyRuleset.extradata.categories) {
                        $categoryLookup[$cat.id] = $cat
                    }
                }
            }

            $destListLookup = @{}
            if ($null -ne $webPolicy.proxyRuleset -and $null -ne $webPolicy.proxyRuleset.extradata) {
                if ($null -ne $webPolicy.proxyRuleset.extradata.destinationLists) {
                    foreach ($dl in $webPolicy.proxyRuleset.extradata.destinationLists) {
                        $destListLookup[$dl.id] = $dl
                    }
                }
            }

            # Process rules
            if ($null -eq $webPolicy.proxyRuleset -or $null -eq $webPolicy.proxyRuleset.rules) {
                Write-LogMessage "Web policy '$($webPolicy.name)': No proxy ruleset rules found" -Level "WARN" `
                    -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                $stats.WebPoliciesProcessed++
                continue
            }

            foreach ($rule in $webPolicy.proxyRuleset.rules) {
                # Skip disabled rules
                if ($rule.ruleIsEnabled -eq $false) {
                    Write-LogMessage "Skipping disabled rule: $($rule.ruleName) (ID: $($rule.ruleId))" -Level "DEBUG" `
                        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                    $stats.WebRulesSkippedDisabled++
                    continue
                }

                Write-LogMessage "Processing web rule: $($rule.ruleName) (action: $($rule.ruleAction), priority: $($rule.rulePriority))" -Level "DEBUG" `
                    -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

                # Parse rule conditions
                $identityScope = "all"
                $identityIds = @()
                $applicationIds = @()
                $destinationListIds = @()
                $contentCategoryIds = @()

                if ($null -ne $rule.ruleConditions) {
                    foreach ($condition in $rule.ruleConditions) {
                        switch ($condition.attributeName) {
                            "umbrella.source.all_policy_identities" {
                                $identityScope = "all"
                            }
                            "umbrella.source.identity_ids" {
                                $identityScope = "specific"
                                $identityIds = @($condition.attributeValue)
                            }
                            "umbrella.destination.application_ids" {
                                $applicationIds = @($condition.attributeValue)
                            }
                            "umbrella.destination.destination_list_ids" {
                                $destinationListIds = @($condition.attributeValue)
                            }
                            "umbrella.destination.content_category_ids" {
                                $contentCategoryIds = @($condition.attributeValue)
                            }
                            "umbrella.bundle_id" {
                                # Internal scoping, skip
                            }
                        }
                    }
                }

                # Determine EIA action
                $eiaAction = switch ($rule.ruleAction) {
                    "block"   { "Block" }
                    "allow"   { "Allow" }
                    "warn"    { "Block" }
                    "isolate" { "Block" }
                    default   { "Block" }
                }

                # Track generated policy names for this rule (for identity scope routing)
                $rulePolicyNames = [System.Collections.ArrayList]::new()

                # 3.3 Convert Application-Based Conditions
                if ($applicationIds.Count -gt 0) {
                    $allEndpoints = [System.Collections.ArrayList]::new()
                    $unmappedApps = [System.Collections.ArrayList]::new()
                    $appReviewReasons = [System.Collections.ArrayList]::new()

                    foreach ($appId in $applicationIds) {
                        $umbrellaApp = $appLookup[$appId]
                        if ($null -eq $umbrellaApp) {
                            Write-LogMessage "Application ID $appId not found in Web Policy lookup, possibly due to missing or outdated data." -Level "WARN" `
                                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                            [void]$appReviewReasons.Add("Unknown application ID: $appId")
                            continue
                        }

                        $appName = $umbrellaApp.label
                        $appMatch = Resolve-AppMapping -AppId $appId -AppName $appName -AppMappingsHashtable $appMappingsHashtable

                        if ($appMatch.IsMapped) {
                            if ($appMatch.Endpoints.Count -gt 0) {
                                foreach ($endpoint in $appMatch.Endpoints) {
                                    $dualEntries = ConvertTo-DualFqdnEntries -Domain $endpoint
                                    foreach ($entry in $dualEntries) {
                                        [void]$allEndpoints.Add($entry)
                                    }
                                }
                            }
                            else {
                                Write-LogMessage "Application '$appName' mapped to '$($appMatch.GSAAppName)' but has no endpoints in mapping file" -Level "WARN" `
                                    -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                                [void]$unmappedApps.Add("UNMAPPED:$appName")
                                [void]$appReviewReasons.Add("App '$appName' mapped to '$($appMatch.GSAAppName)' but has no endpoints")
                            }

                            if ($appMatch.MatchType -eq 'Exact') {
                                $stats.AppsMatchedExact++
                            }
                            else {
                                $stats.AppsMatchedApproximate++
                            }

                            Write-LogMessage $appMatch.LogMessage -Level "DEBUG" `
                                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                        }
                        else {
                            [void]$unmappedApps.Add("UNMAPPED:$appName")
                            [void]$appReviewReasons.Add($appMatch.LogMessage)
                            $appMatchLogLevel = if ($appMatch.MatchType -eq 'NoMatch') { 'DEBUG' } else { 'WARN' }
                            Write-LogMessage $appMatch.LogMessage -Level $appMatchLogLevel `
                                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                            if ($appMatch.MatchType -eq 'NotInFile') {
                                $stats.AppsUnmatched_NotInFile++
                            }
                            else {
                                $stats.AppsUnmatched_NoMatch++
                            }
                        }
                    }

                    if ($allEndpoints.Count -gt 0 -or $unmappedApps.Count -gt 0) {
                        $ruleNameClean = $rule.ruleName -replace '\s+', '' -replace '[^a-zA-Z0-9_-]', ''
                        $policyName = "Web-$ruleNameClean-Apps-$eiaAction"
                        $hasReview = $appReviewReasons.Count -gt 0

                        if ($rule.ruleAction -eq "warn") {
                            [void]$appReviewReasons.Add("Original action was 'warn' (user click-through) - converted to Block")
                            $hasReview = $true
                        }
                        if ($rule.ruleAction -eq "isolate") {
                            [void]$appReviewReasons.Add("Original action was 'isolate' (remote browser isolation) - converted to Block")
                            $hasReview = $true
                        }

                        $stats.TotalFqdnEntries += $allEndpoints.Count

                        # Combine real endpoints and unmapped app placeholders
                        $allRuleDestinations = [System.Collections.ArrayList]::new()
                        foreach ($ep in $allEndpoints) { [void]$allRuleDestinations.Add($ep) }
                        foreach ($ua in $unmappedApps) { [void]$allRuleDestinations.Add($ua) }

                        $groups = Split-ByCharacterLimit -Entries @($allRuleDestinations) -MaxLength 300
                        if ($groups.Count -gt 1) { $stats.RulesSplitForCharLimit++ }

                        # Has unmapped apps means review needed
                        $hasUnmappedApps = $unmappedApps.Count -gt 0

                        for ($i = 0; $i -lt $groups.Count; $i++) {
                            $ruleSuffix = if ($i -eq 0) { "FQDNs" } else { "FQDNs-$($i + 1)" }

                            $policyEntry = [PSCustomObject]@{
                                PolicyName       = $policyName
                                PolicyType       = "WebContentFiltering"
                                PolicyAction     = $eiaAction
                                Description      = "Converted from Umbrella web rule: $($rule.ruleName)"
                                RuleType         = "FQDN"
                                RuleDestinations = $groups[$i] -join ";"
                                RuleName         = $ruleSuffix
                                ReviewNeeded     = if ($hasUnmappedApps) { "Yes" } else { "No" }
                                ReviewDetails    = $appReviewReasons -join "; "
                                Provision        = if ($hasUnmappedApps) { "no" } else { "yes" }
                            }

                            [void]$allPolicies.Add($policyEntry)
                        }

                        [void]$rulePolicyNames.Add($policyName)
                    }
                }

                # 3.4 Convert Destination List Conditions
                if ($destinationListIds.Count -gt 0) {
                    foreach ($listId in $destinationListIds) {
                        $fullList = $destinationListsHashtable[$listId]

                        if ($null -eq $fullList) {
                            Write-LogMessage "Destination list ID $listId not found" -Level "WARN" `
                                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                            continue
                        }

                        if ($null -eq $fullList.destinations -or @($fullList.destinations).Count -eq 0) {
                            Write-LogMessage "Destination list $($fullList.name) has no entries, skipping" -Level "WARN" `
                                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                            continue
                        }

                        # Build FQDN entries with dual pattern
                        $fqdnEntries = [System.Collections.ArrayList]::new()
                        foreach ($dest in $fullList.destinations) {
                            if ($dest.type -eq "domain") {
                                $dualEntries = ConvertTo-DualFqdnEntries -Domain $dest.destination
                                foreach ($entry in $dualEntries) {
                                    [void]$fqdnEntries.Add($entry)
                                }
                            }
                        }

                        if ($fqdnEntries.Count -eq 0) {
                            Write-LogMessage "Destination list $($fullList.name): No valid domain entries" -Level "WARN" `
                                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                            continue
                        }

                        $stats.DestinationListsResolved++
                        $stats.TotalFqdnEntries += $fqdnEntries.Count

                        $listNameClean = $fullList.name -replace '\s+', '' -replace '[^a-zA-Z0-9_-]', ''
                        $ruleNameClean = $rule.ruleName -replace '\s+', '' -replace '[^a-zA-Z0-9_-]', ''
                        $policyName = "Web-$ruleNameClean-$listNameClean-$eiaAction"

                        $destReviewReasons = [System.Collections.ArrayList]::new()
                        if ($rule.ruleAction -eq "warn") {
                            [void]$destReviewReasons.Add("Original action was 'warn' - converted to Block")
                        }
                        if ($rule.ruleAction -eq "isolate") {
                            [void]$destReviewReasons.Add("Original action was 'isolate' - converted to Block")
                        }
                        $hasReview = $destReviewReasons.Count -gt 0

                        $dlGroups = Split-ByCharacterLimit -Entries @($fqdnEntries) -MaxLength 300
                        if ($dlGroups.Count -gt 1) { $stats.RulesSplitForCharLimit++ }

                        for ($i = 0; $i -lt $dlGroups.Count; $i++) {
                            $ruleSuffix = if ($i -eq 0) { "FQDNs" } else { "FQDNs-$($i + 1)" }

                            $policyEntry = [PSCustomObject]@{
                                PolicyName       = $policyName
                                PolicyType       = "WebContentFiltering"
                                PolicyAction     = $eiaAction
                                Description      = "Converted from Umbrella web rule: $($rule.ruleName), list: $($fullList.name)"
                                RuleType         = "FQDN"
                                RuleDestinations = $dlGroups[$i] -join ";"
                                RuleName         = $ruleSuffix
                                ReviewNeeded     = if ($hasReview) { "Yes" } else { "No" }
                                ReviewDetails    = $destReviewReasons -join "; "
                                Provision        = if ($hasReview) { "no" } else { "yes" }
                            }

                            [void]$allPolicies.Add($policyEntry)
                        }

                        [void]$rulePolicyNames.Add($policyName)
                    }
                }

                # 3.5 Convert Content Category Conditions
                if ($contentCategoryIds.Count -gt 0) {
                    $mappedCategories = [System.Collections.ArrayList]::new()
                    $catReviewReasons = [System.Collections.ArrayList]::new()

                    foreach ($catId in $contentCategoryIds) {
                        $umbrellaCat = $categoryLookup[$catId]
                        $catName = if ($null -ne $umbrellaCat) { $umbrellaCat.label } else { "UnknownCategory_$catId" }

                        $mappingResult = Resolve-CategoryMapping -CategoryName $catName -CategoryMappingsHashtable $categoryMappingsHashtable

                        if ($mappingResult.IsMapped) {
                            [void]$mappedCategories.Add($mappingResult.GSACategory)
                            $stats.CategoriesMapped++
                        }
                        else {
                            [void]$mappedCategories.Add($mappingResult.GSACategory)
                            [void]$catReviewReasons.Add($mappingResult.LogMessage)
                            if ($mappingResult.MappingType -eq 'NoMappingRow') {
                                $stats.UnmappedCategories_MissingInFile++
                            }
                            else {
                                $stats.UnmappedCategories_NoGSAValue++
                            }
                            Write-LogMessage "Web rule '$($rule.ruleName)': $($mappingResult.LogMessage)" -Level "WARN" `
                                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                        }
                    }

                    if ($mappedCategories.Count -gt 0) {
                        $ruleNameClean = $rule.ruleName -replace '\s+', '' -replace '[^a-zA-Z0-9_-]', ''
                        $policyName = "Web-$ruleNameClean-Categories-$eiaAction"

                        if ($rule.ruleAction -eq "warn") {
                            [void]$catReviewReasons.Add("Original action was 'warn' - converted to Block")
                        }
                        if ($rule.ruleAction -eq "isolate") {
                            [void]$catReviewReasons.Add("Original action was 'isolate' - converted to Block")
                        }
                        $hasReview = $catReviewReasons.Count -gt 0

                        $policyEntry = [PSCustomObject]@{
                            PolicyName       = $policyName
                            PolicyType       = "WebContentFiltering"
                            PolicyAction     = $eiaAction
                            Description      = "Converted from Umbrella web rule: $($rule.ruleName)"
                            RuleType         = "webCategory"
                            RuleDestinations = $mappedCategories -join ";"
                            RuleName         = "WebCategories"
                            ReviewNeeded     = if ($hasReview) { "Yes" } else { "No" }
                            ReviewDetails    = $catReviewReasons -join "; "
                            Provision        = if ($hasReview) { "no" } else { "yes" }
                        }

                        [void]$allPolicies.Add($policyEntry)
                        [void]$rulePolicyNames.Add($policyName)
                    }
                }

                # 3.6 Identity Scope Routing
                foreach ($policyName in $rulePolicyNames) {
                    if ($identityScope -eq "all") {
                        [void]$defaultScopePolicies.Add($policyName)
                        $stats.IdentityScopesAll++
                    }
                    else {
                        # Resolve identity IDs to names
                        $resolvedGroups = [System.Collections.ArrayList]::new()
                        $resolvedUsers = [System.Collections.ArrayList]::new()

                        foreach ($idVal in $identityIds) {
                            $identity = $identityLookup[$idVal]
                            if ($null -ne $identity) {
                                if ($identity.type -eq 3) {
                                    # AD Group - extract group name from label
                                    $groupName = $identity.label -replace '\s*\(.*\)$', ''
                                    [void]$resolvedGroups.Add($groupName)
                                }
                                elseif ($identity.type -eq 7) {
                                    # AD User - extract UPN from label
                                    if ($identity.label -match '\(([^)]+@[^)]+)\)') {
                                        [void]$resolvedUsers.Add($Matches[1])
                                    }
                                    else {
                                        [void]$resolvedUsers.Add($identity.label)
                                    }
                                }
                            }
                            else {
                                Write-LogMessage "Identity ID $idVal not found in Web Policy lookup, possibly due to missing or outdated data." -Level "WARN" `
                                    -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
                            }
                        }

                        # Create a unique key for this identity set
                        $identityKey = ((@($resolvedGroups) + @($resolvedUsers)) | Sort-Object) -join ";"

                        if (-not $identityScopedRules.ContainsKey($identityKey)) {
                            $identityScopedRules[$identityKey] = @{
                                Groups   = @($resolvedGroups)
                                Users    = @($resolvedUsers)
                                Policies = [System.Collections.ArrayList]::new()
                            }
                        }

                        [void]$identityScopedRules[$identityKey].Policies.Add($policyName)
                        $stats.IdentityScopesSpecific++
                    }
                }

                $stats.WebRulesProcessed++
            }

            # Log warnings for bypassed settings at policy level
            if ($webPolicy.PSObject.Properties.Name -contains 'securitySetting' -and $null -ne $webPolicy.securitySetting) {
                Write-LogMessage "Web policy '$($webPolicy.name)': Security settings detected. Threat Intelligence policies should be configured in Entra Internet Access." -Level "WARN" `
                    -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            }
            if ($webPolicy.PSObject.Properties.Name -contains 'fileInspectionSetting' -and $null -ne $webPolicy.fileInspectionSetting) {
                Write-LogMessage "Web policy '$($webPolicy.name)': File inspection settings detected. File Policies should be configured in Entra Internet Access." -Level "WARN" `
                    -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            }
            if ($webPolicy.PSObject.Properties.Name -contains 'settingGroupBypassInspectionGroup' -and $null -ne $webPolicy.settingGroupBypassInspectionGroup) {
                Write-LogMessage "Web policy '$($webPolicy.name)': TLS inspection bypass settings detected. TLS Inspection Policy should be reviewed and configured in Entra Internet Access." -Level "WARN" `
                    -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
            }

            $stats.WebPoliciesProcessed++
        }

        Write-LogMessage "Web policies processed: $($stats.WebPoliciesProcessed), rules processed: $($stats.WebRulesProcessed), rules skipped (disabled): $($stats.WebRulesSkippedDisabled)" -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    else {
        Write-LogMessage "Phase 3: Skipped — Web policies not provided" -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    #endregion

    #region Phase 4: Deduplication and Merging

    Write-LogMessage "Phase 4: Deduplication and merging..." -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Helper: merge policies of given RuleType and PolicyAction within a scope
    function Invoke-MergePolicies {
        param(
            [System.Collections.ArrayList]$AllPolicies,
            [System.Collections.ArrayList]$ScopePolicies,
            [string]$RuleType,
            [string]$PolicyAction,
            [string]$MergedPolicyName,
            [string]$Description
        )

        # Find candidate policies: those in this scope with matching rule type and action
        $candidates = @($AllPolicies | Where-Object {
            $_.PolicyName -in @($ScopePolicies) -and
            $_.RuleType -eq $RuleType -and
            $_.PolicyAction -eq $PolicyAction
        })

        if ($candidates.Count -le 1) { return }

        Write-LogMessage "Merging $($candidates.Count) $RuleType/$PolicyAction policies into '$MergedPolicyName'" -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

        if ($RuleType -eq "webCategory") {
            # Merge all webCategory destinations
            $allCategories = [System.Collections.ArrayList]::new()
            $allReviewReasons = [System.Collections.ArrayList]::new()

            foreach ($policy in $candidates) {
                $categories = $policy.RuleDestinations -split ";"
                foreach ($cat in $categories) { [void]$allCategories.Add($cat) }
                if (-not [string]::IsNullOrWhiteSpace($policy.ReviewDetails)) {
                    $reasons = $policy.ReviewDetails -split "; "
                    foreach ($r in $reasons) { [void]$allReviewReasons.Add($r) }
                }
            }

            $uniqueCategories = @($allCategories | Select-Object -Unique)
            $uniqueReviewReasons = @($allReviewReasons | Select-Object -Unique)
            $hasReview = $uniqueReviewReasons.Count -gt 0

            # Remove individual candidate policies from allPolicies
            $candidatePolicyNames = @($candidates | ForEach-Object { $_.PolicyName } | Select-Object -Unique)
            $toRemove = @($AllPolicies | Where-Object { $_.PolicyName -in $candidatePolicyNames -and $_.RuleType -eq $RuleType -and $_.PolicyAction -eq $PolicyAction })
            foreach ($item in $toRemove) { [void]$AllPolicies.Remove($item) }

            # Remove from scope policies and add merged name
            $namesToRemove = $candidatePolicyNames
            $indicesToRemove = @()
            for ($idx = $ScopePolicies.Count - 1; $idx -ge 0; $idx--) {
                if ($ScopePolicies[$idx] -in $namesToRemove) {
                    $indicesToRemove += $idx
                }
            }
            foreach ($idx in $indicesToRemove) { $ScopePolicies.RemoveAt($idx) }

            $mergedPolicy = [PSCustomObject]@{
                PolicyName       = $MergedPolicyName
                PolicyType       = "WebContentFiltering"
                PolicyAction     = $PolicyAction
                Description      = $Description
                RuleType         = "webCategory"
                RuleDestinations = $uniqueCategories -join ";"
                RuleName         = "WebCategories"
                ReviewNeeded     = if ($hasReview) { "Yes" } else { "No" }
                ReviewDetails    = $uniqueReviewReasons -join "; "
                Provision        = if ($hasReview) { "no" } else { "yes" }
            }

            [void]$AllPolicies.Add($mergedPolicy)
            [void]$ScopePolicies.Add($MergedPolicyName)
            $stats.PoliciesMergedDedup += $candidates.Count - 1
        }
        elseif ($RuleType -eq "FQDN") {
            # Merge all FQDN destinations
            $allFqdns = [System.Collections.ArrayList]::new()

            foreach ($policy in $candidates) {
                $fqdns = $policy.RuleDestinations -split ";"
                foreach ($f in $fqdns) { [void]$allFqdns.Add($f) }
            }

            $uniqueFqdns = @($allFqdns | Select-Object -Unique)

            # Remove individual candidate policies from allPolicies
            $candidatePolicyNames = @($candidates | ForEach-Object { $_.PolicyName } | Select-Object -Unique)
            $toRemove = @($AllPolicies | Where-Object { $_.PolicyName -in $candidatePolicyNames -and $_.RuleType -eq $RuleType -and $_.PolicyAction -eq $PolicyAction })
            foreach ($item in $toRemove) { [void]$AllPolicies.Remove($item) }

            # Remove from scope policies and add merged name
            $namesToRemove = $candidatePolicyNames
            $indicesToRemove = @()
            for ($idx = $ScopePolicies.Count - 1; $idx -ge 0; $idx--) {
                if ($ScopePolicies[$idx] -in $namesToRemove) {
                    $indicesToRemove += $idx
                }
            }
            foreach ($idx in $indicesToRemove) { $ScopePolicies.RemoveAt($idx) }

            # Group FQDNs by base domain for meaningful rule names
            $fqdnsByBaseDomain = @{}
            foreach ($fqdn in $uniqueFqdns) {
                $baseDomain = Get-BaseDomain -Domain $fqdn
                if (-not $fqdnsByBaseDomain.ContainsKey($baseDomain)) {
                    $fqdnsByBaseDomain[$baseDomain] = [System.Collections.ArrayList]::new()
                }
                [void]$fqdnsByBaseDomain[$baseDomain].Add($fqdn)
            }

            # Create policy entries for each base domain group, split by character limit
            foreach ($baseDomain in $fqdnsByBaseDomain.Keys | Sort-Object) {
                $splitGroups = Split-ByCharacterLimit -Entries @($fqdnsByBaseDomain[$baseDomain]) -MaxLength 300

                for ($i = 0; $i -lt $splitGroups.Count; $i++) {
                    $ruleName = if ($i -eq 0) { $baseDomain } else { "$baseDomain-$($i + 1)" }

                    $policyEntry = [PSCustomObject]@{
                        PolicyName       = $MergedPolicyName
                        PolicyType       = "WebContentFiltering"
                        PolicyAction     = $PolicyAction
                        Description      = $Description
                        RuleType         = "FQDN"
                        RuleDestinations = $splitGroups[$i] -join ";"
                        RuleName         = $ruleName
                        ReviewNeeded     = "No"
                        ReviewDetails    = ""
                        Provision        = "yes"
                    }

                    [void]$AllPolicies.Add($policyEntry)
                }
            }

            [void]$ScopePolicies.Add($MergedPolicyName)
            $stats.PoliciesMergedDedup += $candidates.Count - 1
        }
    }

    # Merge default scope policies
    Invoke-MergePolicies -AllPolicies $allPolicies -ScopePolicies $defaultScopePolicies `
        -RuleType "webCategory" -PolicyAction "Block" `
        -MergedPolicyName "Default-Categories-Block" -Description "Merged category blocks from DNS and web policies"

    Invoke-MergePolicies -AllPolicies $allPolicies -ScopePolicies $defaultScopePolicies `
        -RuleType "webCategory" -PolicyAction "Allow" `
        -MergedPolicyName "Default-Categories-Allow" -Description "Merged category allows from DNS and web policies"

    Invoke-MergePolicies -AllPolicies $allPolicies -ScopePolicies $defaultScopePolicies `
        -RuleType "FQDN" -PolicyAction "Block" `
        -MergedPolicyName "Default-Destinations-Block" -Description "Merged FQDN blocks from DNS and web policies"

    Invoke-MergePolicies -AllPolicies $allPolicies -ScopePolicies $defaultScopePolicies `
        -RuleType "FQDN" -PolicyAction "Allow" `
        -MergedPolicyName "Default-Destinations-Allow" -Description "Merged FQDN allows from DNS and web policies"

    # Merge override scope policies
    foreach ($identityKey in $identityScopedRules.Keys) {
        $scopeData = $identityScopedRules[$identityKey]
        $overrideScopePolicies = $scopeData.Policies

        # Build a label for merged policy names
        $groupLabel = if ($scopeData.Groups.Count -gt 0) {
            ($scopeData.Groups | Select-Object -First 2) -join "-"
        }
        elseif ($scopeData.Users.Count -gt 0) {
            "Users-$($scopeData.Users.Count)"
        }
        else { "Unknown" }
        $groupLabelClean = $groupLabel -replace '\s+', '' -replace '[^a-zA-Z0-9_-]', ''

        Invoke-MergePolicies -AllPolicies $allPolicies -ScopePolicies $overrideScopePolicies `
            -RuleType "webCategory" -PolicyAction "Block" `
            -MergedPolicyName "Override-$groupLabelClean-Categories-Block" -Description "Merged category blocks for override: $groupLabel"

        Invoke-MergePolicies -AllPolicies $allPolicies -ScopePolicies $overrideScopePolicies `
            -RuleType "webCategory" -PolicyAction "Allow" `
            -MergedPolicyName "Override-$groupLabelClean-Categories-Allow" -Description "Merged category allows for override: $groupLabel"

        Invoke-MergePolicies -AllPolicies $allPolicies -ScopePolicies $overrideScopePolicies `
            -RuleType "FQDN" -PolicyAction "Block" `
            -MergedPolicyName "Override-$groupLabelClean-Destinations-Block" -Description "Merged FQDN blocks for override: $groupLabel"

        Invoke-MergePolicies -AllPolicies $allPolicies -ScopePolicies $overrideScopePolicies `
            -RuleType "FQDN" -PolicyAction "Allow" `
            -MergedPolicyName "Override-$groupLabelClean-Destinations-Allow" -Description "Merged FQDN allows for override: $groupLabel"
    }

    Write-LogMessage "Deduplication complete. Policies merged: $($stats.PoliciesMergedDedup)" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    #endregion

    #region Phase 5: Security Profile Assembly

    Write-LogMessage "Phase 5: Assembling security profiles..." -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    $securityProfiles = [System.Collections.ArrayList]::new()

    # Create Default Security Profile
    $uniqueDefaultPolicies = @($defaultScopePolicies | Select-Object -Unique)

    if ($uniqueDefaultPolicies.Count -gt 0) {
        $linkPriority = 100
        $profileLinks = [System.Collections.ArrayList]::new()
        foreach ($policyName in $uniqueDefaultPolicies) {
            [void]$profileLinks.Add("${policyName}:${linkPriority}")
            $linkPriority += 100
        }

        $defaultProfile = [PSCustomObject]@{
            SecurityProfileName  = "Default-CiscoUmbrella"
            Priority             = 50000
            SecurityProfileLinks = $profileLinks -join ";"
            CADisplayName        = "CA-EIA-Default-CiscoUmbrella"
            EntraUsers           = ""
            EntraGroups          = "All Internet Access Users"
            Provision            = "yes"
        }

        [void]$securityProfiles.Add($defaultProfile)
    }

    # Create Override Security Profiles
    $overridePriority = 1000
    $stats.UniqueIdentitySets = $identityScopedRules.Keys.Count

    foreach ($identityKey in $identityScopedRules.Keys) {
        $scopeData = $identityScopedRules[$identityKey]

        # Deduplicate policy names for this scope
        $uniquePolicies = @($scopeData.Policies | Select-Object -Unique)

        # Build SecurityProfileLinks with priority numbering
        $linkPriority = 100
        $profileLinks = [System.Collections.ArrayList]::new()
        foreach ($policyName in $uniquePolicies) {
            [void]$profileLinks.Add("${policyName}:${linkPriority}")
            $linkPriority += 100
        }

        # Generate profile name from group names
        $groupLabel = if ($scopeData.Groups.Count -gt 0) {
            ($scopeData.Groups | Select-Object -First 2) -join "-"
        }
        elseif ($scopeData.Users.Count -gt 0) {
            "Users-$($scopeData.Users.Count)"
        }
        else { "Unknown" }

        $profileName = "Override-$groupLabel"

        $overrideProfile = [PSCustomObject]@{
            SecurityProfileName  = $profileName
            Priority             = $overridePriority
            SecurityProfileLinks = $profileLinks -join ";"
            CADisplayName        = "CA-EIA-$profileName"
            EntraUsers           = $scopeData.Users -join ";"
            EntraGroups          = $scopeData.Groups -join ";"
            Provision            = "yes"
        }

        [void]$securityProfiles.Add($overrideProfile)
        $overridePriority += 100
    }

    $stats.SecurityProfilesCreated = $securityProfiles.Count
    $stats.PolicyRowsCreated = $allPolicies.Count

    Write-LogMessage "Security profiles assembled: $($stats.SecurityProfilesCreated)" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    #endregion

    #region Phase 6: Export and Summary

    Write-LogMessage "Phase 6: Exporting results..." -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Export Policies CSV
    $policiesCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_Policies.csv"
    $allPolicies | Export-Csv -Path $policiesCsvPath -NoTypeInformation -Encoding utf8BOM
    Write-LogMessage "Exported $($allPolicies.Count) policy rows to: $policiesCsvPath" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Export Security Profiles CSV
    $spCsvPath = Join-Path $OutputBasePath "${timestamp}_EIA_SecurityProfiles.csv"
    $securityProfiles | Export-Csv -Path $spCsvPath -NoTypeInformation -Encoding utf8BOM
    Write-LogMessage "Exported $($securityProfiles.Count) security profiles to: $spCsvPath" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    # Count unique policies and category/FQDN breakdowns
    $uniquePolicyCount = ($allPolicies | Select-Object -Property PolicyName -Unique).Count
    $webCategoryPolicyCount = ($allPolicies | Where-Object { $_.RuleType -eq "webCategory" } | Select-Object -Property PolicyName -Unique).Count
    $fqdnPolicyCount = ($allPolicies | Where-Object { $_.RuleType -eq "FQDN" } | Select-Object -Property PolicyName -Unique).Count
    $overrideCount = $securityProfiles.Count - 1
    if ($overrideCount -lt 0) { $overrideCount = 0 }

    # Generate summary
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "=== CONVERSION SUMMARY ===" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Input mode: $inputMode" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    if ($hasPolicyFilter) {
        Write-LogMessage "Policy name filter active:" -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        if ($hasDnsPolicies) {
            Write-LogMessage "  - DNS policies skipped by filter: $($stats.DnsPoliciesSkippedByFilter)" -Level "INFO" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
        if ($hasWebPolicies) {
            Write-LogMessage "  - Web policies skipped by filter: $($stats.WebPoliciesSkippedByFilter)" -Level "INFO" `
                -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        }
    }

    if ($hasDnsPolicies) {
        Write-LogMessage "DNS policies processed: $($stats.DnsPoliciesProcessed)" -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    else {
        Write-LogMessage "DNS policies processed: N/A - DNS policies not provided" -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    if ($hasWebPolicies) {
        Write-LogMessage "Web policies processed: $($stats.WebPoliciesProcessed)" -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        Write-LogMessage "Web rules processed (enabled): $($stats.WebRulesProcessed)" -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
        Write-LogMessage "Web rules skipped (disabled): $($stats.WebRulesSkippedDisabled)" -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }
    else {
        Write-LogMessage "Web policies processed: N/A - Web policies not provided" -Level "INFO" `
            -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    }

    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Categories mapped: $($stats.CategoriesMapped)" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Unmapped categories:" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Missing in mapping file: $($stats.UnmappedCategories_MissingInFile)" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - No GSA category value: $($stats.UnmappedCategories_NoGSAValue)" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Applications matched (exact): $($stats.AppsMatchedExact)" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Applications matched (approximate): $($stats.AppsMatchedApproximate)" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Applications unmatched:" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - No match in mapping file: $($stats.AppsUnmatched_NoMatch)" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Missing from mapping file: $($stats.AppsUnmatched_NotInFile)" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Destination lists resolved: $($stats.DestinationListsResolved)" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Total FQDN entries generated: $($stats.TotalFqdnEntries)" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Policies created: $uniquePolicyCount" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - webCategory policies: $webCategoryPolicyCount" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - FQDN policies: $fqdnPolicyCount" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Security profiles created: $($stats.SecurityProfilesCreated)" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Default: 1" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Overrides: $overrideCount" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Policies merged during deduplication: $($stats.PoliciesMergedDedup)" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Rules split for character limit: $($stats.RulesSplitForCharLimit)" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Warnings:" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Configure Threat Intelligence policies in Entra Internet Access" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Configure File Policies in Entra Internet Access" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Review TLS Inspection Policy configuration in Entra Internet Access" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "Output files:" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Policies: $policiesCsvPath" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Security Profiles: $spCsvPath" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging
    Write-LogMessage "  - Log File: $logPath" -Level "INFO" `
        -Component "Convert-CiscoUmbrella2EIA" -LogPath $logPath -EnableDebugLogging:$EnableDebugLogging

    #endregion
}
