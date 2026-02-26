function Export-MDEWebFilteringConfig {
    <#
    .SYNOPSIS
        Exports Microsoft Defender for Endpoint web filtering configuration from a HAR file.

    .DESCRIPTION
        Extracts MDE web filtering configuration objects from an HTTP Archive (HAR) file captured
        while browsing the security.microsoft.com portal. Parses API responses from internal
        /apiproxy/mtp/ endpoints to reconstruct the configuration without requiring live API access.

        Extracts 4 object types: Web Content Filtering Policies, IP Indicators, URL/Domain Indicators,
        and Device Groups (Machine Groups).

        Alternatively, with -ExportCleanHAR, produces a sanitized copy of the HAR file suitable
        for sharing (sensitive headers removed, non-API entries stripped).

    .PARAMETER HARFilePath
        Absolute or relative path to the .har file captured from the MDE portal.

    .PARAMETER OutputDirectory
        Directory where the timestamped backup folder will be created. Defaults to current directory.

    .PARAMETER ExportCleanHAR
        When specified, only produces a sanitized copy of the HAR file and skips configuration extraction.

    .OUTPUTS
        System.Boolean
        Returns $true if export completed successfully, $false otherwise.

    .EXAMPLE
        Export-MDEWebFilteringConfig -HARFilePath "C:\captures\mde_portal.har"

        Basic usage — exports all configuration objects to the current directory.

    .EXAMPLE
        Export-MDEWebFilteringConfig -HARFilePath "C:\captures\mde_portal.har" -OutputDirectory "C:\Backups\MDE"

        Export with a custom output directory.

    .EXAMPLE
        Export-MDEWebFilteringConfig -HARFilePath "C:\captures\mde_portal.har" -ExportCleanHAR

        Produces only a sanitized HAR copy — no JSON extraction is performed.

    .NOTES
        Author: Andres Canello
        Date: February 26, 2026

        The MDE portal uses internal proxy API endpoints (/apiproxy/mtp/) that route to backend
        microservices. These endpoints are session-authenticated via the portal and are not part
        of the official public MDE API surface. Capturing a HAR file while browsing the relevant
        dashboard pages is the most reliable way to obtain the complete configuration data.

        Dependencies:
        - PowerShell 7.0 or higher
        - No external modules or network access required
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if (-not (Test-Path $_)) {
                throw "HAR file not found: $_"
            }
            if ([System.IO.Path]::GetExtension($_) -ne '.har') {
                throw "File must have a .har extension: $_"
            }
            $true
        })]
        [string]$HARFilePath,

        [Parameter(Mandatory = $false)]
        [string]$OutputDirectory = (Get-Location).Path,

        [Parameter(Mandatory = $false)]
        [switch]$ExportCleanHAR
    )

    # Set strict error handling
    $ErrorActionPreference = 'Stop'

    $script:LogPath = $null
    $script:EnableDebugLogging = $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Debug')

    #region Constants

    # MDE web category ID to name mapping (28 categories)
    $WebCategoryMap = @{
        7  = "Chat"
        12 = "Criminal activity"
        14 = "Download Sites"
        18 = "Gambling"
        19 = "Games"
        21 = "Hate & intolerance"
        23 = "Illegal drug"
        26 = "Streaming media & downloads"
        29 = "Nudity"
        33 = "Pornography/Sexually explicit"
        39 = "Social networking"
        46 = "Violence"
        47 = "Weapons"
        48 = "Web-based email"
        51 = "Parked Domains"
        52 = "Newly registered domains"
        62 = "Cults"
        65 = "Hacking"
        67 = "Illegal software"
        68 = "Image sharing"
        70 = "Instant messaging"
        73 = "Peer-to-peer"
        75 = "School cheating"
        76 = "Sex education"
        77 = "Tasteless"
        78 = "Child Abuse Images"
        84 = "Self-harm"
        92 = "Professional networking"
    }

    # Indicator action enum
    $IndicatorActionMap = @{
        0 = "AlertOnly"
        1 = "Allow"
        2 = "Block"
        4 = "Warn"
    }

    # Indicator severity enum
    $IndicatorSeverityMap = @{
        0 = "Informational"
        1 = "Low"
        2 = "Medium"
        3 = "High"
    }

    # Indicator type enum
    $IndicatorTypeMap = @{
        3 = "IP"
        4 = "URL"
        5 = "DomainURL"
    }

    # Auto-remediation level enum
    $AutoRemediationLevelMap = @{
        0 = "NoAutomatedResponse"
        1 = "SemiRequireApprovalAll"
        2 = "SemiRequireApprovalNonTemp"
        3 = "FullAutomated"
    }

    # GroupRules property enum
    $GroupRulesPropertyMap = @{
        0 = "MachineName"
        1 = "Domain"
        2 = "Tag"
        3 = "OS"
        4 = "Other"
    }

    #endregion Constants

    #region Internal Functions

    function Read-HARFile {
        <#
        .SYNOPSIS
            Reads and validates a HAR file, returning the parsed object.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [string]$Path
        )

        $resolvedPath = (Resolve-Path $Path).Path
        $fileInfo = Get-Item $resolvedPath
        $fileSizeMB = [math]::Round($fileInfo.Length / 1MB, 2)
        Write-LogMessage "Reading HAR file: $resolvedPath ($fileSizeMB MB)" -Level INFO -Component "HAR"

        try {
            $rawJson = [System.IO.File]::ReadAllText($resolvedPath)
        }
        catch {
            throw "Failed to read HAR file: $($_.Exception.Message)"
        }

        try {
            $har = $rawJson | ConvertFrom-Json
        }
        catch {
            throw "The file is not a valid HAR/JSON file: $($_.Exception.Message)"
        }
        finally {
            $rawJson = $null
        }

        if ($null -eq $har.log -or $null -eq $har.log.entries) {
            throw "The file does not appear to be a HAR file (missing log.entries)"
        }

        Write-LogMessage "HAR file parsed: $($har.log.entries.Count) total entries" -Level INFO -Component "HAR"
        return $har
    }

    function Get-HARApiEntries {
        <#
        .SYNOPSIS
            Filters HAR entries to relevant MDE API host and path with successful GET responses.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [object[]]$Entries
        )

        $filtered = $Entries | Where-Object {
            $_.request.method -eq 'GET' -and
            $_.response.status -eq 200 -and
            $_.response.content.text -and
            $(try {
                $uri = [System.Uri]::new($_.request.url)
                $uri.Host -eq 'security.microsoft.com' -and $uri.AbsolutePath -like '/apiproxy/mtp/*'
            } catch { $false })
        }

        if ($null -eq $filtered -or @($filtered).Count -eq 0) {
            throw "No MDE API requests found in the HAR file. Ensure the HAR was captured while browsing the MDE portal at security.microsoft.com"
        }

        $count = @($filtered).Count
        Write-LogMessage "Filtered to $count relevant API entries (security.microsoft.com/apiproxy/mtp/)" -Level INFO -Component "HAR"
        return @($filtered)
    }

    function Get-HARResponseByUrl {
        <#
        .SYNOPSIS
            Extracts parsed response data from HAR entries matching a URL pattern.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [object[]]$Entries,

            [Parameter(Mandatory = $true)]
            [string]$UrlPattern,

            [Parameter(Mandatory = $false)]
            [string]$QueryFilter,

            [Parameter(Mandatory = $false)]
            [switch]$All
        )

        $matched = $Entries | Where-Object {
            $_.request.url -match $UrlPattern -and
            (-not $QueryFilter -or $_.request.url -match $QueryFilter)
        }

        if ($null -eq $matched -or @($matched).Count -eq 0) {
            return $null
        }

        if ($All) {
            $results = @()
            foreach ($entry in @($matched)) {
                try {
                    $body = $entry.response.content.text
                    if ($entry.response.content.encoding -eq 'base64') {
                        $body = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($body))
                    }
                    $parsed = $body | ConvertFrom-Json
                    $results += $parsed
                }
                catch {
                    $url = $entry.request.url
                    Write-LogMessage "Could not parse response for $url — skipping" -Level WARN -Component "HAR"
                }
            }
            return $results
        }
        else {
            # Use the last successful response (handles browser retries/polling)
            $last = @($matched) | Select-Object -Last 1
            try {
                $body = $last.response.content.text
                if ($last.response.content.encoding -eq 'base64') {
                    $body = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($body))
                }
                return ($body | ConvertFrom-Json)
            }
            catch {
                $url = $last.request.url
                Write-LogMessage "Could not parse response for $url — skipping" -Level WARN -Component "HAR"
                return $null
            }
        }
    }

    function Get-HARTenantId {
        <#
        .SYNOPSIS
            Auto-detects the tenant ID from the x-tid or tenant-id request header.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [object[]]$Entries
        )

        $tenantId = $Entries | ForEach-Object {
            $tidHeader = $_.request.headers | Where-Object { $_.name -eq 'x-tid' }
            if ($tidHeader) { $tidHeader.value }
        } | Select-Object -First 1

        if (-not $tenantId) {
            # Fall back to tenant-id header
            $tenantId = $Entries | ForEach-Object {
                $tidHeader = $_.request.headers | Where-Object { $_.name -eq 'tenant-id' }
                if ($tidHeader) { $tidHeader.value }
            } | Select-Object -First 1
        }

        if (-not $tenantId) {
            throw "Could not detect tenant ID from HAR entries. Ensure the HAR was captured while browsing the MDE portal."
        }

        Write-LogMessage "Detected tenant ID: $tenantId" -Level INFO -Component "HAR"
        return $tenantId
    }

    function Export-CleanHARFile {
        <#
        .SYNOPSIS
            Sanitizes a HAR file by removing non-API entries and sensitive headers.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [object]$HarObject,

            [Parameter(Mandatory = $true)]
            [string]$OutputPath
        )

        Write-LogMessage "Sanitizing HAR file..." -Level INFO -Component "CleanHAR"

        $sensitiveHeaders = @('authorization', 'cookie', 'set-cookie', 'x-xsrf-token')

        # Filter entries to relevant API host and path
        $cleanEntries = @($HarObject.log.entries | Where-Object {
            try {
                $uri = [System.Uri]::new($_.request.url)
                $uri.Host -eq 'security.microsoft.com' -and $uri.AbsolutePath -like '/apiproxy/mtp/*'
            } catch { $false }
        })

        Write-LogMessage "Retained $($cleanEntries.Count) API entries (removed $(($HarObject.log.entries.Count) - $cleanEntries.Count) non-API entries)" -Level INFO -Component "CleanHAR"

        # Strip sensitive headers and cookies from each entry
        foreach ($entry in $cleanEntries) {
            if ($entry.request.headers) {
                $entry.request.headers = @($entry.request.headers | Where-Object {
                    $headerName = $_.name.ToLower()
                    $headerName -notin $sensitiveHeaders -and -not $headerName.StartsWith('x-auth')
                })
            }
            if ($entry.response.headers) {
                $entry.response.headers = @($entry.response.headers | Where-Object {
                    $headerName = $_.name.ToLower()
                    $headerName -notin $sensitiveHeaders -and -not $headerName.StartsWith('x-auth')
                })
            }
            # Clear cookies arrays
            if ($null -ne $entry.request.PSObject.Properties['cookies']) {
                $entry.request.cookies = @()
            }
            if ($null -ne $entry.response.PSObject.Properties['cookies']) {
                $entry.response.cookies = @()
            }
        }

        # Build clean HAR object preserving metadata
        $cleanHar = [PSCustomObject]@{
            log = [PSCustomObject]@{
                version = $HarObject.log.version
                creator = $HarObject.log.creator
                browser = $HarObject.log.browser
                pages   = $HarObject.log.pages
                entries = $cleanEntries
            }
        }

        $cleanJson = $cleanHar | ConvertTo-Json -Depth 20
        [System.IO.File]::WriteAllText($OutputPath, $cleanJson, [System.Text.Encoding]::UTF8)

        $fileSizeKB = [math]::Round((Get-Item $OutputPath).Length / 1KB, 2)
        Write-LogMessage "Clean HAR written: $OutputPath ($fileSizeKB KB)" -Level SUCCESS -Component "CleanHAR"
    }

    function Get-DeviceGroups {
        <#
        .SYNOPSIS
            Extracts Device Groups (Machine Groups) from HAR entries.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [object[]]$Entries
        )

        Write-LogMessage "Extracting Device Groups..." -Level INFO -Component "Export"

        $dgPattern = '/apiproxy/mtp/rbacManagementApi/rbac/machine_groups'

        # Prefer the variant with addAadGroupNames=true
        $response = Get-HARResponseByUrl -Entries $Entries -UrlPattern $dgPattern -QueryFilter 'addAadGroupNames=true'
        if ($null -eq $response) {
            $response = Get-HARResponseByUrl -Entries $Entries -UrlPattern $dgPattern
        }

        if ($null -eq $response) {
            Write-LogMessage "No Device Groups response found in HAR — skipping" -Level WARN -Component "Export"
            return @()
        }

        # Extract the items array from the wrapper object
        $groups = if ($response.items) { @($response.items) } else { @($response) }

        # Resolve enums to human-readable strings
        foreach ($group in $groups) {
            # AutoRemediationLevel
            if ($null -ne $group.AutoRemediationLevel -and $AutoRemediationLevelMap.ContainsKey([int]$group.AutoRemediationLevel)) {
                $group.AutoRemediationLevel = $AutoRemediationLevelMap[[int]$group.AutoRemediationLevel]
            }

            # GroupRules[].Property
            if ($group.GroupRules) {
                foreach ($rule in @($group.GroupRules)) {
                    if ($null -ne $rule.Property -and $GroupRulesPropertyMap.ContainsKey([int]$rule.Property)) {
                        $rule.Property = $GroupRulesPropertyMap[[int]$rule.Property]
                    }
                }
            }
        }

        $names = ($groups | ForEach-Object {
            $displayName = if ($_.IsUnassignedMachineGroup) { "$($_.Name) (unassigned)" } else { $_.Name }
            "         - $displayName"
        }) -join "`n"
        Write-LogMessage "Extracted $($groups.Count) device groups:`n$names" -Level SUCCESS -Component "Export"
        return $groups
    }

    function Get-WcfPolicies {
        <#
        .SYNOPSIS
            Extracts Web Content Filtering Policies from HAR entries.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [object[]]$Entries,

            [Parameter(Mandatory = $true)]
            [hashtable]$DeviceGroupLookup
        )

        Write-LogMessage "Extracting Web Content Filtering Policies..." -Level INFO -Component "Export"

        $wcfPattern = '/apiproxy/mtp/userRequests/webcategory/policies'
        $response = Get-HARResponseByUrl -Entries $Entries -UrlPattern $wcfPattern

        if ($null -eq $response) {
            Write-LogMessage "No WCF Policies response found in HAR — skipping" -Level WARN -Component "Export"
            return @()
        }

        $policies = @($response)
        $result = @()

        foreach ($policy in $policies) {
            # Resolve BlockedCategoryIds to names
            $blockedCategories = @()
            if ($policy.BlockedCategoryIds) {
                foreach ($catId in @($policy.BlockedCategoryIds)) {
                    $intId = [int]$catId
                    if ($WebCategoryMap.ContainsKey($intId)) {
                        $blockedCategories += $WebCategoryMap[$intId]
                    }
                    else {
                        $blockedCategories += "Unknown ($intId)"
                        Write-LogMessage "Unknown web category ID $intId in policy '$($policy.PolicyName)' — exported as 'Unknown ($intId)'" -Level WARN -Component "Export"
                    }
                }
            }

            # Resolve AuditCategoryIds to names
            $auditCategories = @()
            if ($policy.AuditCategoryIds) {
                foreach ($catId in @($policy.AuditCategoryIds)) {
                    $intId = [int]$catId
                    if ($WebCategoryMap.ContainsKey($intId)) {
                        $auditCategories += $WebCategoryMap[$intId]
                    }
                    else {
                        $auditCategories += "Unknown ($intId)"
                        Write-LogMessage "Unknown web category ID $intId in policy '$($policy.PolicyName)' — exported as 'Unknown ($intId)'" -Level WARN -Component "Export"
                    }
                }
            }

            # Resolve RbacGroupIds to device group names
            $rbacGroupNames = Resolve-RbacGroupIds -RbacGroupIds $policy.RbacGroupIds -DeviceGroupLookup $DeviceGroupLookup

            $result += [PSCustomObject]@{
                PolicyName        = $policy.PolicyName
                BlockedCategories = $blockedCategories
                AuditCategories   = $auditCategories
                RbacGroupNames    = $rbacGroupNames
                CreatedBy         = $policy.CreatedBy
                LastUpdateTime    = $policy.LastUpdateTime
            }
        }

        $names = ($result | ForEach-Object {
            $blocked = @($_.BlockedCategories).Count
            $audited = @($_.AuditCategories).Count
            "         - $($_.PolicyName) ($blocked blocked, $audited audited categories)"
        }) -join "`n"
        Write-LogMessage "Extracted $($result.Count) WCF policies:`n$names" -Level SUCCESS -Component "Export"
        return $result
    }

    function Get-Indicators {
        <#
        .SYNOPSIS
            Extracts Custom Indicators (IP or URL/Domain) from HAR entries.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [object[]]$Entries,

            [Parameter(Mandatory = $true)]
            [ValidateSet('ip', 'url')]
            [string]$IndicatorQueryType,

            [Parameter(Mandatory = $true)]
            [hashtable]$DeviceGroupLookup
        )

        $typeLabel = if ($IndicatorQueryType -eq 'ip') { "IP" } else { "URL/Domain" }
        Write-LogMessage "Extracting $typeLabel Indicators..." -Level INFO -Component "Export"

        $indicatorPattern = '/apiproxy/mtp/papin/api/cloud/public/internal/indicators/getQuery'
        $queryFilter = "type=$IndicatorQueryType"

        # Get all matching responses (may have multiple pages)
        $responses = Get-HARResponseByUrl -Entries $Entries -UrlPattern $indicatorPattern -QueryFilter $queryFilter -All

        if ($null -eq $responses -or @($responses).Count -eq 0) {
            Write-LogMessage "No $typeLabel Indicators response found in HAR — skipping" -Level WARN -Component "Export"
            return @()
        }

        # Merge all page arrays into a single consolidated array
        $indicators = @($responses)

        # Resolve enums and device group names
        foreach ($indicator in $indicators) {
            # Resolve action enum
            if ($null -ne $indicator.action -and $IndicatorActionMap.ContainsKey([int]$indicator.action)) {
                $indicator.action = $IndicatorActionMap[[int]$indicator.action]
            }

            # Resolve severity enum
            if ($null -ne $indicator.severity -and $IndicatorSeverityMap.ContainsKey([int]$indicator.severity)) {
                $indicator.severity = $IndicatorSeverityMap[[int]$indicator.severity]
            }

            # Resolve indicatorType enum
            if ($null -ne $indicator.indicatorType -and $IndicatorTypeMap.ContainsKey([int]$indicator.indicatorType)) {
                $indicator.indicatorType = $IndicatorTypeMap[[int]$indicator.indicatorType]
            }

            # Resolve RbacGroupIds to device group names
            $rbacGroupNames = Resolve-RbacGroupIds -RbacGroupIds $indicator.rbacGroupIds -DeviceGroupLookup $DeviceGroupLookup

            # Add resolved names as a new property
            $indicator | Add-Member -NotePropertyName 'rbacGroupNames' -NotePropertyValue $rbacGroupNames -Force
        }

        $names = ($indicators | ForEach-Object {
            $value = if ($_.indicatorValue) { $_.indicatorValue } else { "unknown" }
            $act = if ($_.action) { $_.action } else { "unknown" }
            "         - $value ($act)"
        }) -join "`n"
        Write-LogMessage "Extracted $($indicators.Count) $typeLabel indicator(s):`n$names" -Level SUCCESS -Component "Export"
        return $indicators
    }

    function Resolve-RbacGroupIds {
        <#
        .SYNOPSIS
            Resolves RbacGroupIds to device group names using the lookup table.
        #>
        param(
            [object]$RbacGroupIds,

            [Parameter(Mandatory = $true)]
            [hashtable]$DeviceGroupLookup
        )

        if ($null -eq $RbacGroupIds -or @($RbacGroupIds).Count -eq 0) {
            return @("All device groups")
        }

        $names = @()
        foreach ($groupId in @($RbacGroupIds)) {
            if ($DeviceGroupLookup.ContainsKey($groupId)) {
                $names += $DeviceGroupLookup[$groupId]
            }
            else {
                $names += "Unknown ($groupId)"
                Write-LogMessage "Unknown device group ID $groupId — exported as 'Unknown ($groupId)'" -Level WARN -Component "Export"
            }
        }
        return $names
    }

    #endregion Internal Functions

    #region Main Execution

    try {
        # Generate timestamp
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

        # Ensure output directory exists
        if (-not (Test-Path $OutputDirectory)) {
            New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        }

        # Create timestamped backup folder
        $backupDir = Join-Path $OutputDirectory "MDE-backup_$timestamp"
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

        # Set log path
        $LogPath = Join-Path $backupDir "${timestamp}_Export-MDEWebFilteringConfig.log"
        $script:LogPath = $LogPath
        New-Item -Path $LogPath -ItemType File -Force | Out-Null

        Write-LogMessage "MDE Web Filtering Configuration Export (HAR)" -Level SUMMARY -Component "Main"
        Write-LogMessage "Started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level INFO -Component "Main"
        Write-LogMessage "" -Level INFO

        # Log parameters
        Write-LogMessage "Parameters:" -Level INFO -Component "Main"
        Write-LogMessage "  HAR File: $HARFilePath" -Level INFO -Component "Main"
        Write-LogMessage "  Output Directory: $OutputDirectory" -Level INFO -Component "Main"
        Write-LogMessage "  Export Mode: $(if ($ExportCleanHAR) { 'Clean HAR Only' } else { 'Full Configuration Extract' })" -Level INFO -Component "Main"
        Write-LogMessage "" -Level INFO

        # Step 1: Read and parse HAR file
        $har = Read-HARFile -Path $HARFilePath

        # Step 2: If ExportCleanHAR mode, sanitize and return early
        if ($ExportCleanHAR) {
            $cleanHarPath = Join-Path $backupDir "mde_clean.har"
            Export-CleanHARFile -HarObject $har -OutputPath $cleanHarPath
            $har = $null
            [System.GC]::Collect()

            Write-LogMessage "" -Level INFO
            Write-LogMessage "Export completed successfully!" -Level SUCCESS -Component "Main"
            Write-LogMessage "" -Level INFO
            Write-LogMessage "Backup folder: $backupDir" -Level INFO -Component "Main"
            Write-LogMessage "" -Level INFO
            Write-LogMessage "Files created:" -Level INFO -Component "Main"
            Write-LogMessage "  - mde_clean.har" -Level INFO -Component "Main"
            Write-LogMessage "  - $(Split-Path $LogPath -Leaf)" -Level INFO -Component "Main"
            return $true
        }

        # Step 3: Filter to relevant API entries
        $relevantEntries = Get-HARApiEntries -Entries $har.log.entries

        # Step 4: Release full HAR from memory
        $har = $null
        [System.GC]::Collect()

        # Step 5: Auto-detect tenant ID
        $tenantId = Get-HARTenantId -Entries $relevantEntries

        Write-LogMessage "" -Level INFO

        # Step 6: Extract each object type
        $warnings = [System.Collections.Generic.List[string]]::new()

        # 6a: Device Groups (must be first — builds the lookup table)
        $deviceGroups = Get-DeviceGroups -Entries $relevantEntries

        # Build device group lookup: MachineGroupId → Name
        $deviceGroupLookup = @{}
        foreach ($group in $deviceGroups) {
            $name = if ($group.IsUnassignedMachineGroup) { "Ungrouped devices" }
                    elseif ([string]::IsNullOrEmpty($group.Name)) { "Unnamed ($($group.MachineGroupId))" }
                    else { $group.Name }
            $deviceGroupLookup[$group.MachineGroupId] = $name
        }

        # 6b: WCF Policies
        $wcfPolicies = Get-WcfPolicies -Entries $relevantEntries -DeviceGroupLookup $deviceGroupLookup

        # 6c: IP Indicators
        $ipIndicators = Get-Indicators -Entries $relevantEntries -IndicatorQueryType 'ip' -DeviceGroupLookup $deviceGroupLookup

        # 6d: URL/Domain Indicators
        $urlIndicators = Get-Indicators -Entries $relevantEntries -IndicatorQueryType 'url' -DeviceGroupLookup $deviceGroupLookup

        Write-LogMessage "" -Level INFO

        # Step 7: Save each object type to JSON files
        Write-LogMessage "Saving configuration files..." -Level INFO -Component "Backup"
        $filesCreated = @()

        $exportMap = [ordered]@{
            'wcf_policies'   = $wcfPolicies
            'ip_indicators'  = $ipIndicators
            'url_indicators' = $urlIndicators
            'device_groups'  = $deviceGroups
        }

        foreach ($name in $exportMap.Keys) {
            $data = $exportMap[$name]
            $filePath = Join-Path $backupDir "$name.json"

            if ($null -ne $data -and @($data).Count -gt 0) {
                $result = Export-DataToFile -Data @($data) -FilePath $filePath -Format "JSON"
                if ($result) {
                    $filesCreated += "$name.json"
                }
            }
            else {
                # Write empty array for missing types
                '[]' | Out-File -FilePath $filePath -Encoding UTF8
                $warnings.Add("No $name data found in HAR — exported empty array")
                $filesCreated += "$name.json"
                Write-LogMessage "No data for $name — wrote empty array" -Level WARN -Component "Backup"
            }
        }

        # Step 8: Write export metadata
        $harFileInfo = Get-Item (Resolve-Path $HARFilePath).Path
        $objectCounts = [ordered]@{
            wcfPolicies   = @($wcfPolicies).Count
            ipIndicators  = @($ipIndicators).Count
            urlIndicators = @($urlIndicators).Count
            deviceGroups  = @($deviceGroups).Count
        }

        $metadata = [PSCustomObject]@{
            timestamp            = $timestamp
            sourceFile           = $harFileInfo.FullName
            sourceFileSizeBytes  = $harFileInfo.Length
            tenantId             = $tenantId
            exportFunction       = "Export-MDEWebFilteringConfig"
            exportModuleVersion  = "0.x.x"
            objectCounts         = [PSCustomObject]$objectCounts
            warnings             = @($warnings)
        }

        $metadataPath = Join-Path $backupDir "export_metadata.json"
        $metadata | ConvertTo-Json -Depth 10 | Out-File -FilePath $metadataPath -Encoding UTF8
        $filesCreated += "export_metadata.json"

        Write-LogMessage "" -Level INFO

        # Step 9: Display completion summary
        Write-LogMessage "Export completed successfully!" -Level SUCCESS -Component "Main"
        Write-LogMessage "" -Level INFO
        Write-LogMessage "Backup folder: $backupDir" -Level INFO -Component "Main"
        Write-LogMessage "" -Level INFO
        Write-LogMessage "MDE Web Filtering Configuration (from HAR):" -Level SUMMARY -Component "Main"
        Write-LogMessage "  Tenant ID:          $tenantId" -Level INFO -Component "Main"
        Write-LogMessage "  WCF Policies:       $($objectCounts.wcfPolicies)" -Level INFO -Component "Main"
        Write-LogMessage "  IP Indicators:      $($objectCounts.ipIndicators)" -Level INFO -Component "Main"
        Write-LogMessage "  URL Indicators:     $($objectCounts.urlIndicators)" -Level INFO -Component "Main"
        Write-LogMessage "  Device Groups:      $($objectCounts.deviceGroups)" -Level INFO -Component "Main"

        if ($warnings.Count -gt 0) {
            Write-LogMessage "  Warnings:           $($warnings.Count)" -Level WARN -Component "Main"
        }
        else {
            Write-LogMessage "  Warnings:           0" -Level INFO -Component "Main"
        }

        Write-LogMessage "" -Level INFO
        Write-LogMessage "Files created:" -Level INFO -Component "Main"
        foreach ($file in $filesCreated) {
            Write-LogMessage "  - $file" -Level INFO -Component "Main"
        }
        Write-LogMessage "  - $(Split-Path $LogPath -Leaf)" -Level INFO -Component "Main"

        Write-LogMessage "" -Level INFO
        Write-LogMessage "Finished at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level INFO -Component "Main"
        return $true
    }
    catch {
        Write-LogMessage "" -Level INFO
        $errorMsg = $_.Exception.Message
        Write-LogMessage "Export process failed: $errorMsg" -Level ERROR -Component "Main"

        if ($script:EnableDebugLogging) {
            Write-LogMessage "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR -Component "Main"
            throw
        }

        $PSCmdlet.ThrowTerminatingError($_)
    }

    #endregion Main Execution
}
