function Export-CiscoUmbrellaConfig {
    <#
    .SYNOPSIS
        Exports Cisco Umbrella configuration from a HAR file captured from the Umbrella dashboard.

    .DESCRIPTION
        Extracts Cisco Umbrella configuration objects from an HTTP Archive (HAR) file captured
        while browsing the Umbrella dashboard. Parses API responses from api.opendns.com and
        api.umbrella.com to reconstruct the full configuration without requiring live API access.

        Extracts 8 object types: DNS Policies, Firewall Rules, Web Policies, Destination Lists,
        Category Settings, Application Settings, Security Settings, and Selective Decryption Lists.

        Alternatively, with -ExportCleanHAR, produces a sanitized copy of the HAR file suitable
        for sharing (sensitive headers removed, non-API entries stripped).

    .PARAMETER HARFilePath
        Absolute or relative path to the .har file captured from the Umbrella dashboard.

    .PARAMETER OutputDirectory
        Directory where the timestamped backup folder will be created. Defaults to current directory.

    .PARAMETER ExportCleanHAR
        When specified, only produces a sanitized copy of the HAR file and skips configuration extraction.

    .OUTPUTS
        System.Boolean
        Returns $true if export completed successfully, $false otherwise.

    .EXAMPLE
        Export-CiscoUmbrellaConfig -HARFilePath "C:\captures\umbrella_dashboard.har"

        Basic usage — exports all configuration objects to the current directory.

    .EXAMPLE
        Export-CiscoUmbrellaConfig -HARFilePath "C:\captures\umbrella.har" -OutputDirectory "C:\Backups\Umbrella"

        Export with a custom output directory.

    .EXAMPLE
        Export-CiscoUmbrellaConfig -HARFilePath "C:\captures\umbrella.har" -ExportCleanHAR

        Produces only a sanitized HAR copy — no JSON extraction is performed.

    .NOTES
        Author: Andres Canello
        Date: February 20, 2026

        The Cisco Umbrella dashboard uses internal APIs (api.opendns.com/v3/ and api.umbrella.com/v1/)
        that are not part of Cisco's public API surface. Capturing a HAR file while browsing the
        dashboard is the most reliable way to obtain the full configuration data.

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
            Filters HAR entries to relevant Umbrella API hosts with successful GET responses.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [object[]]$Entries
        )

        $relevantHosts = @('api.opendns.com', 'api.umbrella.com')

        $filtered = $Entries | Where-Object {
            $_.request.method -eq 'GET' -and
            $_.response.status -eq 200 -and
            $_.response.content.text -and
            $(try { $uri = [System.Uri]::new($_.request.url); $uri.Host -in $relevantHosts } catch { $false })
        }

        if ($null -eq $filtered -or @($filtered).Count -eq 0) {
            throw "No Cisco Umbrella API requests found in the HAR file. Ensure the HAR was captured while browsing the Umbrella dashboard."
        }

        $count = @($filtered).Count
        Write-LogMessage "Filtered to $count relevant API entries (api.opendns.com, api.umbrella.com)" -Level INFO -Component "HAR"
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
            [switch]$All
        )

        $matched = $Entries | Where-Object {
            $decodedUrl = [System.Uri]::UnescapeDataString($_.request.url)
            $decodedUrl -match $UrlPattern
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
            # Use the last successful response for deduplication
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

    function Get-HAROrganizationId {
        <#
        .SYNOPSIS
            Auto-detects the organizationId from HAR entry URLs.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [object[]]$Entries
        )

        $orgIdPattern = '/organizations/(\d+)/'
        $firstMatch = $Entries | ForEach-Object {
            if ($_.request.url -match $orgIdPattern) { $Matches[1] }
        } | Select-Object -First 1

        if (-not $firstMatch) {
            throw "Could not detect organizationId from HAR entries"
        }

        Write-LogMessage "Detected Umbrella organizationId: $firstMatch" -Level INFO -Component "HAR"
        return $firstMatch
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

        $relevantHosts = @('api.opendns.com', 'api.umbrella.com')
        $sensitiveHeaders = @('authorization', 'cookie', 'set-cookie', 'x-csrf-token')

        # Filter entries to relevant API hosts
        $cleanEntries = @($HarObject.log.entries | Where-Object {
            try { $uri = [System.Uri]::new($_.request.url); $uri.Host -in $relevantHosts } catch { $false }
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

    function Get-BundleTypeFromUrl {
        <#
        .SYNOPSIS
            Determines the bundleTypeId from a URL query string.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [string]$Url
        )

        $decodedUrl = [System.Uri]::UnescapeDataString($Url)
        if ($decodedUrl -match '"bundleTypeId"\s*:\s*(\d+)') {
            return [int]$Matches[1]
        }
        return $null
    }

    function Get-DnsPolicies {
        <#
        .SYNOPSIS
            Extracts DNS Policies from HAR entries.
        #>
        param(
            [object[]]$Entries,
            [string]$OrgId
        )

        Write-LogMessage "Extracting DNS Policies..." -Level INFO -Component "Export"

        # Find bundles list filtered to bundleTypeId=1
        $bundleEntries = $Entries | Where-Object {
            $decodedUrl = [System.Uri]::UnescapeDataString($_.request.url)
            $decodedUrl -match "/organizations/$OrgId/bundles\?" -and
            $decodedUrl -match '"bundleTypeId"\s*:\s*1[,}\s]'
        }

        # Also look for bundles with optionalFields that include policySetting (DNS-specific enriched calls)
        if ($null -eq $bundleEntries -or @($bundleEntries).Count -eq 0) {
            $bundleEntries = $Entries | Where-Object {
                $decodedUrl = [System.Uri]::UnescapeDataString($_.request.url)
                $decodedUrl -match "/organizations/$OrgId/bundles\?" -and
                $decodedUrl -match 'bundleTypeId.*1'
            }
        }

        if ($null -eq $bundleEntries -or @($bundleEntries).Count -eq 0) {
            Write-LogMessage "No DNS Policies list response found in HAR — skipping" -Level WARN -Component "Export"
            return @()
        }

        # Use the last matching entry
        $entry = @($bundleEntries) | Select-Object -Last 1
        try {
            $response = $entry.response.content.text | ConvertFrom-Json
        }
        catch {
            Write-LogMessage "Could not parse DNS Policies response — skipping" -Level WARN -Component "Export"
            return @()
        }

        $policies = if ($response.data) { @($response.data) } else { @($response) }

        # Enrich with individual policysettings detail responses
        $detailPattern = "/organizations/$OrgId/policysettings/\d+(\?|$)"
        foreach ($policy in $policies) {
            $policySettingId = $policy.policySettingGroupId
            if ($policySettingId) {
                $detailResponse = Get-HARResponseByUrl -Entries $Entries -UrlPattern "/organizations/$OrgId/policysettings/$policySettingId(\?|$)"
                if ($detailResponse) {
                    $detailData = if ($detailResponse.data) { $detailResponse.data } else { $detailResponse }
                    $policy | Add-Member -NotePropertyName 'policySettingDetail' -NotePropertyValue $detailData -Force
                }
            }
        }

        $names = ($policies | ForEach-Object { "         - $($_.name)" }) -join "`n"
        Write-LogMessage "Extracted $($policies.Count) DNS policies:`n$names" -Level SUCCESS -Component "Export"
        return $policies
    }

    function Get-FirewallRules {
        <#
        .SYNOPSIS
            Extracts Firewall Rules from HAR entries.
        #>
        param(
            [object[]]$Entries,
            [string]$OrgId
        )

        Write-LogMessage "Extracting Firewall Rules..." -Level INFO -Component "Export"

        # Find all firewall ruleset responses (may be paginated)
        $fwPattern = "/organizations/$OrgId/rulesets/firewall"
        $fwResponses = Get-HARResponseByUrl -Entries $Entries -UrlPattern $fwPattern -All

        if ($null -eq $fwResponses -or @($fwResponses).Count -eq 0) {
            Write-LogMessage "No Firewall Rules response found in HAR — skipping" -Level WARN -Component "Export"
            return $null
        }

        # Merge paginated responses if multiple
        $responses = @($fwResponses)
        if ($responses.Count -eq 1) {
            $ruleset = $responses[0]
        }
        else {
            # Take the first response as the base and merge rules from all
            $ruleset = $responses[0]
            $allRules = @()
            foreach ($resp in $responses) {
                if ($resp.rules) { $allRules += @($resp.rules) }
                elseif ($resp.data -and $resp.data.rules) { $allRules += @($resp.data.rules) }
            }
            if ($allRules.Count -gt 0) {
                if ($ruleset.PSObject.Properties['rules']) {
                    $ruleset.rules = $allRules
                }
                else {
                    $ruleset | Add-Member -NotePropertyName 'rules' -NotePropertyValue $allRules -Force
                }
            }
        }

        # Optionally attach hit count intervals
        $hitCountResponse = Get-HARResponseByUrl -Entries $Entries -UrlPattern "/organizations/$OrgId/firewallhitcountintervals"
        if ($hitCountResponse) {
            $hitData = if ($hitCountResponse.data) { $hitCountResponse.data } else { $hitCountResponse }
            $ruleset | Add-Member -NotePropertyName 'hitCountIntervals' -NotePropertyValue $hitData -Force
        }

        $ruleCount = 0
        if ($ruleset.rules) { $ruleCount = @($ruleset.rules).Count }
        elseif ($ruleset.data -and $ruleset.data.rules) { $ruleCount = @($ruleset.data.rules).Count }
        Write-LogMessage "Extracted $ruleCount firewall rules (1 ruleset)" -Level SUCCESS -Component "Export"
        return $ruleset
    }

    function Get-WebPolicies {
        <#
        .SYNOPSIS
            Extracts Web Policies from HAR entries.
        #>
        param(
            [object[]]$Entries,
            [string]$OrgId
        )

        Write-LogMessage "Extracting Web Policies..." -Level INFO -Component "Export"

        # Find bundles list filtered to bundleTypeId=2
        $bundleEntries = $Entries | Where-Object {
            $decodedUrl = [System.Uri]::UnescapeDataString($_.request.url)
            $decodedUrl -match "/organizations/$OrgId/bundles\?" -and
            $decodedUrl -match '"bundleTypeId"\s*:\s*2[,}\s]'
        }

        if ($null -eq $bundleEntries -or @($bundleEntries).Count -eq 0) {
            $bundleEntries = $Entries | Where-Object {
                $decodedUrl = [System.Uri]::UnescapeDataString($_.request.url)
                $decodedUrl -match "/organizations/$OrgId/bundles\?" -and
                $decodedUrl -match 'bundleTypeId.*2'
            }
        }

        if ($null -eq $bundleEntries -or @($bundleEntries).Count -eq 0) {
            Write-LogMessage "No Web Policies list response found in HAR — skipping" -Level WARN -Component "Export"
            return @()
        }

        $entry = @($bundleEntries) | Select-Object -Last 1
        try {
            $response = $entry.response.content.text | ConvertFrom-Json
        }
        catch {
            Write-LogMessage "Could not parse Web Policies response — skipping" -Level WARN -Component "Export"
            return @()
        }

        $policies = if ($response.data) { @($response.data) } else { @($response) }

        # Enrich with proxy ruleset and ruleset settings
        foreach ($policy in $policies) {
            $bundleId = $policy.id
            if ($bundleId) {
                # Proxy ruleset: /v1/organizations/{orgId}/rulesets/bundle/{bundleId}
                $proxyResponse = Get-HARResponseByUrl -Entries $Entries -UrlPattern "/organizations/$OrgId/rulesets/bundle/$bundleId"
                if ($proxyResponse) {
                    $policy | Add-Member -NotePropertyName 'proxyRuleset' -NotePropertyValue $proxyResponse -Force

                    # Ruleset settings: /v1/organizations/{orgId}/rulesets/{rulesetId}/settings
                    $rulesetId = $proxyResponse.id
                    if (-not $rulesetId) { $rulesetId = $proxyResponse.rulesetId }
                    if ($rulesetId) {
                        $settingsResponse = Get-HARResponseByUrl -Entries $Entries -UrlPattern "/organizations/$OrgId/rulesets/$rulesetId/settings"
                        if ($settingsResponse) {
                            $proxyResponse | Add-Member -NotePropertyName 'rulesetSettings' -NotePropertyValue $settingsResponse -Force
                        }
                    }
                }
            }
        }

        $names = ($policies | ForEach-Object { "         - $($_.name)" }) -join "`n"
        Write-LogMessage "Extracted $($policies.Count) web policies with proxy ruleset:`n$names" -Level SUCCESS -Component "Export"
        return $policies
    }

    function Get-DestinationLists {
        <#
        .SYNOPSIS
            Extracts Destination Lists from HAR entries.
        #>
        param(
            [object[]]$Entries,
            [string]$OrgId
        )

        Write-LogMessage "Extracting Destination Lists..." -Level INFO -Component "Export"

        # Find destination lists response (exclude URLs that contain /destinations)
        $listPattern = "/organizations/$OrgId/destinationlists(\?|$)"
        $listEntries = $Entries | Where-Object {
            $decodedUrl = [System.Uri]::UnescapeDataString($_.request.url)
            $decodedUrl -match $listPattern -and $decodedUrl -notmatch '/destinationlists/\d+/destinations'
        }

        if ($null -eq $listEntries -or @($listEntries).Count -eq 0) {
            Write-LogMessage "No Destination Lists response found in HAR — skipping" -Level WARN -Component "Export"
            return @()
        }

        # Merge data from all list responses (there may be multiple queries with different filters)
        $allLists = @{}
        foreach ($entry in @($listEntries)) {
            try {
                $response = $entry.response.content.text | ConvertFrom-Json
                $items = if ($response.data) { @($response.data) } else { @($response) }
                foreach ($item in $items) {
                    if ($item.id -and -not $allLists.ContainsKey("$($item.id)")) {
                        $allLists["$($item.id)"] = $item
                    }
                }
            }
            catch {
                Write-LogMessage "Could not parse a destination lists response — skipping" -Level WARN -Component "Export"
            }
        }

        $lists = @($allLists.Values)

        # Enrich each list with its destination entries
        $listsWithEntries = 0
        foreach ($list in $lists) {
            $listId = $list.id
            if ($listId) {
                $destEntries = $Entries | Where-Object {
                    $decodedUrl = [System.Uri]::UnescapeDataString($_.request.url)
                    $decodedUrl -match "/organizations/$OrgId/destinationlists/$listId/destinations"
                }
                if ($null -ne $destEntries -and @($destEntries).Count -gt 0) {
                    $allDestinations = @()
                    foreach ($destEntry in @($destEntries)) {
                        try {
                            $destResponse = $destEntry.response.content.text | ConvertFrom-Json
                            $destItems = if ($destResponse.data) { @($destResponse.data) } else { @($destResponse) }
                            $allDestinations += $destItems
                        }
                        catch {
                            Write-LogMessage "Could not parse destination entries for list $listId — skipping page" -Level WARN -Component "Export"
                        }
                    }
                    if ($allDestinations.Count -gt 0) {
                        # Deduplicate by a composite key if possible
                        $list | Add-Member -NotePropertyName 'destinations' -NotePropertyValue $allDestinations -Force
                        $listsWithEntries++
                    }
                }
            }
        }

        $names = ($lists | ForEach-Object {
            $entryCount = if ($_.destinations) { @($_.destinations).Count } else { 0 }
            "         - $($_.name) ($entryCount entries)"
        }) -join "`n"
        Write-LogMessage "Extracted $($lists.Count) destination lists ($listsWithEntries with entries):`n$names" -Level SUCCESS -Component "Export"
        return $lists
    }

    function Get-CategorySettings {
        <#
        .SYNOPSIS
            Extracts Category Settings from HAR entries.
        #>
        param(
            [object[]]$Entries,
            [string]$OrgId
        )

        Write-LogMessage "Extracting Category Settings..." -Level INFO -Component "Export"

        # Find list response (exclude individual detail URLs)
        $listPattern = "/organizations/$OrgId/categorysettings(\?|$)"
        $listEntries = $Entries | Where-Object {
            $decodedUrl = [System.Uri]::UnescapeDataString($_.request.url)
            $decodedUrl -match $listPattern -and $decodedUrl -notmatch "/categorysettings/\d+"
        }

        if ($null -eq $listEntries -or @($listEntries).Count -eq 0) {
            Write-LogMessage "No Category Settings list response found in HAR — skipping" -Level WARN -Component "Export"
            return @()
        }

        $entry = @($listEntries) | Select-Object -Last 1
        try {
            $response = $entry.response.content.text | ConvertFrom-Json
        }
        catch {
            Write-LogMessage "Could not parse Category Settings response — skipping" -Level WARN -Component "Export"
            return @()
        }

        $items = if ($response.data) { @($response.data) } else { @($response) }

        # Prefer detail responses where available
        $detailCount = 0
        $result = @()
        foreach ($item in $items) {
            $itemId = $item.id
            if ($itemId) {
                $detailResponse = Get-HARResponseByUrl -Entries $Entries -UrlPattern "/organizations/$OrgId/categorysettings/$itemId(\?|$)"
                if ($detailResponse) {
                    $detailData = if ($detailResponse.data) { $detailResponse.data } else { $detailResponse }
                    $result += $detailData
                    $detailCount++
                }
                else {
                    Write-LogMessage "No detail response for categorysettings id=$itemId — using list data" -Level WARN -Component "Export"
                    $result += $item
                }
            }
            else {
                $result += $item
            }
        }

        $names = ($result | ForEach-Object { "         - $($_.name)" }) -join "`n"
        Write-LogMessage "Extracted $($result.Count) category settings ($detailCount with full category details):`n$names" -Level SUCCESS -Component "Export"
        return $result
    }

    function Get-ApplicationSettings {
        <#
        .SYNOPSIS
            Extracts Application Settings from HAR entries.
        #>
        param(
            [object[]]$Entries,
            [string]$OrgId
        )

        Write-LogMessage "Extracting Application Settings..." -Level INFO -Component "Export"

        # Find list response
        $listPattern = "/organizations/$OrgId/applicationsettings(\?|$)"
        $listEntries = $Entries | Where-Object {
            $decodedUrl = [System.Uri]::UnescapeDataString($_.request.url)
            $decodedUrl -match $listPattern -and $decodedUrl -notmatch "/applicationsettings/\d+"
        }

        if ($null -eq $listEntries -or @($listEntries).Count -eq 0) {
            Write-LogMessage "No Application Settings list response found in HAR — skipping" -Level WARN -Component "Export"
            return @()
        }

        $entry = @($listEntries) | Select-Object -Last 1
        try {
            $response = $entry.response.content.text | ConvertFrom-Json
        }
        catch {
            Write-LogMessage "Could not parse Application Settings response — skipping" -Level WARN -Component "Export"
            return @()
        }

        $items = if ($response.data) { @($response.data) } else { @($response) }
        $listIds = @($items | ForEach-Object { $_.id })

        # Prefer detail responses where available
        $detailCount = 0
        $result = @()
        foreach ($item in $items) {
            $itemId = $item.id
            if ($itemId) {
                $detailResponse = Get-HARResponseByUrl -Entries $Entries -UrlPattern "/organizations/$OrgId/applicationsettings/$itemId(\?|$)"
                if ($detailResponse) {
                    $detailData = if ($detailResponse.data) { $detailResponse.data } else { $detailResponse }
                    $result += $detailData
                    $detailCount++
                }
                else {
                    Write-LogMessage "No detail response for applicationsettings id=$itemId — using list data" -Level WARN -Component "Export"
                    $result += $item
                }
            }
            else {
                $result += $item
            }
        }

        # Special case: scan for system-inherited settings not in the list
        $allDetailEntries = $Entries | Where-Object {
            $decodedUrl = [System.Uri]::UnescapeDataString($_.request.url)
            $decodedUrl -match "/organizations/$OrgId/applicationsettings/\d+(\?|$)"
        }
        foreach ($detailEntry in @($allDetailEntries)) {
            try {
                $detailResp = $detailEntry.response.content.text | ConvertFrom-Json
                $detailData = if ($detailResp.data) { $detailResp.data } else { $detailResp }
                if ($detailData.id -and $detailData.id -notin $listIds -and $detailData.id -notin ($result | ForEach-Object { $_.id })) {
                    Write-LogMessage "Found system-inherited application setting id=$($detailData.id) (organizationId=$($detailData.organizationId)) not in list — including" -Level INFO -Component "Export"
                    $result += $detailData
                }
            }
            catch {
                # Skip unparseable entries
            }
        }

        $names = ($result | ForEach-Object { "         - $($_.name)" }) -join "`n"
        Write-LogMessage "Extracted $($result.Count) application settings ($detailCount with full app details):`n$names" -Level SUCCESS -Component "Export"
        return $result
    }

    function Get-SecuritySettings {
        <#
        .SYNOPSIS
            Extracts Security Settings from HAR entries.
        #>
        param(
            [object[]]$Entries,
            [string]$OrgId
        )

        Write-LogMessage "Extracting Security Settings..." -Level INFO -Component "Export"

        # Find list response
        $listPattern = "/organizations/$OrgId/securitysettings(\?|$)"
        $listEntries = $Entries | Where-Object {
            $decodedUrl = [System.Uri]::UnescapeDataString($_.request.url)
            $decodedUrl -match $listPattern -and $decodedUrl -notmatch "/securitysettings/\d+"
        }

        if ($null -eq $listEntries -or @($listEntries).Count -eq 0) {
            Write-LogMessage "No Security Settings list response found in HAR — skipping" -Level WARN -Component "Export"
            return @()
        }

        # Prefer the response with optionalFields=categories if available
        $enrichedEntry = @($listEntries) | Where-Object {
            $decodedUrl = [System.Uri]::UnescapeDataString($_.request.url)
            $decodedUrl -match 'optionalFields.*categories'
        } | Select-Object -Last 1

        $entry = if ($enrichedEntry) { $enrichedEntry } else { @($listEntries) | Select-Object -Last 1 }

        try {
            $response = $entry.response.content.text | ConvertFrom-Json
        }
        catch {
            Write-LogMessage "Could not parse Security Settings response — skipping" -Level WARN -Component "Export"
            return @()
        }

        $items = if ($response.data) { @($response.data) } else { @($response) }

        # Prefer detail responses where available
        $inheritedCount = 0
        $result = @()
        foreach ($item in $items) {
            $itemId = $item.id
            if ($itemId) {
                $detailResponse = Get-HARResponseByUrl -Entries $Entries -UrlPattern "/organizations/$OrgId/securitysettings/$itemId(\?|$)"
                if ($detailResponse) {
                    $detailData = if ($detailResponse.data) { $detailResponse.data } else { $detailResponse }
                    # Tag MSP-inherited records
                    if ($detailData.organizationId -and "$($detailData.organizationId)" -ne "$OrgId") {
                        $detailData | Add-Member -NotePropertyName '_isInherited' -NotePropertyValue $true -Force
                        $inheritedCount++
                    }
                    $result += $detailData
                }
                else {
                    # Tag MSP-inherited records from list data
                    if ($item.organizationId -and "$($item.organizationId)" -ne "$OrgId") {
                        $item | Add-Member -NotePropertyName '_isInherited' -NotePropertyValue $true -Force
                        $inheritedCount++
                    }
                    $result += $item
                }
            }
            else {
                $result += $item
            }
        }

        $inheritedNote = if ($inheritedCount -gt 0) { " ($inheritedCount MSP-inherited)" } else { "" }
        $names = ($result | ForEach-Object {
            $inherited = if ($_._isInherited) { " (inherited)" } else { "" }
            "         - $($_.name)$inherited"
        }) -join "`n"
        Write-LogMessage "Extracted $($result.Count) security settings$inheritedNote`:`n$names" -Level SUCCESS -Component "Export"
        return $result
    }

    function Get-SelectiveDecryptionLists {
        <#
        .SYNOPSIS
            Extracts Selective Decryption Lists from HAR entries.
        #>
        param(
            [object[]]$Entries,
            [string]$OrgId
        )

        Write-LogMessage "Extracting Selective Decryption Lists..." -Level INFO -Component "Export"

        # Find list response
        $listPattern = "/organizations/$OrgId/bypassinspectiongroupsettings(\?|$)"
        $listEntries = $Entries | Where-Object {
            $decodedUrl = [System.Uri]::UnescapeDataString($_.request.url)
            $decodedUrl -match $listPattern -and $decodedUrl -notmatch "/bypassinspectiongroupsettings/\d+"
        }

        if ($null -eq $listEntries -or @($listEntries).Count -eq 0) {
            Write-LogMessage "No Selective Decryption Lists response found in HAR — skipping" -Level WARN -Component "Export"
            return @()
        }

        $entry = @($listEntries) | Select-Object -Last 1
        try {
            $response = $entry.response.content.text | ConvertFrom-Json
        }
        catch {
            Write-LogMessage "Could not parse Selective Decryption Lists response — skipping" -Level WARN -Component "Export"
            return @()
        }

        # Always use data.Count, never meta.total (meta.total is unreliable for this endpoint)
        $items = if ($response.data) { @($response.data) } else { @($response) }

        # Prefer detail responses where available
        $result = @()
        foreach ($item in $items) {
            $itemId = $item.id
            if ($itemId) {
                $detailResponse = Get-HARResponseByUrl -Entries $Entries -UrlPattern "/organizations/$OrgId/bypassinspectiongroupsettings/$itemId(\?|$)"
                if ($detailResponse) {
                    $detailData = if ($detailResponse.data) { $detailResponse.data } else { $detailResponse }
                    $result += $detailData
                }
                else {
                    $result += $item
                }
            }
            else {
                $result += $item
            }
        }

        $names = ($result | ForEach-Object { "         - $($_.name)" }) -join "`n"
        Write-LogMessage "Extracted $($result.Count) selective decryption lists:`n$names" -Level SUCCESS -Component "Export"
        return $result
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
        $backupDir = Join-Path $OutputDirectory "CiscoUmbrella-backup_$timestamp"
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

        # Set log path
        $LogPath = Join-Path $backupDir "${timestamp}_Export-CiscoUmbrella.log"
        $script:LogPath = $LogPath
        New-Item -Path $LogPath -ItemType File -Force | Out-Null

        Write-LogMessage "Cisco Umbrella Configuration Export (HAR)" -Level SUMMARY -Component "Main"
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
            $cleanHarPath = Join-Path $backupDir "umbrella_clean.har"
            Export-CleanHARFile -HarObject $har -OutputPath $cleanHarPath
            $har = $null
            [System.GC]::Collect()

            Write-LogMessage "" -Level INFO
            Write-LogMessage "Export completed successfully!" -Level SUCCESS -Component "Main"
            Write-LogMessage "" -Level INFO
            Write-LogMessage "Backup folder: $backupDir" -Level INFO -Component "Main"
            Write-LogMessage "" -Level INFO
            Write-LogMessage "Files created:" -Level INFO -Component "Main"
            Write-LogMessage "  - umbrella_clean.har" -Level INFO -Component "Main"
            Write-LogMessage "  - $(Split-Path $LogPath -Leaf)" -Level INFO -Component "Main"
            return $true
        }

        # Step 3: Filter to relevant API entries
        $relevantEntries = Get-HARApiEntries -Entries $har.log.entries

        # Step 4: Release full HAR from memory
        $har = $null
        [System.GC]::Collect()

        # Step 5: Auto-detect organizationId
        $organizationId = Get-HAROrganizationId -Entries $relevantEntries

        Write-LogMessage "" -Level INFO

        # Step 6: Extract each object type
        $warnings = [System.Collections.Generic.List[string]]::new()

        # 6a: DNS Policies
        $dnsPolicies = Get-DnsPolicies -Entries $relevantEntries -OrgId $organizationId

        # 6b: Firewall Rules
        $firewallRules = Get-FirewallRules -Entries $relevantEntries -OrgId $organizationId

        # 6c: Web Policies
        $webPolicies = Get-WebPolicies -Entries $relevantEntries -OrgId $organizationId

        # 6d: Destination Lists
        $destinationLists = Get-DestinationLists -Entries $relevantEntries -OrgId $organizationId

        # 6e: Category Settings
        $categorySettings = Get-CategorySettings -Entries $relevantEntries -OrgId $organizationId

        # 6f: Application Settings
        $applicationSettings = Get-ApplicationSettings -Entries $relevantEntries -OrgId $organizationId

        # 6g: Security Settings
        $securitySettings = Get-SecuritySettings -Entries $relevantEntries -OrgId $organizationId

        # 6h: Selective Decryption Lists
        $selectiveDecryptionLists = Get-SelectiveDecryptionLists -Entries $relevantEntries -OrgId $organizationId

        Write-LogMessage "" -Level INFO

        # Step 7: Save each object type to JSON files
        Write-LogMessage "Saving configuration files..." -Level INFO -Component "Backup"
        $filesCreated = @()

        $exportMap = [ordered]@{
            'dns_policies'              = $dnsPolicies
            'firewall_rules'            = $firewallRules
            'web_policies'              = $webPolicies
            'destination_lists'         = $destinationLists
            'category_settings'         = $categorySettings
            'application_settings'      = $applicationSettings
            'security_settings'         = $securitySettings
            'selective_decryption_lists' = $selectiveDecryptionLists
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
        $objectCounts = [ordered]@{
            dnsPolicies              = @($dnsPolicies).Count
            firewallRules            = if ($firewallRules.rules) { @($firewallRules.rules).Count } elseif ($firewallRules) { 1 } else { 0 }
            webPolicies              = @($webPolicies).Count
            destinationLists         = @($destinationLists).Count
            categorySettings         = @($categorySettings).Count
            applicationSettings      = @($applicationSettings).Count
            securitySettings         = @($securitySettings).Count
            selectiveDecryptionLists = @($selectiveDecryptionLists).Count
        }

        $metadata = [PSCustomObject]@{
            timestamp      = $timestamp
            sourceHARFile  = Split-Path $HARFilePath -Leaf
            organizationId = $organizationId
            exportType     = "CiscoUmbrella_HAR_Extract"
            objectCounts   = [PSCustomObject]$objectCounts
            warnings       = @($warnings)
        }

        $metadataPath = Join-Path $backupDir "export_metadata.json"
        $metadata | ConvertTo-Json -Depth 10 | Out-File -FilePath $metadataPath -Encoding UTF8
        $filesCreated += "export_metadata.json"

        Write-LogMessage "" -Level INFO

        # Step 9: Display completion summary
        $listsWithEntries = @($destinationLists | Where-Object { $_.destinations }).Count
        $detailCatCount = @($categorySettings | Where-Object { $_.categories }).Count
        $detailAppCount = @($applicationSettings | Where-Object { $_.applications -or $_.applicationsCategories }).Count
        $inheritedSecCount = @($securitySettings | Where-Object { $_._isInherited }).Count

        Write-LogMessage "Export completed successfully!" -Level SUCCESS -Component "Main"
        Write-LogMessage "" -Level INFO
        Write-LogMessage "Backup folder: $backupDir" -Level INFO -Component "Main"
        Write-LogMessage "" -Level INFO
        Write-LogMessage "Cisco Umbrella Configuration (from HAR):" -Level SUMMARY -Component "Main"
        Write-LogMessage "  Organization ID:           $organizationId" -Level INFO -Component "Main"
        Write-LogMessage "  DNS Policies:              $($objectCounts.dnsPolicies)" -Level INFO -Component "Main"
        Write-LogMessage "  Firewall Rules:            $($objectCounts.firewallRules)" -Level INFO -Component "Main"
        Write-LogMessage "  Web Policies:              $($objectCounts.webPolicies)" -Level INFO -Component "Main"
        Write-LogMessage "  Destination Lists:         $($objectCounts.destinationLists) ($listsWithEntries with entries)" -Level INFO -Component "Main"
        Write-LogMessage "  Category Settings:         $($objectCounts.categorySettings) ($detailCatCount with full category details)" -Level INFO -Component "Main"
        Write-LogMessage "  Application Settings:      $($objectCounts.applicationSettings) ($detailAppCount with full app details)" -Level INFO -Component "Main"

        $secInheritedNote = if ($inheritedSecCount -gt 0) { " ($inheritedSecCount MSP-inherited)" } else { "" }
        Write-LogMessage "  Security Settings:         $($objectCounts.securitySettings)$secInheritedNote" -Level INFO -Component "Main"
        Write-LogMessage "  Selective Decryption Lists: $($objectCounts.selectiveDecryptionLists)" -Level INFO -Component "Main"

        if ($warnings.Count -gt 0) {
            Write-LogMessage "  Warnings: $($warnings.Count) (see log file for details)" -Level WARN -Component "Main"
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
