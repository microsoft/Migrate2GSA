<#
.SYNOPSIS
    Exports Microsoft Entra Private Access application configurations to CSV format.

.DESCRIPTION
    Retrieves all Entra Private Access (EPA) application configurations from an existing
    Entra tenant and exports them to a CSV file. The exported CSV is formatted to be directly
    compatible with the Start-EntraPrivateAccessProvisioning function, enabling backup/restore
    and migration scenarios.

    Each application segment creates one row in the CSV. Applications with multiple segments
    generate multiple rows with identical application-level properties.

.PARAMETER OutputPath
    Directory where the timestamped backup folder will be created.
    Defaults to the current directory.

.PARAMETER LogPath
    Path for the log file. Defaults to the timestamped backup folder.

.EXAMPLE
    Export-EntraPrivateAccessConfig

    Exports to current directory: .\GSA-backup_20260203_143022\PrivateAccess\

.EXAMPLE
    Export-EntraPrivateAccessConfig -OutputPath "C:\GSA-Backups"

    Exports to: C:\GSA-Backups\GSA-backup_20260203_143022\PrivateAccess\

.EXAMPLE
    Export-EntraPrivateAccessConfig -OutputPath "C:\Backups" -LogPath "C:\Logs\EPA-Export.log"

    Custom log location outside the backup folder.

.NOTES
    Author: Franck Heilmann and Andres Canello
    Version: 1.0
    Requires: PowerShell 7+, Microsoft.Graph.Authentication module
    Required scopes: Application.Read.All, Directory.Read.All, NetworkAccess.Read.All
#>

function Export-EntraPrivateAccessConfig {
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = "Directory where timestamped backup folder will be created")]
        [string]$OutputPath = $PWD,

        [Parameter(HelpMessage = "Path for the log file")]
        [string]$LogPath
    )

    #region Initialization
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFolderName = "GSA-backup_$timestamp"
    $privateAccessFolder = Join-Path -Path $OutputPath -ChildPath $backupFolderName | Join-Path -ChildPath "PrivateAccess"
    $csvFileName = "${timestamp}_EPA_Config.csv"
    $csvFilePath = Join-Path -Path $privateAccessFolder -ChildPath $csvFileName

    # Set log path
    if (-not $LogPath) {
        $LogPath = Join-Path -Path $privateAccessFolder -ChildPath "${timestamp}_Export-EPA.log"
    }

    # Validate OutputPath write permissions by creating the folder structure
    try {
        if (-not (Test-Path -Path $privateAccessFolder)) {
            New-Item -Path $privateAccessFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
    }
    catch {
        Write-Error "Cannot create output folder '$privateAccessFolder': $_"
        throw "Output path validation failed. Ensure you have write permissions to '$OutputPath'."
    }

    # Set script-scoped LogPath for Write-LogMessage
    $script:LogPath = $LogPath

    # Initialize caches and counters
    $connectorGroupCache = @{}
    $groupCache = @{}
    $userCache = @{}
    $graphApiCalls = 0
    $cachedLookups = 0
    $warningCount = 0
    $errorCount = 0
    $startTime = Get-Date
    #endregion

    #region Validation
    Write-LogMessage "Starting Entra Private Access configuration export..." -Level INFO -Component "Export"
    Write-LogMessage "Output folder: $privateAccessFolder" -Level INFO -Component "Export"
    Write-LogMessage "Timestamp: $timestamp" -Level INFO -Component "Export"

    # Validate required PowerShell modules
    $requiredModules = @('Microsoft.Graph.Authentication')
    Test-RequiredModules -RequiredModules $requiredModules

    # Validate Graph connection with read-only scopes
    $requiredScopes = @(
        'Application.Read.All',
        'Directory.Read.All',
        'NetworkAccess.Read.All'
    )
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

    # Validate Private Access feature is enabled
    Write-LogMessage "Validating Private Access feature is enabled..." -Level INFO -Component "Validation"
    $paProfile = Get-IntNetworkAccessForwardingProfile -ProfileType 'private'
    $graphApiCalls++
    if (-not $paProfile -or $paProfile.state -ne 'enabled') {
        $currentState = if ($paProfile) { $paProfile.state } else { 'not found' }
        Write-LogMessage "Private Access is not enabled on this tenant. Current state: $currentState" -Level ERROR -Component "Validation"
        throw "Private Access feature validation failed. Please enable Private Access before exporting."
    }
    Write-LogMessage "Private Access feature validated: enabled" -Level SUCCESS -Component "Validation"

    # Check connector groups availability and build cache
    Write-LogMessage "Checking connector groups availability..." -Level INFO -Component "Validation"
    $allConnectorGroups = Get-IntApplicationProxyConnectorGroup
    $graphApiCalls++
    if (-not $allConnectorGroups -or @($allConnectorGroups).Count -eq 0) {
        Write-LogMessage "No connector groups found in tenant. Exported apps will have empty ConnectorGroup field." -Level WARN -Component "Validation"
        $warningCount++
    }
    else {
        $cgCount = @($allConnectorGroups).Count
        Write-LogMessage "Found $cgCount connector group(s) in tenant" -Level INFO -Component "Validation"
        # Pre-populate connector group cache (ID -> Name)
        foreach ($cg in $allConnectorGroups) {
            $connectorGroupCache[$cg.id] = $cg.name
        }
    }
    #endregion

    #region Retrieve Applications
    Write-Progress -Activity "Exporting Private Access Configuration" -Status "Retrieving applications..." -PercentComplete 10

    Write-LogMessage "Retrieving Private Access applications..." -Level INFO -Component "Export"
    $applications = Get-IntPrivateAccessApp
    $graphApiCalls++

    if (-not $applications -or @($applications).Count -eq 0) {
        Write-LogMessage "No Private Access applications found in tenant. Creating empty CSV with headers." -Level WARN -Component "Export"
        $warningCount++

        # Create empty CSV with headers
        $emptyRow = [PSCustomObject]@{
            EnterpriseAppName = $null
            SegmentId         = $null
            isQuickAccess     = $null
            destinationHost   = $null
            DestinationType   = $null
            Protocol          = $null
            Ports             = $null
            ConnectorGroup    = $null
            Provision         = $null
            EntraGroups       = $null
            EntraUsers        = $null
        }
        @($emptyRow) | Select-Object * | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8
        # Remove data row, keep only headers
        $headerLine = Get-Content -Path $csvFilePath -First 1
        Set-Content -Path $csvFilePath -Value $headerLine -Encoding UTF8

        Write-Progress -Activity "Exporting Private Access Configuration" -Completed
        Write-LogMessage "Export completed. Empty CSV created at: $csvFilePath" -Level SUCCESS -Component "Export"
        return
    }

    $applications = @($applications)

    # Identify Quick Access applications (tagged with NetworkAccessQuickAccessApplication)
    $quickAccessAppIds = @{}
    $quickAccessApps = @($applications | Where-Object { $_.tags -contains 'NetworkAccessQuickAccessApplication' })
    if ($quickAccessApps.Count -gt 0) {
        foreach ($qaApp in $quickAccessApps) {
            $quickAccessAppIds[$qaApp.id] = $true
            Write-LogMessage "Found Quick Access application '$($qaApp.displayName)' (ID: $($qaApp.id))" -Level INFO -Component "Export"
        }
    }

    $totalApps = $applications.Count
    Write-LogMessage "Found $totalApps Private Access application(s) to export" -Level INFO -Component "Export"
    #endregion

    #region Process Applications
    $csvRows = @()
    $totalSegments = 0
    $appsWithNoSegments = 0
    $appsWithNoConnectorGroup = 0
    $deletedConnectorGroups = 0
    $appsWithNoAssignments = 0
    $allUniqueGroups = @{}
    $allUniqueUsers = @{}
    $maxSegmentsApp = ""
    $maxSegmentsCount = 0
    $currentAppIndex = 0

    foreach ($app in $applications) {
        $currentAppIndex++
        $percentComplete = (($currentAppIndex / $totalApps) * 80) + 20
        Write-Progress -Activity "Exporting Private Access Configuration" `
            -Status "Processing application $currentAppIndex of ${totalApps}: $($app.displayName)" `
            -PercentComplete $percentComplete

        Write-LogMessage "Processing application $currentAppIndex/${totalApps}: $($app.displayName) (ID: $($app.id))" -Level INFO -Component "Export"

        $appName = $app.displayName
        $appObjectId = $app.id
        $appClientId = $app.appId
        $isQuickAccess = if ($quickAccessAppIds.ContainsKey($appObjectId)) { "yes" } else { "no" }

        #region Connector Group
        $connectorGroupName = ""
        try {
            $publishingInfo = Get-IntApplicationOnPremisesPublishing -ApplicationId $appObjectId
            $graphApiCalls += 2  # Two API calls inside (onPremisesPublishing + connectorGroup)

            if ($publishingInfo.connectorGroup) {
                $cgId = $publishingInfo.connectorGroup.id
                $cgName = $publishingInfo.connectorGroup.name

                if ($cgName) {
                    $connectorGroupName = $cgName
                    # Update cache
                    if (-not $connectorGroupCache.ContainsKey($cgId)) {
                        $connectorGroupCache[$cgId] = $cgName
                    }
                }
                elseif ($cgId -and $connectorGroupCache.ContainsKey($cgId)) {
                    $connectorGroupName = $connectorGroupCache[$cgId]
                    $cachedLookups++
                }
                elseif ($cgId) {
                    $connectorGroupName = "[DELETED]_$cgId"
                    $deletedConnectorGroups++
                    Write-LogMessage "Connector group ID '$cgId' referenced by app '$appName' but name not resolved (likely deleted)" -Level WARN -Component "Export"
                    $warningCount++
                }
            }
            else {
                $appsWithNoConnectorGroup++
                Write-LogMessage "Application '$appName' has no connector group assigned" -Level WARN -Component "Export"
                $warningCount++
            }
        }
        catch {
            Write-LogMessage "Failed to retrieve connector group for application '$appName': $_" -Level WARN -Component "Export"
            $warningCount++
        }
        #endregion

        #region Service Principal and Assignments
        $entraGroups = ""
        $entraUsers = ""

        try {
            $servicePrincipal = Get-IntServicePrincipal -Filter "appId eq '$appClientId'"
            $graphApiCalls++

            if ($servicePrincipal) {
                $spId = $servicePrincipal.Id
                if (-not $spId) { $spId = $servicePrincipal.id }

                try {
                    $assignments = Get-IntServicePrincipalAppRoleAssignedTo -ServicePrincipalId $spId
                    $graphApiCalls++

                    if ($assignments) {
                        $assignments = @($assignments)

                        # Process group assignments
                        $groupAssignments = $assignments | Where-Object { $_.principalType -eq 'Group' }
                        $groupNames = @()
                        foreach ($ga in $groupAssignments) {
                            $groupId = $ga.principalId
                            if (-not $groupId) { $groupId = $ga.PrincipalId }

                            $groupName = $null

                            # Try principalDisplayName first (available directly from assignment)
                            if ($ga.principalDisplayName) {
                                $groupName = $ga.principalDisplayName
                                $groupCache[$groupId] = $groupName
                            }
                            elseif ($ga.PrincipalDisplayName) {
                                $groupName = $ga.PrincipalDisplayName
                                $groupCache[$groupId] = $groupName
                            }
                            # Try cache
                            elseif ($groupCache.ContainsKey($groupId)) {
                                $groupName = $groupCache[$groupId]
                                $cachedLookups++
                            }
                            # Resolve via API
                            else {
                                try {
                                    $groupObj = Get-IntGroup -Filter "id eq '$groupId'"
                                    $graphApiCalls++
                                    if ($groupObj) {
                                        $groupName = $groupObj.displayName
                                        $groupCache[$groupId] = $groupName
                                    }
                                }
                                catch {
                                    Write-LogMessage "Failed to resolve group ID '$groupId' for app '$appName': $_" -Level WARN -Component "Export"
                                    $warningCount++
                                }
                            }

                            if ($groupName) {
                                $groupNames += $groupName
                                $allUniqueGroups[$groupName] = $true
                            }
                        }
                        if ($groupNames.Count -gt 0) {
                            $entraGroups = $groupNames -join ';'
                        }

                        # Process user assignments
                        $userAssignments = $assignments | Where-Object { $_.principalType -eq 'User' }
                        $userUpns = @()
                        foreach ($ua in $userAssignments) {
                            $userId = $ua.principalId
                            if (-not $userId) { $userId = $ua.PrincipalId }

                            $userUpn = $null

                            # Try cache first
                            if ($userCache.ContainsKey($userId)) {
                                $userUpn = $userCache[$userId]
                                $cachedLookups++
                            }
                            else {
                                try {
                                    $userObj = Get-IntUser -Filter "id eq '$userId'"
                                    $graphApiCalls++
                                    if ($userObj) {
                                        $userUpn = $userObj.userPrincipalName
                                        $userCache[$userId] = $userUpn
                                    }
                                }
                                catch {
                                    Write-LogMessage "Failed to resolve user ID '$userId' for app '$appName': $_" -Level WARN -Component "Export"
                                    $warningCount++
                                }
                            }

                            if ($userUpn) {
                                $userUpns += $userUpn
                                $allUniqueUsers[$userUpn] = $true
                            }
                        }
                        if ($userUpns.Count -gt 0) {
                            $entraUsers = $userUpns -join ';'
                        }
                    }

                    if ([string]::IsNullOrEmpty($entraGroups) -and [string]::IsNullOrEmpty($entraUsers)) {
                        $appsWithNoAssignments++
                        Write-LogMessage "Application '$appName' has no user/group assignments" -Level WARN -Component "Export"
                        $warningCount++
                    }
                }
                catch {
                    Write-LogMessage "Failed to retrieve assignments for app '$appName': $_" -Level WARN -Component "Export"
                    $warningCount++
                }
            }
            else {
                Write-LogMessage "Service principal not found for app '$appName' (appId: $appClientId). Assignments will be empty." -Level WARN -Component "Export"
                $warningCount++
            }
        }
        catch {
            Write-LogMessage "Failed to retrieve service principal for app '$appName': $_" -Level WARN -Component "Export"
            $warningCount++
        }
        #endregion

        #region Segments
        try {
            $segments = Get-IntPrivateAccessAppSegment -ApplicationId $appObjectId
            $graphApiCalls++

            if (-not $segments -or @($segments).Count -eq 0) {
                Write-LogMessage "Application '$appName' has no segments. Skipping." -Level WARN -Component "Export"
                $warningCount++
                $appsWithNoSegments++
                continue
            }

            $segments = @($segments)
            $segmentCount = $segments.Count
            $totalSegments += $segmentCount

            if ($segmentCount -gt $maxSegmentsCount) {
                $maxSegmentsCount = $segmentCount
                $maxSegmentsApp = $appName
            }

            Write-LogMessage "  Found $segmentCount segment(s) for '$appName'" -Level INFO -Component "Export"

            foreach ($segment in $segments) {
                $segmentId = $segment.id
                $destHost = $segment.destinationHost
                $destType = $segment.destinationType
                $protocol = $segment.protocol

                # Map Graph API destinationType values to provisioning-compatible values
                # API returns: ip, ipRange, ipRangeCidr, fqdn, dnsSuffix
                # Provisioning expects: ipAddress, ipRange, ipRangeCidr, FQDN, dnsSuffix
                switch ($destType) {
                    'ip'          { $destType = 'ipAddress' }
                    'ipRangeCidr' { $destType = 'ipRangeCidr' }
                    'ipRange'     { $destType = 'ipRange' }
                    'fqdn'        { $destType = 'FQDN' }
                    'dnsSuffix'   { $destType = 'dnsSuffix' }
                }

                #region Segment Validation
                # Destination host validation
                if ([string]::IsNullOrWhiteSpace($destHost)) {
                    Write-LogMessage "Segment '$segmentId' in app '$appName' has empty destinationHost. Skipping segment." -Level ERROR -Component "Export"
                    $errorCount++
                    continue
                }

                # dnsSuffix segments define DNS suffixes only; protocol and ports are not applicable.
                # Export them with empty Protocol/Ports and Provision=no (not yet supported by provisioning).
                if ($destType -eq 'dnsSuffix') {
                    $csvRows += [PSCustomObject]@{
                        EnterpriseAppName = $appName
                        SegmentId         = $segmentId
                        isQuickAccess     = $isQuickAccess
                        destinationHost   = $destHost
                        DestinationType   = $destType
                        Protocol          = ""
                        Ports             = ""
                        ConnectorGroup    = $connectorGroupName
                        Provision         = "no"
                        EntraGroups       = $entraGroups
                        EntraUsers        = $entraUsers
                    }
                    continue
                }

                # Map numeric privateNetworkProtocol enum values to string equivalents
                # Graph beta API may return enum ordinals as int or string: 0/"0"=tcp, 1/"1"=udp
                switch ($protocol) {
                    { $_ -eq 0 -or $_ -eq '0' } { $protocol = 'tcp' }
                    { $_ -eq 1 -or $_ -eq '1' } { $protocol = 'udp' }
                }

                if ($destHost -match '^(localhost|127\.0\.0\.1|0\.0\.0\.0)$') {
                    Write-LogMessage "Segment '$segmentId' in app '$appName' has suspicious destination: $destHost" -Level WARN -Component "Export"
                    $warningCount++
                }

                # Protocol validation
                if ($protocol -and $protocol -notin @('tcp', 'udp', 'tcp,udp', 'udp,tcp')) {
                    Write-LogMessage "Segment '$segmentId' in app '$appName' has unexpected protocol: $protocol" -Level WARN -Component "Export"
                    $warningCount++
                }

                # Destination type vs host consistency
                switch ($destType) {
                    'FQDN' {
                        if ($destHost -notmatch '\.') {
                            Write-LogMessage "Segment '$segmentId' in app '$appName': destinationType is 'FQDN' but '$destHost' doesn't look like an FQDN" -Level WARN -Component "Export"
                            $warningCount++
                        }
                    }
                    'ipAddress' {
                        if ($destHost -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                            Write-LogMessage "Segment '$segmentId' in app '$appName': destinationType is 'ipAddress' but '$destHost' doesn't look like an IP" -Level WARN -Component "Export"
                            $warningCount++
                        }
                    }
                    'ipRangeCidr' {
                        if ($destHost -notmatch '/\d+$') {
                            Write-LogMessage "Segment '$segmentId' in app '$appName': destinationType is 'ipRangeCidr' but '$destHost' doesn't look like CIDR notation" -Level WARN -Component "Export"
                            $warningCount++
                        }
                    }
                    'ipRange' {
                        if ($destHost -notmatch '\.\.\d') {
                            Write-LogMessage "Segment '$segmentId' in app '$appName': destinationType is 'ipRange' but '$destHost' doesn't look like a valid IP range (start..end)" -Level WARN -Component "Export"
                            $warningCount++
                        }
                    }
                }
                #endregion

                #region Port Processing
                # Graph API returns ports as array of strings like ["445-445", "80-80", "8080-8090"]
                $portsString = ""
                if ($segment.ports) {
                    $portParts = @()
                    foreach ($portEntry in $segment.ports) {
                        if ($portEntry -match '^(\d+)-(\d+)$') {
                            $startPort = [int]$Matches[1]
                            $endPort = [int]$Matches[2]

                            # Validate port range
                            if ($startPort -lt 1 -or $startPort -gt 65535 -or $endPort -lt 1 -or $endPort -gt 65535) {
                                Write-LogMessage "Segment '$segmentId' in app '$appName' has invalid port range: $portEntry" -Level WARN -Component "Export"
                                $warningCount++
                                continue
                            }

                            if ($startPort -eq $endPort) {
                                # Single port (e.g., "445-445" -> "445")
                                $portParts += "$startPort"
                            }
                            else {
                                # Port range (e.g., "8080-8090")
                                $portParts += $portEntry
                            }
                        }
                        else {
                            $portParts += $portEntry
                        }
                    }
                    $portsString = $portParts -join ','
                }
                #endregion

                # Build CSV row
                $csvRows += [PSCustomObject]@{
                    EnterpriseAppName = $appName
                    SegmentId         = $segmentId
                    isQuickAccess     = $isQuickAccess
                    destinationHost   = $destHost
                    DestinationType   = $destType
                    Protocol          = $protocol
                    Ports             = $portsString
                    ConnectorGroup    = $connectorGroupName
                    Provision         = "no"
                    EntraGroups       = $entraGroups
                    EntraUsers        = $entraUsers
                }
            }
        }
        catch {
            Write-LogMessage "Failed to retrieve segments for app '$appName': $_" -Level ERROR -Component "Export"
            $errorCount++
        }
        #endregion
    }
    #endregion

    #region Write CSV
    Write-Progress -Activity "Exporting Private Access Configuration" -Status "Writing CSV file..." -PercentComplete 95

    try {
        if ($csvRows.Count -gt 0) {
            $csvRows | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8
        }
        else {
            # Create empty CSV with headers only
            $emptyRow = [PSCustomObject]@{
                EnterpriseAppName = $null
                SegmentId         = $null
                isQuickAccess     = $null
                destinationHost   = $null
                DestinationType   = $null
                Protocol          = $null
                Ports             = $null
                ConnectorGroup    = $null
                Provision         = $null
                EntraGroups       = $null
                EntraUsers        = $null
            }
            @($emptyRow) | Select-Object * | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8
            $headerLine = Get-Content -Path $csvFilePath -First 1
            Set-Content -Path $csvFilePath -Value $headerLine -Encoding UTF8
        }

        $csvFileInfo = Get-Item -Path $csvFilePath
        $csvSizeKB = [math]::Round($csvFileInfo.Length / 1KB, 1)
        Write-LogMessage "CSV file written: $csvFilePath ($csvSizeKB KB, $($csvRows.Count) rows)" -Level SUCCESS -Component "Export"
    }
    catch {
        Write-LogMessage "Failed to write CSV file: $_" -Level ERROR -Component "Export"
        throw "CSV export failed: $_"
    }
    #endregion

    Write-Progress -Activity "Exporting Private Access Configuration" -Completed

    #region Summary Report
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationSeconds = [math]::Round($duration.TotalSeconds, 1)
    $avgSegments = if ($totalApps -gt 0 -and ($totalApps - $appsWithNoSegments) -gt 0) {
        [math]::Round($totalSegments / ($totalApps - $appsWithNoSegments), 1)
    }
    else { 0 }

    $logFileInfo = if (Test-Path $LogPath) { Get-Item -Path $LogPath } else { $null }
    $logSizeKB = if ($logFileInfo) { [math]::Round($logFileInfo.Length / 1KB, 1) } else { 0 }

    # Build backup folder path (parent of PrivateAccess)
    $backupFolder = Split-Path -Path $privateAccessFolder -Parent

    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "=== EXPORT SUMMARY ===" -Level SUMMARY -Component "Summary"
    Write-LogMessage "Export completed successfully!" -Level SUCCESS -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "Backup folder: $backupFolder" -Level SUMMARY -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "Entra Private Access (EPA):" -Level SUMMARY -Component "Summary"
    Write-LogMessage "  Exported: $totalApps Applications" -Level SUMMARY -Component "Summary"
    Write-LogMessage "  Exported: $totalSegments Segments" -Level SUMMARY -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "  Connector Groups:" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Unique connector groups referenced: $($connectorGroupCache.Count)" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Apps with no connector group: $appsWithNoConnectorGroup" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Deleted connector groups detected: $deletedConnectorGroups" -Level SUMMARY -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "  Assignments:" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Apps with no user/group assignments: $appsWithNoAssignments" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Total unique groups assigned: $($allUniqueGroups.Count)" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Total unique users assigned: $($allUniqueUsers.Count)" -Level SUMMARY -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "  Segment Statistics:" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Average segments per app: $avgSegments" -Level SUMMARY -Component "Summary"
    if ($maxSegmentsApp) {
        Write-LogMessage "    App with most segments: $maxSegmentsApp ($maxSegmentsCount segments)" -Level SUMMARY -Component "Summary"
    }
    Write-LogMessage "    Apps with no segments: $appsWithNoSegments" -Level SUMMARY -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "  Performance:" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Graph API calls made: $graphApiCalls" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Cached lookups used: $cachedLookups" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Total duration: $durationSeconds seconds" -Level SUMMARY -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "  Warnings: $warningCount (see log file for details)" -Level SUMMARY -Component "Summary"
    Write-LogMessage "  Errors: $errorCount" -Level SUMMARY -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "Files created in PrivateAccess\:" -Level SUMMARY -Component "Summary"
    Write-LogMessage "  - $csvFileName ($csvSizeKB KB)" -Level SUMMARY -Component "Summary"
    Write-LogMessage "  - $(Split-Path -Path $LogPath -Leaf) ($logSizeKB KB)" -Level SUMMARY -Component "Summary"
    #endregion
}
