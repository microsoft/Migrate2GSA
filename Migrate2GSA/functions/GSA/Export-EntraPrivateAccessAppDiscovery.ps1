<#
.SYNOPSIS
    Exports Microsoft Entra Private Access App Discovery data to CSV format.

.DESCRIPTION
    Retrieves App Discovery data from Microsoft Entra Private Access via the Graph API and
    exports discovered segments to a CSV file compatible with Start-EntraPrivateAccessProvisioning.

    App Discovery captures network traffic observed flowing through the Global Secure Access client,
    revealing destination hosts and ports that users are actively accessing. This data is invaluable
    for identifying resources that should be published as formal Private Access applications.

    The most valuable scenario is exporting quickAccess discovered segments, which represent traffic
    flowing through the Quick Access application (a catch-all) that should ideally be converted into
    dedicated named Private Access applications for better governance and access control.

    For each discovered segment, the function also retrieves the list of users who accessed it and
    populates the EntraUsers column with their UPNs.

.PARAMETER OutputPath
    Directory where the timestamped backup folder will be created.
    Defaults to the current directory.

.PARAMETER DaysBack
    Number of days back from today for the discovery report window.
    Must be between 1 and 180. Default: 30.

.PARAMETER AccessTypeFilter
    Filter by access type: 'quickAccess', 'appAccess', or 'all'.
    Default: 'quickAccess'.

.PARAMETER Top
    Maximum number of records to return from the API (ordered by userCount descending).
    Must be between 1 and 5000. Default: 500.

.PARAMETER ResolveAppNames
    Whether to query traffic logs to resolve the application ID and display name
    for each discovered segment. When enabled, populates OriginalAppId and
    OriginalAppName from the applicationSnapshot in traffic logs.
    Default: $true.

.PARAMETER LogPath
    Path for the log file. Defaults to the timestamped backup folder.

.EXAMPLE
    Export-EntraPrivateAccessAppDiscovery

    Exports quickAccess discovered segments from the last 30 days.

.EXAMPLE
    Export-EntraPrivateAccessAppDiscovery -AccessTypeFilter all

    Exports both quickAccess and appAccess discovered segments.

.EXAMPLE
    Export-EntraPrivateAccessAppDiscovery -DaysBack 90 -OutputPath "C:\GSA-Backups"

    Exports last 90 days of discovery data to a custom location.

.EXAMPLE
    Export-EntraPrivateAccessAppDiscovery -Top 2000 -AccessTypeFilter all

    Retrieves up to 2000 discovered segments of all access types.

.EXAMPLE
    # End-to-end workflow: Discovery to Provisioning
    Export-EntraPrivateAccessAppDiscovery -DaysBack 30
    # Review and edit the CSV (set EnterpriseAppName, ConnectorGroup, EntraGroups, Provision=Yes)
    Start-EntraPrivateAccessProvisioning -ProvisioningConfigPath ".\GSA-backup_...\PrivateAccess\..._EPA_AppDiscovery.csv"

.NOTES
    Author: Andres Canello
    Version: 1.0
    Requires: PowerShell 7+, Microsoft.Graph.Authentication module
    Required scopes: NetworkAccess.Read.All, NetworkAccessPolicy.Read.All, Application.Read.All (when ResolveAppNames is enabled)
#>

function Export-EntraPrivateAccessAppDiscovery {
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = "Directory where timestamped backup folder will be created")]
        [string]$OutputPath = $PWD,

        [Parameter(HelpMessage = "Number of days back from today for the discovery report window")]
        [ValidateRange(1, 180)]
        [int]$DaysBack = 30,

        [Parameter(HelpMessage = "Filter by access type: quickAccess, appAccess, or all")]
        [ValidateSet('quickAccess', 'appAccess', 'all')]
        [string]$AccessTypeFilter = 'quickAccess',

        [Parameter(HelpMessage = "Maximum number of records to return from the API")]
        [ValidateRange(1, 5000)]
        [int]$Top = 500,

        [Parameter(HelpMessage = "Resolve application names from traffic logs")]
        [bool]$ResolveAppNames = $true,

        [Parameter(HelpMessage = "Path for the log file")]
        [string]$LogPath
    )

    #region Initialization
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupFolderName = "GSA-backup_$timestamp"
    $privateAccessFolder = Join-Path -Path $OutputPath -ChildPath $backupFolderName | Join-Path -ChildPath "PrivateAccess"
    $csvFileName = "${timestamp}_EPA_AppDiscovery.csv"
    $csvFilePath = Join-Path -Path $privateAccessFolder -ChildPath $csvFileName

    # Set log path
    if (-not $LogPath) {
        $LogPath = Join-Path -Path $privateAccessFolder -ChildPath "${timestamp}_Export-EPA-Discovery.log"
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

    # Initialize counters
    $warningCount = 0
    $skippedRecords = 0
    $failedUserReportCount = 0
    $failedAppResolveCount = 0
    $startTime = Get-Date
    #endregion

    #region Validation
    Write-LogMessage "Starting Entra Private Access App Discovery export..." -Level INFO -Component "Export"
    Write-LogMessage "Output folder: $privateAccessFolder" -Level INFO -Component "Export"
    Write-LogMessage "Timestamp: $timestamp" -Level INFO -Component "Export"
    Write-LogMessage "Parameters: DaysBack=$DaysBack, AccessTypeFilter=$AccessTypeFilter, Top=$Top, ResolveAppNames=$ResolveAppNames" -Level INFO -Component "Export"

    # Validate required PowerShell modules
    $requiredModules = @('Microsoft.Graph.Authentication')
    Test-RequiredModules -RequiredModules $requiredModules

    # Validate Graph connection with required scopes
    $requiredScopes = @(
        'NetworkAccess.Read.All',
        'NetworkAccessPolicy.Read.All'
    )
    if ($ResolveAppNames) {
        $requiredScopes += 'Application.Read.All'
    }
    Test-GraphConnection -RequiredScopes $requiredScopes

    # Validate GSA tenant onboarding status
    Write-LogMessage "Validating Global Secure Access tenant onboarding status..." -Level INFO -Component "Validation"
    $tenantStatus = Get-IntGSATenantStatus
    if ($tenantStatus.onboardingStatus -ne 'onboarded') {
        Write-LogMessage "Global Secure Access has not been activated on this tenant. Current onboarding status: $($tenantStatus.onboardingStatus)." -Level ERROR -Component "Validation"
        throw "Tenant onboarding validation failed. Status: $($tenantStatus.onboardingStatus)"
    }
    Write-LogMessage "Global Secure Access tenant status validated: $($tenantStatus.onboardingStatus)" -Level SUCCESS -Component "Validation"

    # Validate Private Access feature is enabled
    Write-LogMessage "Validating Private Access feature is enabled..." -Level INFO -Component "Validation"
    $paProfile = Get-IntNetworkAccessForwardingProfile -ProfileType 'private'
    if (-not $paProfile -or $paProfile.state -ne 'enabled') {
        $currentState = if ($paProfile) { $paProfile.state } else { 'not found' }
        Write-LogMessage "Private Access is not enabled on this tenant. Current state: $currentState" -Level ERROR -Component "Validation"
        throw "Private Access feature validation failed. Please enable Private Access before exporting."
    }
    Write-LogMessage "Private Access feature validated: enabled" -Level SUCCESS -Component "Validation"
    #endregion

    #region Compute Date Range
    $endDateTime = (Get-Date).ToUniversalTime()
    $startDateTime = $endDateTime.AddDays(-$DaysBack)

    $startDateTimeStr = $startDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $endDateTimeStr = $endDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

    Write-LogMessage "Discovery date range: $startDateTimeStr to $endDateTimeStr ($DaysBack days)" -Level INFO -Component "Discovery"
    #endregion

    #region Retrieve Discovered Segments
    Write-Progress -Activity "Exporting App Discovery Data" -Status "Retrieving discovered segments..." -PercentComplete 10

    Write-LogMessage "Retrieving discovered application segments..." -Level INFO -Component "Discovery"

    $accessTypeParam = @{}
    if ($AccessTypeFilter -ne 'all') {
        $accessTypeParam['AccessTypeFilter'] = $AccessTypeFilter
    }

    try {
        $response = Get-IntDiscoveredApplicationSegmentReport `
            -StartDateTime $startDateTime `
            -EndDateTime $endDateTime `
            -Top $Top `
            @accessTypeParam
    }
    catch {
        Write-LogMessage "Failed to retrieve discovered application segments: $_" -Level ERROR -Component "Discovery"
        throw
    }

    if (-not $response -or @($response).Count -eq 0) {
        Write-LogMessage "No discovered segments found for the specified date range and filters." -Level WARN -Component "Discovery"
        $warningCount++

        # Create headers-only CSV
        [PSCustomObject]@{
            SegmentId = $null; OriginalAppId = $null; OriginalAppName = $null
            EnterpriseAppName = $null
            destinationHost = $null; DestinationType = $null; Protocol = $null
            Ports = $null
            EntraGroups = $null; EntraUsers = $null; ConnectorGroup = $null
            Provision = $null
            isQuickAccess = $null; DiscoveryAccessType = $null
            FirstAccessDateTime = $null; LastAccessDateTime = $null
            TransactionCount = $null; UserCount = $null; DeviceCount = $null
            TotalBytesSent = $null; TotalBytesReceived = $null
            DiscoveredApplicationSegmentId = $null
        } | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8
        # Remove the data row (keep only headers)
        $headerLine = (Get-Content -Path $csvFilePath -First 1)
        Set-Content -Path $csvFilePath -Value $headerLine -Encoding UTF8
        Write-LogMessage "No discovered segments found. Created empty CSV with headers only." -Level WARN -Component "Export"

        Write-Progress -Activity "Exporting App Discovery Data" -Completed
        return
    }

    $response = @($response)
    $totalSegments = $response.Count
    Write-LogMessage "Found $totalSegments discovered segment(s)" -Level INFO -Component "Discovery"
    #endregion

    #region Retrieve Users Per Segment
    Write-LogMessage "Retrieving users per discovered segment ($totalSegments segments)..." -Level INFO -Component "UserReport"

    $currentSegmentIndex = 0
    $segmentUserMap = @{}

    foreach ($segment in $response) {
        $currentSegmentIndex++
        $segmentId = $segment.discoveredApplicationSegmentId

        Write-Progress -Activity "Exporting App Discovery Data" `
            -Status "Retrieving users for segment $currentSegmentIndex of $totalSegments" `
            -PercentComplete (10 + (($currentSegmentIndex / $totalSegments) * 60))

        try {
            $userResponse = Get-IntDiscoveredApplicationSegmentUserReport `
                -StartDateTime $startDateTime `
                -EndDateTime $endDateTime `
                -DiscoveredApplicationSegmentId $segmentId

            if ($userResponse -and @($userResponse).Count -gt 0) {
                $upnList = ($userResponse | Where-Object { $_.userPrincipalName } |
                            Select-Object -ExpandProperty userPrincipalName -Unique) -join ';'
                $segmentUserMap[$segmentId] = $upnList
            }
            else {
                $segmentUserMap[$segmentId] = ""
            }
        }
        catch {
            $failedUserReportCount++
            Write-LogMessage "Failed to retrieve users for segment $currentSegmentIndex ($segmentId): $_" -Level WARN -Component "UserReport"
            $segmentUserMap[$segmentId] = ""
        }
    }

    Write-Progress -Activity "Exporting App Discovery Data" -Status "Processing segments..." -PercentComplete 75

    if ($failedUserReportCount -gt 0) {
        Write-LogMessage "User resolution failed for $failedUserReportCount of $totalSegments segments. Those segments will have empty EntraUsers." -Level WARN -Component "UserReport"
        $warningCount += $failedUserReportCount
    }
    else {
        Write-LogMessage "Successfully retrieved user data for $totalSegments segments" -Level SUCCESS -Component "UserReport"
    }
    #endregion

    #region Resolve Application Names from Traffic Logs
    $segmentAppIdMap = @{}
    $appIdNameMap = @{}

    if ($ResolveAppNames) {
        Write-LogMessage "Resolving application IDs from traffic logs ($totalSegments segments)..." -Level INFO -Component "AppResolve"

        $currentResolveIndex = 0
        foreach ($segment in $response) {
            $currentResolveIndex++
            $segmentId = $segment.discoveredApplicationSegmentId

            Write-Progress -Activity "Exporting App Discovery Data" `
                -Status "Resolving app for segment $currentResolveIndex of $totalSegments" `
                -PercentComplete (75 + (($currentResolveIndex / $totalSegments) * 10))

            # Build destination filter based on FQDN or IP
            $destFilter = $null
            if (-not [string]::IsNullOrWhiteSpace($segment.fqdn)) {
                $destFilter = "destinationFQDN eq '$($segment.fqdn)'"
            }
            elseif (-not [string]::IsNullOrWhiteSpace($segment.ip)) {
                $destFilter = "destinationIp eq '$($segment.ip)'"
            }

            if (-not $destFilter) { continue }

            try {
                $trafficUri = "/beta/networkAccess/logs/traffic" +
                    "?`$filter=trafficType eq 'private'" +
                    " and $destFilter" +
                    " and destinationPort eq $($segment.port)" +
                    " and createdDateTime ge $startDateTimeStr" +
                    " and createdDateTime le $endDateTimeStr" +
                    "&`$select=applicationSnapshot" +
                    "&`$orderby=createdDateTime desc" +
                    "&`$top=1"

                $trafficResult = Invoke-InternalGraphRequest -Method GET -OutputType PSObject -Uri $trafficUri -DisablePagination

                $trafficEntry = $null
                if ($trafficResult.PSObject.Properties.Name -contains 'value') {
                    $trafficEntry = $trafficResult.value | Select-Object -First 1
                }
                elseif ($trafficResult) {
                    $trafficEntry = $trafficResult
                }

                if ($trafficEntry -and $trafficEntry.applicationSnapshot -and $trafficEntry.applicationSnapshot.appId) {
                    $appId = $trafficEntry.applicationSnapshot.appId
                    $segmentAppIdMap[$segmentId] = $appId

                    # Track unique appIds for batch resolution
                    if (-not $appIdNameMap.ContainsKey($appId)) {
                        $appIdNameMap[$appId] = $null
                    }
                }
            }
            catch {
                $failedAppResolveCount++
                Write-LogMessage "Failed to resolve app for segment $currentResolveIndex ($segmentId): $_" -Level WARN -Component "AppResolve"
            }
        }

        # Batch resolve unique appIds to display names
        $uniqueAppIds = @($appIdNameMap.Keys)
        if ($uniqueAppIds.Count -gt 0) {
            Write-LogMessage "Resolving display names for $($uniqueAppIds.Count) unique application(s)..." -Level INFO -Component "AppResolve"

            foreach ($appId in $uniqueAppIds) {
                try {
                    $spUri = "/beta/servicePrincipals?`$filter=appId eq '$appId'&`$select=appId,displayName&`$top=1"
                    $spResult = Invoke-InternalGraphRequest -Method GET -OutputType PSObject -Uri $spUri -DisablePagination

                    $sp = $null
                    if ($spResult.PSObject.Properties.Name -contains 'value') {
                        $sp = $spResult.value | Select-Object -First 1
                    }

                    if ($sp -and $sp.displayName) {
                        $appIdNameMap[$appId] = $sp.displayName
                    }
                    else {
                        $appIdNameMap[$appId] = ""
                    }
                }
                catch {
                    Write-LogMessage "Failed to resolve display name for appId $appId`: $_" -Level WARN -Component "AppResolve"
                    $appIdNameMap[$appId] = ""
                }
            }
        }

        $resolvedCount = ($segmentAppIdMap.Values | Where-Object { $_ }).Count
        if ($failedAppResolveCount -gt 0) {
            Write-LogMessage "App resolution failed for $failedAppResolveCount of $totalSegments segments." -Level WARN -Component "AppResolve"
            $warningCount += $failedAppResolveCount
        }
        Write-LogMessage "Resolved application IDs for $resolvedCount of $totalSegments segments ($($uniqueAppIds.Count) unique apps)" -Level SUCCESS -Component "AppResolve"
    }
    else {
        Write-LogMessage "App name resolution skipped (ResolveAppNames=$ResolveAppNames)" -Level INFO -Component "AppResolve"
    }
    #endregion

    #region Transform Records to CSV Rows
    $csvRows = @()
    $recordIndex = 0

    foreach ($segment in $response) {
        $recordIndex++

        # Determine destination host and type
        $destinationHost = $null
        $destinationType = $null

        if (-not [string]::IsNullOrWhiteSpace($segment.fqdn)) {
            $destinationHost = $segment.fqdn
            $destinationType = 'FQDN'
        }
        elseif (-not [string]::IsNullOrWhiteSpace($segment.ip)) {
            $destinationHost = $segment.ip
            $destinationType = 'ipAddress'
        }
        else {
            Write-LogMessage "Skipping record ${recordIndex}: both fqdn and ip are null" -Level WARN -Component "Transform"
            $warningCount++
            $skippedRecords++
            continue
        }

        # Resolve original app ID and name from traffic logs
        $segmentId = $segment.discoveredApplicationSegmentId
        $originalAppId = ""
        $originalAppName = "Discovered-$destinationHost"

        if ($segmentAppIdMap.ContainsKey($segmentId)) {
            $originalAppId = $segmentAppIdMap[$segmentId]
            $resolvedName = $appIdNameMap[$originalAppId]
            if (-not [string]::IsNullOrWhiteSpace($resolvedName)) {
                $originalAppName = $resolvedName
            }
        }

        # Get users for this segment from the pre-fetched map
        $entraUsers = $segmentUserMap[$segment.discoveredApplicationSegmentId]
        if (-not $entraUsers) { $entraUsers = "" }

        # Build CSV row
        $row = [PSCustomObject]@{
            SegmentId                      = "SEG-D-{0:D6}" -f $recordIndex
            OriginalAppId                  = $originalAppId
            OriginalAppName                = $originalAppName
            EnterpriseAppName              = "Placeholder_Review_Me"
            destinationHost                = $destinationHost
            DestinationType                = $destinationType
            Protocol                       = $segment.transportProtocol.ToUpper()
            Ports                          = [string]$segment.port
            EntraGroups                    = ""
            EntraUsers                     = $entraUsers
            ConnectorGroup                 = "Placeholder_Replace_Me"
            Provision                      = "No"
            isQuickAccess                  = "no"
            DiscoveryAccessType            = $segment.accessType
            FirstAccessDateTime            = $segment.firstAccessDateTime
            LastAccessDateTime             = $segment.lastAccessDateTime
            TransactionCount               = $segment.transactionCount
            UserCount                      = $segment.userCount
            DeviceCount                    = $segment.deviceCount
            TotalBytesSent                 = $segment.totalBytesSent
            TotalBytesReceived             = $segment.totalBytesReceived
            DiscoveredApplicationSegmentId = $segment.discoveredApplicationSegmentId
        }

        $csvRows += $row
    }
    #endregion

    #region Write CSV File
    Write-Progress -Activity "Exporting App Discovery Data" -Status "Writing CSV file..." -PercentComplete 90

    try {
        if ($csvRows.Count -gt 0) {
            $csvRows | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8
            Write-LogMessage "Exported $($csvRows.Count) discovered segments to: $csvFilePath" -Level SUCCESS -Component "Export"
        }
        else {
            # Write headers-only CSV
            [PSCustomObject]@{
                SegmentId = $null; OriginalAppId = $null; OriginalAppName = $null
                EnterpriseAppName = $null
                destinationHost = $null; DestinationType = $null; Protocol = $null
                Ports = $null
                EntraGroups = $null; EntraUsers = $null; ConnectorGroup = $null
                Provision = $null
                isQuickAccess = $null; DiscoveryAccessType = $null
                FirstAccessDateTime = $null; LastAccessDateTime = $null
                TransactionCount = $null; UserCount = $null; DeviceCount = $null
                TotalBytesSent = $null; TotalBytesReceived = $null
                DiscoveredApplicationSegmentId = $null
            } | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8
            $headerLine = (Get-Content -Path $csvFilePath -First 1)
            Set-Content -Path $csvFilePath -Value $headerLine -Encoding UTF8
            Write-LogMessage "No valid segments after transformation. Created empty CSV with headers only." -Level WARN -Component "Export"
        }

        $csvFileInfo = Get-Item -Path $csvFilePath
        $csvSizeKB = [math]::Round($csvFileInfo.Length / 1KB, 1)
    }
    catch {
        Write-LogMessage "Failed to write CSV file: $_" -Level ERROR -Component "Export"
        throw "CSV export failed: $_"
    }
    #endregion

    Write-Progress -Activity "Exporting App Discovery Data" -Completed

    #region Summary Report
    $endTime = Get-Date
    $duration = $endTime - $startTime
    $durationSeconds = [math]::Round($duration.TotalSeconds, 1)

    $logFileInfo = if (Test-Path $LogPath) { Get-Item -Path $LogPath } else { $null }
    $logSizeKB = if ($logFileInfo) { [math]::Round($logFileInfo.Length / 1KB, 1) } else { 0 }

    # Build backup folder path (parent of PrivateAccess)
    $backupFolder = Split-Path -Path $privateAccessFolder -Parent

    # Compute statistics
    $byAccessType = @{}
    $byDestType = @{}
    $byProtocol = @{}
    $totalTransactions = 0
    $totalBytesSent = 0
    $totalBytesReceived = 0
    $allUniqueUpns = @{}

    foreach ($row in $csvRows) {
        # Access type counts
        $at = $row.DiscoveryAccessType
        if ($at) { $byAccessType[$at] = ($byAccessType[$at] ?? 0) + 1 }

        # Destination type counts
        $dt = $row.DestinationType
        if ($dt) { $byDestType[$dt] = ($byDestType[$dt] ?? 0) + 1 }

        # Protocol counts
        $pr = $row.Protocol
        if ($pr) { $byProtocol[$pr] = ($byProtocol[$pr] ?? 0) + 1 }

        # Aggregate metrics
        $totalTransactions += [int]$row.TransactionCount
        $totalBytesSent += [long]$row.TotalBytesSent
        $totalBytesReceived += [long]$row.TotalBytesReceived

        # Collect unique UPNs
        if (-not [string]::IsNullOrWhiteSpace($row.EntraUsers)) {
            foreach ($upn in ($row.EntraUsers -split ';')) {
                if (-not [string]::IsNullOrWhiteSpace($upn)) {
                    $allUniqueUpns[$upn] = $true
                }
            }
        }
    }

    # Compute unique user and device counts from the raw response
    $totalUniqueUsers = ($response | Select-Object -ExpandProperty userCount -ErrorAction SilentlyContinue | Measure-Object -Maximum).Maximum
    $totalUniqueDevices = ($response | Select-Object -ExpandProperty deviceCount -ErrorAction SilentlyContinue | Measure-Object -Maximum).Maximum

    # Segments with users resolved vs failed
    $segmentsWithUsers = ($csvRows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.EntraUsers) }).Count

    # Top 5 destinations by user count (from raw response for accurate data)
    $topDestinations = $response | Sort-Object -Property userCount -Descending | Select-Object -First 5

    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "=== EXPORT SUMMARY ===" -Level SUMMARY -Component "Summary"
    Write-LogMessage "Export completed successfully!" -Level SUCCESS -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "Backup folder: $backupFolder\" -Level SUMMARY -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "Entra Private Access App Discovery:" -Level SUMMARY -Component "Summary"
    Write-LogMessage "  Discovery Window: $($startDateTime.ToString('yyyy-MM-dd')) to $($endDateTime.ToString('yyyy-MM-dd')) ($DaysBack days)" -Level SUMMARY -Component "Summary"
    Write-LogMessage "  Access Type Filter: $AccessTypeFilter" -Level SUMMARY -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "  Discovered Segments: $($csvRows.Count)" -Level SUMMARY -Component "Summary"

    # By access type
    Write-LogMessage "    By Access Type:" -Level SUMMARY -Component "Summary"
    foreach ($key in $byAccessType.Keys | Sort-Object) {
        Write-LogMessage "      ${key}: $($byAccessType[$key])" -Level SUMMARY -Component "Summary"
    }

    # By destination type
    Write-LogMessage "    By Destination Type:" -Level SUMMARY -Component "Summary"
    foreach ($key in $byDestType.Keys | Sort-Object) {
        $label = if ($key -eq 'ipAddress') { 'IP Address' } else { $key }
        Write-LogMessage "      ${label}: $($byDestType[$key])" -Level SUMMARY -Component "Summary"
    }

    # By protocol
    Write-LogMessage "    By Protocol:" -Level SUMMARY -Component "Summary"
    foreach ($key in $byProtocol.Keys | Sort-Object) {
        Write-LogMessage "      ${key}: $($byProtocol[$key])" -Level SUMMARY -Component "Summary"
    }

    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "  Usage Metrics (across all segments):" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Total Unique Users: $totalUniqueUsers" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Total Unique Devices: $totalUniqueDevices" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Total Transactions: $totalTransactions" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Total Bytes Sent: $($totalBytesSent.ToString('N0'))" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Total Bytes Received: $($totalBytesReceived.ToString('N0'))" -Level SUMMARY -Component "Summary"

    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "  User Resolution:" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Segments with users resolved: $segmentsWithUsers" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Segments with user resolution failed: $failedUserReportCount" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    Total unique UPNs collected: $($allUniqueUpns.Count)" -Level SUMMARY -Component "Summary"

    # App resolution stats
    if ($ResolveAppNames) {
        $segmentsWithAppId = ($csvRows | Where-Object { -not [string]::IsNullOrWhiteSpace($_.OriginalAppId) }).Count
        $uniqueAppsResolved = ($appIdNameMap.Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
        Write-LogMessage " " -Level INFO -Component "Summary"
        Write-LogMessage "  App Name Resolution:" -Level SUMMARY -Component "Summary"
        Write-LogMessage "    Segments with app ID resolved: $segmentsWithAppId" -Level SUMMARY -Component "Summary"
        Write-LogMessage "    Segments with app resolution failed: $failedAppResolveCount" -Level SUMMARY -Component "Summary"
        Write-LogMessage "    Unique applications resolved: $uniqueAppsResolved" -Level SUMMARY -Component "Summary"
    }

    # Top 5 destinations
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "  Top 5 Destinations by User Count:" -Level SUMMARY -Component "Summary"
    $rank = 0
    foreach ($dest in $topDestinations) {
        $rank++
        $host_ = if ($dest.fqdn) { $dest.fqdn } else { $dest.ip }
        $port_ = $dest.port
        $proto_ = $dest.transportProtocol
        Write-LogMessage "    $rank. ${host_}:${port_}/${proto_} ($($dest.userCount) users, $($dest.transactionCount) txns)" -Level SUMMARY -Component "Summary"
    }

    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "  Records Skipped: $skippedRecords" -Level SUMMARY -Component "Summary"
    Write-LogMessage "  Warnings: $warningCount" -Level SUMMARY -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "  Next Steps:" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    1. Review the CSV and edit EnterpriseAppName to group segments into apps" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    2. Replace Placeholder_Replace_Me in ConnectorGroup column (add EntraGroups if desired)" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    3. Review EntraUsers (pre-populated from discovery data) and replace with EntraGroups if desired" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    4. Set Provision=Yes for rows to provision" -Level SUMMARY -Component "Summary"
    Write-LogMessage "    5. Run: Start-EntraPrivateAccessProvisioning -ProvisioningConfigPath `"$csvFilePath`"" -Level SUMMARY -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "  Duration: $durationSeconds seconds" -Level SUMMARY -Component "Summary"
    Write-LogMessage " " -Level INFO -Component "Summary"
    Write-LogMessage "Files created in PrivateAccess\:" -Level SUMMARY -Component "Summary"
    Write-LogMessage "  - $csvFileName ($csvSizeKB KB)" -Level SUMMARY -Component "Summary"
    Write-LogMessage "  - $(Split-Path -Path $LogPath -Leaf) ($logSizeKB KB)" -Level SUMMARY -Component "Summary"
    #endregion
}
