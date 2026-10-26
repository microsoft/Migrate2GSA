function Export-NetskopeConfigV2 {
    <#
    .SYNOPSIS
        EXPERIMENTAL: Exports Netskope configuration with paginated Destination Profile collections.
    
    .DESCRIPTION
        Best-effort experimental implementation based on public documentation and API models.
        Not yet validated against live Netskope tenants; community validation and contributions welcome.
        Invoke Export-NetskopeConfig for the unchanged original exporter.
        V2 identifies this experimental cmdlet, NOT GSA Filtering Policy Model V2.
        Uses read-only API calls and writes a separate backup_v2_preview directory.
        Does not export the Real-time Protection policies required by the converter.

        This PowerShell function connects to the Netskope API using an API token and exports 
        various configuration types to JSON files. The function handles multiple configuration 
        objects including Private Access applications, publishers, URL lists, policies, and 
        custom profiles.
    
    .PARAMETER ApiToken
        The Netskope API token (generated from the Netskope portal). Must be provided as a 
        SecureString for security.
    
    .PARAMETER TenantUrl
        The base tenant URL (e.g., "https://contoso.goskope.com"). Must be a valid HTTPS URL 
        without trailing slashes.
    
    .PARAMETER OutputDirectory
        The output directory for backup files. Defaults to the current location.
    
    .PARAMETER RequestDelay
        Delay in seconds between API requests to avoid rate limiting. Default is 1 second.
    
    .OUTPUTS
        System.Boolean
        Returns $true if backup completed successfully, $false otherwise.
    
    .EXAMPLE
        $token = Read-Host "Enter API Token" -AsSecureString
        Export-NetskopeConfigV2 -ApiToken $token -TenantUrl "https://contoso.goskope.com"
        
        Basic usage with interactive token input.
    
    .EXAMPLE
        $token = ConvertTo-SecureString "your-token" -AsPlainText -Force
        Export-NetskopeConfigV2 -ApiToken $token -TenantUrl "https://contoso.goskope.com" -OutputDirectory "C:\Backups\Netskope"
        
        Export with custom output directory.
    
    .EXAMPLE
        $token = Read-Host "Enter API Token" -AsSecureString
        Export-NetskopeConfigV2 -ApiToken $token -TenantUrl "https://contoso.goskope.com" -RequestDelay 2
        
        Export with custom delay between API requests.
    
    .EXAMPLE
        $token = Read-Host "Enter API Token" -AsSecureString
        Export-NetskopeConfigV2 -ApiToken $token -TenantUrl "https://contoso.goskope.com" -Debug
        
        Export with debug mode to see raw API responses.
    
    .NOTES
        Status: Best-effort experimental implementation; API contracts require tenant Swagger validation.
        Validation feedback: https://github.com/microsoft/Migrate2GSA/issues
        Share only sanitized, authorized examples; never tokens or real customer configuration.

        Author: Migration Team
        Date: October 15, 2025
        
        Security Considerations:
        - Always use SecureString for token input
        - Output files may contain sensitive configuration data
        - Secure backup directory with appropriate ACLs
        
        Dependencies:
        - PowerShell 7.0 or higher
        - Network access to Netskope tenant
        - Valid Netskope API token with appropriate permissions
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [SecureString]$ApiToken,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantUrl,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputDirectory = (Get-Location).Path,
        
        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 60)]
        [int]$RequestDelay = 1
    )
    
    Write-Warning "EXPERIMENTAL: Export-NetskopeConfigV2 is a best-effort implementation, not yet validated against live Netskope tenants. Community validation and contributions welcome. Validate API contracts and completeness; use Export-NetskopeConfig for the original behavior."

    # Set strict error handling
    $ErrorActionPreference = 'Stop'
    
    # Script-scoped variables for Netskope session
    $script:NetskopeHeaders = $null
    $script:NetskopeTenantUrl = $null
    $script:NetskopeRequestDelay = $RequestDelay
    $script:EnableDebugLogging = $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Debug')
    $script:LogPath = $null
    
    #region Internal Functions
    
    function Test-TenantUrl {
        <#
        .SYNOPSIS
            Validates and normalizes the Netskope tenant URL.
        
        .PARAMETER Url
            The URL to validate and normalize.
        
        .OUTPUTS
            System.String
            Returns the normalized URL or throws an error if invalid.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [string]$Url
        )
        
        try {
            # Remove trailing slashes
            $normalizedUrl = $Url.TrimEnd('/')
            
            # Validate HTTPS protocol
            if (-not $normalizedUrl.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
                throw "Tenant URL must use HTTPS protocol. Received: $normalizedUrl"
            }
            
            # Validate as proper URI
            $uri = [System.Uri]$normalizedUrl
            if (-not $uri.IsAbsoluteUri) {
                throw "Tenant URL must be a valid absolute URI. Received: $normalizedUrl"
            }
            
            Write-LogMessage "Tenant URL validated: $normalizedUrl" -Level INFO -Component "Validation"
            return $normalizedUrl
        }
        catch {
            throw "Invalid tenant URL: $_"
        }
    }
    
    function Initialize-NetskopeSession {
        <#
        .SYNOPSIS
            Initializes the Netskope API session with authentication.
        
        .PARAMETER ApiToken
            The Netskope API token as a SecureString.
        
        .PARAMETER TenantUrl
            The validated tenant URL.
        
        .OUTPUTS
            System.Boolean
            Returns $true if initialization was successful.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [SecureString]$ApiToken,
            
            [Parameter(Mandatory = $true)]
            [string]$TenantUrl
        )
        
        try {
            Write-LogMessage "Initializing Netskope session..." -Level INFO -Component "Auth"
            
            # Validate and normalize URL
            $script:NetskopeTenantUrl = Test-TenantUrl -Url $TenantUrl
            
            # Convert SecureString token to plain text for header
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiToken)
            try {
                $plainToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                
                if ([string]::IsNullOrWhiteSpace($plainToken)) {
                    throw "API token cannot be empty"
                }
                
                # Create headers hashtable
                $script:NetskopeHeaders = @{
                    "Netskope-Api-Token" = $plainToken
                    "Content-Type" = "application/json"
                }
                
                Write-LogMessage "API headers configured successfully" -Level INFO -Component "Auth"
            }
            finally {
                # Clear sensitive data from memory
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }

            # Connectivity is checked by endpoint requests. Profile collection failures
            # abort the backup rather than exporting an incomplete migration input.
            Write-LogMessage "Successfully authenticated with Netskope API" -Level SUCCESS -Component "Auth"
            return $true
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-LogMessage "Failed to initialize Netskope session: $errorMsg" -Level ERROR -Component "Auth"

            if ($script:EnableDebugLogging) {
                Write-LogMessage "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR -Component "Auth"
            }

            # URL validation / setup failures are unrecoverable - terminate cleanly
            # without stack trace noise in normal mode.
            $PSCmdlet.ThrowTerminatingError(
                [System.Management.Automation.ErrorRecord]::new(
                    [System.Exception]::new($errorMsg),
                    'NetskopeAuthenticationFailed',
                    [System.Management.Automation.ErrorCategory]::AuthenticationError,
                    $TenantUrl
                )
            )
        }
    }
    
    function Invoke-NetskopeApi {
        <#
        .SYNOPSIS
            Makes an API call to the Netskope API.
        
        .PARAMETER Endpoint
            The API endpoint to call (e.g., "/api/v2/steering/apps/private").
        
        .PARAMETER DelaySeconds
            Delay in seconds after the request to avoid rate limiting.
        
        .OUTPUTS
            System.Object
            Returns the parsed JSON response or $null on error.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [string]$Endpoint,
            
            [Parameter(Mandatory = $false)]
            [int]$DelaySeconds = 1
        )
        
        try {
            # Construct full URL
            $fullUrl = "$script:NetskopeTenantUrl$Endpoint"
            
            Write-LogMessage "Making API request to: $Endpoint" -Level DEBUG -Component "API"
            
            # Make GET request
            $response = Invoke-RestMethod -Uri $fullUrl -Method Get -Headers $script:NetskopeHeaders -ErrorAction Stop
            
            Write-LogMessage "API request successful: $Endpoint" -Level DEBUG -Component "API"
            
            # Log raw response if debug is enabled
            if ($script:EnableDebugLogging) {
                $responseJson = $response | ConvertTo-Json -Depth 10 -Compress
                Write-LogMessage "Raw API Response: $responseJson" -Level DEBUG -Component "API"
            }
            
            # Apply delay after request
            if ($DelaySeconds -gt 0) {
                Start-Sleep -Seconds $DelaySeconds
            }
            
            return $response
        }
        catch {
            $errorMessage = $_.Exception.Message
            $statusCode = $null
            
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                
                switch ($statusCode) {
                    401 { $errorMessage = "Invalid or expired API token" }
                    403 { $errorMessage = "Insufficient permissions for endpoint: $Endpoint" }
                    404 { $errorMessage = "Endpoint not available or feature not enabled: $Endpoint" }
                    429 { $errorMessage = "Rate limit exceeded. Consider increasing RequestDelay parameter." }
                    500 { $errorMessage = "Netskope API server error" }
                    default { $errorMessage = "HTTP $statusCode : $errorMessage" }
                }
            }
            
            Write-LogMessage "API request failed for $Endpoint : $errorMessage" -Level ERROR -Component "API"
            return $null
        }
    }
    
    function Get-NetskopePrivateApps {
        <#
        .SYNOPSIS
            Retrieves Netskope Private Access applications.
        #>
        Write-LogMessage "Retrieving Private Applications..." -Level INFO -Component "Export"
        $response = Invoke-NetskopeApi -Endpoint "/api/v2/steering/apps/private" -DelaySeconds $script:NetskopeRequestDelay
        
        if ($null -eq $response) {
            Write-LogMessage "No data retrieved for Private Applications" -Level WARN -Component "Export"
            return $null
        }
        
        # Handle different response formats
        if ($response -is [array]) {
            Write-LogMessage "Retrieved $($response.Count) Private Applications" -Level SUCCESS -Component "Export"
            return $response
        }
        elseif ($response.PSObject.Properties.Name -contains 'data' -and $response.data -is [array]) {
            Write-LogMessage "Retrieved $($response.data.Count) Private Applications" -Level SUCCESS -Component "Export"
            return $response.data
        }
        elseif ($response.PSObject.Properties.Name -contains 'result' -and $response.result -is [array]) {
            Write-LogMessage "Retrieved $($response.result.Count) Private Applications" -Level SUCCESS -Component "Export"
            return $response.result
        }
        else {
            Write-LogMessage "Retrieved Private Applications data (unknown format)" -Level SUCCESS -Component "Export"
            return $response
        }
    }
    
    function Get-NetskopePublishers {
        <#
        .SYNOPSIS
            Retrieves Netskope Publishers.
        #>
        Write-LogMessage "Retrieving Publishers..." -Level INFO -Component "Export"
        $response = Invoke-NetskopeApi -Endpoint "/api/v2/infrastructure/publishers" -DelaySeconds $script:NetskopeRequestDelay
        
        if ($null -eq $response) {
            Write-LogMessage "No data retrieved for Publishers" -Level WARN -Component "Export"
            return $null
        }
        
        # Handle different response formats
        if ($response -is [array]) {
            Write-LogMessage "Retrieved $($response.Count) Publishers" -Level SUCCESS -Component "Export"
            return $response
        }
        elseif ($response.PSObject.Properties.Name -contains 'data' -and $response.data -is [array]) {
            Write-LogMessage "Retrieved $($response.data.Count) Publishers" -Level SUCCESS -Component "Export"
            return $response.data
        }
        elseif ($response.PSObject.Properties.Name -contains 'result' -and $response.result -is [array]) {
            Write-LogMessage "Retrieved $($response.result.Count) Publishers" -Level SUCCESS -Component "Export"
            return $response.result
        }
        else {
            Write-LogMessage "Retrieved Publishers data (unknown format)" -Level SUCCESS -Component "Export"
            return $response
        }
    }
    
    function Get-NetskopeUrlLists {
        <#
        .SYNOPSIS
            Retrieves Netskope URL Lists.
        #>
        Write-LogMessage "Retrieving URL Lists..." -Level INFO -Component "Export"
        $response = Invoke-NetskopeApi -Endpoint "/api/v2/policy/urllist" -DelaySeconds $script:NetskopeRequestDelay
        
        if ($null -eq $response) {
            Write-LogMessage "No data retrieved for URL Lists" -Level WARN -Component "Export"
            return $null
        }
        
        # Handle different response formats
        if ($response -is [array]) {
            Write-LogMessage "Retrieved $($response.Count) URL Lists" -Level SUCCESS -Component "Export"
            return $response
        }
        elseif ($response.PSObject.Properties.Name -contains 'data' -and $response.data -is [array]) {
            Write-LogMessage "Retrieved $($response.data.Count) URL Lists" -Level SUCCESS -Component "Export"
            return $response.data
        }
        elseif ($response.PSObject.Properties.Name -contains 'result' -and $response.result -is [array]) {
            Write-LogMessage "Retrieved $($response.result.Count) URL Lists" -Level SUCCESS -Component "Export"
            return $response.result
        }
        else {
            Write-LogMessage "Retrieved URL Lists data (unknown format)" -Level SUCCESS -Component "Export"
            return $response
        }
    }
    
    function Get-NetskopeNpaPolicies {
        <#
        .SYNOPSIS
            Retrieves Netskope Private Access policies.
        #>
        Write-LogMessage "Retrieving NPA Policies..." -Level INFO -Component "Export"
        $response = Invoke-NetskopeApi -Endpoint "/api/v2/policy/npa/rules" -DelaySeconds $script:NetskopeRequestDelay
        
        if ($null -eq $response) {
            Write-LogMessage "No data retrieved for NPA Policies" -Level WARN -Component "Export"
            return $null
        }
        
        # Handle different response formats
        if ($response -is [array]) {
            Write-LogMessage "Retrieved $($response.Count) NPA Policies" -Level SUCCESS -Component "Export"
            return $response
        }
        elseif ($response.PSObject.Properties.Name -contains 'data' -and $response.data -is [array]) {
            Write-LogMessage "Retrieved $($response.data.Count) NPA Policies" -Level SUCCESS -Component "Export"
            return $response.data
        }
        elseif ($response.PSObject.Properties.Name -contains 'result' -and $response.result -is [array]) {
            Write-LogMessage "Retrieved $($response.result.Count) NPA Policies" -Level SUCCESS -Component "Export"
            return $response.result
        }
        else {
            Write-LogMessage "Retrieved NPA Policies data (unknown format)" -Level SUCCESS -Component "Export"
            return $response
        }
    }
    
    function Get-NetskopeNpaPolicyGroups {
        <#
        .SYNOPSIS
            Retrieves Netskope Private Access policy groups.
        #>
        Write-LogMessage "Retrieving NPA Policy Groups..." -Level INFO -Component "Export"
        $response = Invoke-NetskopeApi -Endpoint "/api/v2/policy/npa/policygroups" -DelaySeconds $script:NetskopeRequestDelay
        
        if ($null -eq $response) {
            Write-LogMessage "No data retrieved for NPA Policy Groups" -Level WARN -Component "Export"
            return $null
        }
        
        # Handle different response formats
        if ($response -is [array]) {
            Write-LogMessage "Retrieved $($response.Count) NPA Policy Groups" -Level SUCCESS -Component "Export"
            return $response
        }
        elseif ($response.PSObject.Properties.Name -contains 'data' -and $response.data -is [array]) {
            Write-LogMessage "Retrieved $($response.data.Count) NPA Policy Groups" -Level SUCCESS -Component "Export"
            return $response.data
        }
        elseif ($response.PSObject.Properties.Name -contains 'result' -and $response.result -is [array]) {
            Write-LogMessage "Retrieved $($response.result.Count) NPA Policy Groups" -Level SUCCESS -Component "Export"
            return $response.result
        }
        else {
            Write-LogMessage "Retrieved NPA Policy Groups data (unknown format)" -Level SUCCESS -Component "Export"
            return $response
        }
    }
    
    function Get-NetskopePagedProfiles {
        param(
            [string]$Endpoint,
            [switch]$AllowLegacyResponse
        )

        $items = [System.Collections.Generic.List[object]]::new()
        $seenIds = [System.Collections.Generic.HashSet[string]]::new()
        $expectedCount = $null
        do {
            $offset = $items.Count
            $response = Invoke-NetskopeApi -Endpoint "${Endpoint}?limit=100&offset=$offset" -DelaySeconds $script:NetskopeRequestDelay
            if ($null -eq $response) {
                throw "Unable to export $Endpoint at offset $offset; partial results will not be saved."
            }
            if ($response.PSObject.Properties.Name -notcontains 'elements') {
                if ($AllowLegacyResponse -and $offset -eq 0) {
                    Write-LogMessage "Legacy response from $Endpoint; pagination completeness cannot be verified." -Level WARN -Component "Export"
                    return $response
                }
                throw "Unsupported response from $Endpoint; expected elements and total_count. Check tenant Swagger."
            }
            if ($response.elements -isnot [array] -or
                ($response.total_count -isnot [long] -and $response.total_count -isnot [int]) -or
                $response.total_count -lt 0) {
                throw "Invalid elements/total_count response from $Endpoint."
            }
            if ($null -eq $expectedCount) {
                $expectedCount = $response.total_count
            } elseif ($response.total_count -ne $expectedCount) {
                throw "Collection changed while exporting $Endpoint. Retry against a stable configuration."
            }
            foreach ($item in $response.elements) {
                if ([string]::IsNullOrWhiteSpace($item.id) -or -not $seenIds.Add([string]$item.id)) {
                    throw "Missing or repeated ID while exporting $Endpoint at offset $offset."
                }
                $items.Add($item)
            }
            if ($items.Count -gt $expectedCount -or ($response.elements.Count -eq 0 -and $items.Count -lt $expectedCount)) {
                throw "Incomplete or inconsistent collection from $Endpoint at offset $offset."
            }
        } while ($items.Count -lt $expectedCount)

        Write-LogMessage "Retrieved $($items.Count) objects from $Endpoint" -Level SUCCESS -Component "Export"
        return [PSCustomObject]@{ total_count = $items.Count; elements = $items.ToArray() }
    }

    function Get-NetskopeCustomCategories {
        <#
        .SYNOPSIS
            Retrieves Netskope Custom Categories.
        #>
        Write-LogMessage "Retrieving Custom Categories..." -Level INFO -Component "Export"
        $response = Get-NetskopePagedProfiles -Endpoint "/api/v2/profiles/customcategories" -AllowLegacyResponse
        
        if ($null -eq $response) {
            Write-LogMessage "No data retrieved for Custom Categories" -Level WARN -Component "Export"
            return $null
        }
        
        # Preserve the modern collection envelope and typed references.
        if ($response.PSObject.Properties.Name -contains 'elements') {
            return $response
        }
        elseif ($response -is [array]) {
            Write-LogMessage "Retrieved $($response.Count) Custom Categories" -Level SUCCESS -Component "Export"
            return $response
        }
        elseif ($response.PSObject.Properties.Name -contains 'data' -and $response.data -is [array]) {
            Write-LogMessage "Retrieved $($response.data.Count) Custom Categories" -Level SUCCESS -Component "Export"
            return $response.data
        }
        elseif ($response.PSObject.Properties.Name -contains 'result' -and $response.result -is [array]) {
            Write-LogMessage "Retrieved $($response.result.Count) Custom Categories" -Level SUCCESS -Component "Export"
            return $response.result
        }
        else {
            Write-LogMessage "Retrieved Custom Categories data (unknown format)" -Level SUCCESS -Component "Export"
            return $response
        }
    }
    
    function Get-NetskopeDestinations {
        <#
        .SYNOPSIS
            Retrieves all pages of Netskope Destination Profiles, including deployment status.
        #>
        Write-LogMessage "Retrieving Destination Profiles..." -Level INFO -Component "Export"
        return Get-NetskopePagedProfiles -Endpoint "/api/v2/profiles/destinations"
    }
    
    function Start-NetskopeFullBackup {
        <#
        .SYNOPSIS
            Performs a full backup of Netskope configurations.
        
        .PARAMETER BackupDir
            The backup directory where files will be saved (already created).
        
        .OUTPUTS
            System.Boolean
            Returns $true if backup completed successfully.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [string]$BackupDir
        )
        
        try {
            Write-LogMessage "Starting configuration data collection..." -Level INFO -Component "Backup"
            Write-LogMessage "" -Level INFO
            
            # Collect configurations
            
            $configs = @{
                "private_apps" = Get-NetskopePrivateApps
                "publishers" = Get-NetskopePublishers
                "url_lists" = Get-NetskopeUrlLists
                "npa_policies" = Get-NetskopeNpaPolicies
                "npa_policy_groups" = Get-NetskopeNpaPolicyGroups
                "custom_categories" = Get-NetskopeCustomCategories
                "destinations" = Get-NetskopeDestinations
            }
            
            Write-LogMessage "" -Level INFO
            Write-LogMessage "Configuration data collection completed" -Level SUCCESS -Component "Backup"
            Write-LogMessage "" -Level INFO
            
            # Track backup statistics
            $successCount = 0
            $failureCount = 0
            $totalConfigs = $configs.Keys.Count
            
            Write-LogMessage "Saving configuration files..." -Level INFO -Component "Backup"
            
            # Save individual files
            foreach ($configName in $configs.Keys) {
                $configData = $configs[$configName]
                
                if ($null -ne $configData) {
                    try {
                        $filename = Join-Path $backupDir "$configName.json"
                        
                        $configData | ConvertTo-Json -Depth 10 | Out-File -FilePath $filename -Encoding UTF8
                        
                        # Verify file was created and get size
                        if (Test-Path $filename) {
                            $fileSize = (Get-Item $filename).Length
                            $fileSizeKB = [math]::Round($fileSize / 1KB, 2)
                            Write-LogMessage "Saved $configName ($fileSizeKB KB)" -Level SUCCESS -Component "Backup"
                            $successCount++
                        }
                        else {
                            Write-LogMessage "File was not created for $configName" -Level ERROR -Component "Backup"
                            $failureCount++
                        }
                    }
                    catch {
                        Write-LogMessage "Failed to save $configName : $($_.Exception.Message)" -Level ERROR -Component "Backup"
                        $failureCount++
                    }
                }
                else {
                    Write-LogMessage "No data available for $configName (skipped)" -Level WARN -Component "Backup"
                    $failureCount++
                }
            }
            
            Write-LogMessage "" -Level INFO
            
            # Save complete backup
            Write-LogMessage "Creating complete backup file..." -Level INFO -Component "Backup"
            
            $completeBackup = @{
                "timestamp" = Get-Date -Format "yyyyMMdd_HHmmss"
                "tenant_url" = $script:NetskopeTenantUrl
                "backup_type" = "Netskope_Configuration_V2_Preview"
                "configurations" = $configs
            }
            
            try {
                $completeFilename = Join-Path $backupDir "netskope_complete_backup.json"
                
                $completeBackup | ConvertTo-Json -Depth 10 | Out-File -FilePath $completeFilename -Encoding UTF8
                
                # Verify complete backup file
                if (Test-Path $completeFilename) {
                    $fileSize = (Get-Item $completeFilename).Length
                    $fileSizeMB = [math]::Round($fileSize / 1MB, 2)
                    Write-LogMessage "Complete backup saved ($fileSizeMB MB)" -Level SUCCESS -Component "Backup"
                }
                else {
                    Write-LogMessage "Complete backup file was not created" -Level ERROR -Component "Backup"
                    return $false
                }
            }
            catch {
                Write-LogMessage "Failed to create complete backup file: $($_.Exception.Message)" -Level ERROR -Component "Backup"
                return $false
            }
            
            # Display summary
            Write-LogMessage "" -Level INFO
            Write-LogMessage "Backup Summary" -Level SUMMARY -Component "Backup"
            Write-LogMessage "Total configurations: $totalConfigs" -Level INFO -Component "Backup"
            Write-LogMessage "Successful backups: $successCount" -Level INFO -Component "Backup"
            Write-LogMessage "Failed/Skipped: $failureCount" -Level INFO -Component "Backup"
            Write-LogMessage "Backup directory: $backupDir" -Level INFO -Component "Backup"
            Write-LogMessage "Log file: $script:LogPath" -Level INFO -Component "Backup"
            Write-LogMessage "" -Level INFO
            
            if ($successCount -gt 0) {
                Write-LogMessage "Backup completed successfully!" -Level SUCCESS -Component "Backup"
                return $true
            }
            else {
                Write-LogMessage "Backup completed with no data exported" -Level WARN -Component "Backup"
                return $false
            }
        }
        catch {
            Write-LogMessage "Backup process failed: $($_.Exception.Message)" -Level ERROR -Component "Backup"
            return $false
        }
    }
    
    #endregion Internal Functions
    
    #region Main Execution
    
    try {
        # Set up log file path early for all log messages
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        
        # Ensure output directory exists
        if (-not (Test-Path $OutputDirectory)) {
            New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        }
        
        # Create timestamped backup folder
        $backupDir = Join-Path $OutputDirectory "backup_v2_preview_$timestamp"
        if (-not (Test-Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        }
        
        # Set log path for Write-LogMessage (both script and local scope for compatibility)
        $LogPath = Join-Path $backupDir "Export-NetskopeConfigV2.log"
        $script:LogPath = $LogPath
        
        # Initialize log file
        try {
            # Create empty log file to ensure it exists and is writable
            New-Item -Path $LogPath -ItemType File -Force | Out-Null
        }
        catch {
            Write-Warning "Could not create log file at $LogPath : $_"
        }
        
        Write-LogMessage "Netskope Configuration Export" -Level SUMMARY -Component "Main"
        Write-LogMessage "EXPERIMENTAL V2: best-effort implementation, not yet validated against live tenants; community validation and contributions welcome." -Level WARN -Component "Main"
        Write-LogMessage "Started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level INFO -Component "Main"
        Write-LogMessage "" -Level INFO
        
        # Log parameters (excluding sensitive data)
        Write-LogMessage "Parameters:" -Level INFO -Component "Main"
        Write-LogMessage "  Tenant URL: $TenantUrl" -Level INFO -Component "Main"
        Write-LogMessage "  Output Directory: $OutputDirectory" -Level INFO -Component "Main"
        Write-LogMessage "  Request Delay: $RequestDelay seconds" -Level INFO -Component "Main"
        Write-LogMessage "  API Token: [PROTECTED]" -Level INFO -Component "Main"
        Write-LogMessage "" -Level INFO
        
        # Initialize session
        $initSuccess = Initialize-NetskopeSession -ApiToken $ApiToken -TenantUrl $TenantUrl
        
        if (-not $initSuccess) {
            throw "Failed to initialize Netskope session"
        }
        
        Write-LogMessage "" -Level INFO
        Write-LogMessage "Backup directory: $backupDir" -Level INFO -Component "Main"
        Write-LogMessage "Log file: $script:LogPath" -Level INFO -Component "Main"
        Write-LogMessage "" -Level INFO
        
        # Perform backup
        $backupSuccess = Start-NetskopeFullBackup -BackupDir $backupDir
        
        if ($backupSuccess) {
            Write-LogMessage "" -Level INFO
            Write-LogMessage "Export process completed successfully!" -Level SUCCESS -Component "Main"
            Write-LogMessage "Finished at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level INFO -Component "Main"

            # Send usage telemetry
            Send-UsageTelemetry -EventName 'Export-NetskopeConfigV2'

            return $true
        }
        else {
            throw "Backup process failed"
        }
    }
    catch {
        Write-LogMessage "" -Level INFO
        
        $errorMsg = $_.Exception.Message
        Write-LogMessage "Export process failed: $errorMsg" -Level ERROR -Component "Main"
        Write-LogMessage "Error type: $($_.Exception.GetType().Name)" -Level ERROR -Component "Main"
        
        if ($_.Exception.InnerException) {
            Write-LogMessage "Inner exception: $($_.Exception.InnerException.Message)" -Level ERROR -Component "Main"
        }
        
        Write-LogMessage "Failed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level ERROR -Component "Main"
        
        # In debug mode, show full error details
        if ($script:EnableDebugLogging) {
            Write-LogMessage "" -Level INFO
            Write-LogMessage "Full error details (Debug mode):" -Level ERROR -Component "Main"
            Write-LogMessage "Exception Type: $($_.Exception.GetType().FullName)" -Level ERROR -Component "Main"
            
            if ($_.ErrorDetails) {
                Write-LogMessage "Error Details: $($_.ErrorDetails.Message)" -Level ERROR -Component "Main"
            }
            
            if ($_.Exception.Response) {
                Write-LogMessage "HTTP Status Code: $([int]$_.Exception.Response.StatusCode)" -Level ERROR -Component "Main"
            }
            
            Write-LogMessage "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR -Component "Main"
            Write-LogMessage "Position: $($_.InvocationInfo.PositionMessage)" -Level ERROR -Component "Main"
            
            # In debug mode, preserve the original error for full PowerShell output
            throw
        }
        
        # Normal mode: Re-throw with terminating error for cleaner output
        $PSCmdlet.ThrowTerminatingError($_)
    }
    finally {
        # Clear sensitive data from script scope
        $script:NetskopeHeaders = $null
        $script:NetskopeTenantUrl = $null
    }
    
    #endregion Main Execution
}
