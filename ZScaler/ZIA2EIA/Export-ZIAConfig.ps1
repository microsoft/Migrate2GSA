<#
.SYNOPSIS
    Zscaler Internet Access (ZIA) Configuration Backup Script
    Exports ZIA configurations to JSON files

.DESCRIPTION
    This PowerShell script connects to the ZIA API using admin credentials and API key/token
    and exports various configuration types to JSON files for backup purposes.

.PARAMETER Username
    The ZIA admin username

.PARAMETER Password
    The ZIA admin password (as SecureString)

.PARAMETER ApiKey
    The ZIA API key/token

.PARAMETER BaseUrl
    The ZIA API base URL (defaults to production cloud)

.PARAMETER OutputDirectory
    The output directory for backup files (defaults to the script directory)

.EXAMPLE
    $securePassword = Read-Host "Enter Password" -AsSecureString
    .\Export-ZIAConfig.ps1 -Username "admin@example.com" -Password $securePassword -ApiKey "your-api-key"

.EXAMPLE
    $securePassword = ConvertTo-SecureString "your-password" -AsPlainText -Force
    .\Export-ZIAConfig.ps1 -Username "admin@example.com" -Password $securePassword -ApiKey "your-api-key" -BaseUrl "https://admin.zscaler.net/api/v1" -OutputDirectory "C:\Backups\ZIA"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Username,
    [Parameter(Mandatory = $true)]
    [SecureString]$Password,
    [Parameter(Mandatory = $true)]
    [string]$ApiKey,
    [Parameter(Mandatory = $false)]
    [string]$BaseUrl = "https://zsapi.zscaler.net/api/v1",
    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = $PSScriptRoot
)

class ZIABackup {
    [string]$Username
    [SecureString]$Password
    [string]$ApiKey
    [string]$BaseUrl
    [object]$Session

    ZIABackup([string]$Username, [SecureString]$Password, [string]$ApiKey, [string]$BaseUrl) {
        $this.Username = $Username
        $this.Password = $Password
        $this.ApiKey = $ApiKey
        $this.BaseUrl = $BaseUrl
        $this.Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    }

    [string] ObfuscateApiKey([string]$apiKey, [string]$timestamp) {
        $high = $timestamp.Substring($timestamp.Length - 6)
        $low = ([int]$high -shr 1).ToString()
        while ($low.Length -lt 6) {
            $low = '0' + $low
        }
        $obfuscatedApiKey = ''
        for ($i = 0; $i -lt $high.Length; $i++) {
            $obfuscatedApiKey += $apiKey[[int64]($high[$i].ToString())]
        }
        for ($j = 0; $j -lt $low.Length; $j++) {
            $obfuscatedApiKey += $apiKey[[int64]$low[$j].ToString() + 2]
        }
        return $obfuscatedApiKey
    }

    [bool] Authenticate() {
        try {
            Write-Host "Starting ZIA authentication process..." -ForegroundColor Gray
            $authUrl = "$($this.BaseUrl)/authenticatedSession"
            Write-Host "Authentication URL: $authUrl" -ForegroundColor Gray

            # Convert SecureString to plain text for API call
            $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($this.Password))

            # Get timestamp in milliseconds since epoch
            $timestamp = [string]([math]::Round((Get-Date).ToUniversalTime().Subtract([datetime]'1970-01-01').TotalMilliseconds))

            # Obfuscate API key using official ZIA logic
            $obfuscatedApiKey = $this.ObfuscateApiKey($this.ApiKey, $timestamp)

            $headers = @{
                "Content-Type" = "application/json"
            }

            $body = @{
                "username" = $this.Username
                "password" = $plainPassword
                "apiKey" = $obfuscatedApiKey
                "timestamp" = $timestamp
            } | ConvertTo-Json

            Write-Host "Sending authentication request to ZIA API..." -ForegroundColor Gray
            $response = Invoke-RestMethod -Uri $authUrl -Method Post -Headers $headers -Body $body -WebSession $this.Session

            if ($response.success -or $response.sessionId) {
                Write-Host "Session created successfully" -ForegroundColor Gray
                $this.Session.Headers["Cookie"] = "JSESSIONID=$($response.sessionId)"
                $this.Session.Headers["Content-Type"] = "application/json"
                Write-Host "Session headers configured with session cookie" -ForegroundColor Gray
                Write-Host "ZIA Authentication successful" -ForegroundColor Green
                return $true
            }
            else {
                Write-Error "ZIA Authentication failed: No sessionId received"
                Write-Host "Response received but no sessionId found" -ForegroundColor Red
                return $false
            }
        }
        catch {
            Write-Error "ZIA Authentication failed: $($_.Exception.Message)"
            Write-Host "Authentication error details: $($_.Exception.GetType().Name)" -ForegroundColor Red
            if ($_.Exception.Response) {
                Write-Host "HTTP Status Code: $($_.Exception.Response.StatusCode)" -ForegroundColor Red
                Write-Host "HTTP Status Description: $($_.Exception.Response.StatusDescription)" -ForegroundColor Red
            }
            return $false
        }
    }

    [object] BackupUrlFilteringPolicy() {
        Write-Host "Backing up URL Filtering Policy..." -ForegroundColor Gray
        return $this.InvokeZIAApi("/urlFilteringRules")
    }

    [object] BackupUrlCategories() {
        Write-Host "Backing up URL Categories..." -ForegroundColor Gray
        return $this.InvokeZIAApi("/urlCategories")
    }

    [object] BackupSslInspectionPolicy() {
        Write-Host "Backing up SSL Inspection Policy..." -ForegroundColor Gray
        return $this.InvokeZIAApi("/sslInspectionRules")
    }

    [object] BackupFileTypeControl() {
        Write-Host "Backing up File Type Control Policy..." -ForegroundColor Gray
        return $this.InvokeZIAApi("/fileTypeRules")
    }

    [object] BackupFirewallControl() {
        Write-Host "Backing up Firewall Control Policy..." -ForegroundColor Gray
        return $this.InvokeZIAApi("/firewallFilteringRules")
    }

    [object] InvokeZIAApi([string]$Endpoint) {
        try {
            $url = "$($this.BaseUrl)$Endpoint"
            Write-Host "Making API call to: $url" -ForegroundColor Gray
            $response = Invoke-RestMethod -Uri $url -Method Get -WebSession $this.Session
            if ($response) {
                if ($response -is [array]) {
                    Write-Host "API call successful - Retrieved $($response.Count) items from $Endpoint" -ForegroundColor Gray
                } elseif ($response.PSObject.Properties['list'] -and $response.list -is [array]) {
                    Write-Host "API call successful - Retrieved $($response.list.Count) items from $Endpoint" -ForegroundColor Gray
                } else {
                    Write-Host "API call successful - Retrieved data from $Endpoint" -ForegroundColor Gray
                }
            } else {
                Write-Host "API call successful but no data returned from $Endpoint" -ForegroundColor Yellow
            }
            return $response
        }
        catch {
            Write-Warning "Failed to retrieve data from $Endpoint : $($_.Exception.Message)"
            Write-Host "API call error details for $Endpoint" -ForegroundColor Red
            Write-Host "Error type: $($_.Exception.GetType().Name)" -ForegroundColor Red
            if ($_.Exception.Response) {
                Write-Host "HTTP Status Code: $($_.Exception.Response.StatusCode)" -ForegroundColor Red
                Write-Host "HTTP Status Description: $($_.Exception.Response.StatusDescription)" -ForegroundColor Red
            }
            return $null
        }
    }

    [bool] FullBackup([string]$OutputDir) {
        Write-Host "Starting full backup process..." -ForegroundColor Gray
        if (-not $this.Authenticate()) {
            Write-Host "Full backup cancelled due to authentication failure" -ForegroundColor Red
            return $false
        }
        # Create output directory with timestamp
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupDir = "$OutputDir`_$timestamp"
        Write-Host "Creating backup directory: $backupDir" -ForegroundColor Gray
        if (-not (Test-Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
            Write-Host "Backup directory created successfully" -ForegroundColor Gray
        } else {
            Write-Host "Backup directory already exists" -ForegroundColor Yellow
        }
        Write-Host "Starting ZIA configuration backup..." -ForegroundColor Yellow
        Write-Host "Backup timestamp: $timestamp" -ForegroundColor Gray
        # Backup configurations
        Write-Host "Initializing configuration backup operations..." -ForegroundColor Gray
        $configs = @{
            "url_filtering_policy" = $this.BackupUrlFilteringPolicy()
            "url_categories" = $this.BackupUrlCategories()
            "ssl_inspection_policy" = $this.BackupSslInspectionPolicy()
            "file_type_control" = $this.BackupFileTypeControl()
            "firewall_control" = $this.BackupFirewallControl()
        }
        Write-Host "Configuration data collection completed. Starting file export..." -ForegroundColor Gray
        # Track backup statistics
        $successCount = 0
        $failureCount = 0
        $totalConfigs = $configs.Keys.Count
        # Save individual files
        foreach ($configName in $configs.Keys) {
            $configData = $configs[$configName]
            if ($configData) {
                try {
                    $filename = Join-Path $backupDir "$configName.json"
                    Write-Host "Writing $configName to file: $filename" -ForegroundColor Gray
                    $configData | ConvertTo-Json -Depth 10 | Out-File -FilePath $filename -Encoding UTF8
                    # Verify file was created and get size
                    if (Test-Path $filename) {
                        $fileSize = (Get-Item $filename).Length
                        Write-Host "Saved $configName to $filename (Size: $fileSize bytes)" -ForegroundColor Green
                        $successCount++
                    } else {
                        Write-Warning "File was not created for $configName"
                        $failureCount++
                    }
                }
                catch {
                    Write-Warning "Failed to save $configName : $($_.Exception.Message)"
                    $failureCount++
                }
            }
            else {
                Write-Warning "No data retrieved for $configName"
                $failureCount++
            }
        }
        Write-Host "Individual file export completed. Successfully saved: $successCount/$totalConfigs configurations" -ForegroundColor Gray
        # Save complete backup
        Write-Host "Creating complete backup file..." -ForegroundColor Gray
        $completeBackup = @{
            "timestamp" = $timestamp
            "username" = $this.Username
            "backup_type" = "ZIA_Configuration"
            "configurations" = $configs
        }
        try {
            $completeFilename = Join-Path $backupDir "zia_complete_backup.json"
            Write-Host "Writing complete backup to: $completeFilename" -ForegroundColor Gray
            $completeBackup | ConvertTo-Json -Depth 10 | Out-File -FilePath $completeFilename -Encoding UTF8
            # Verify complete backup file
            if (Test-Path $completeFilename) {
                $fileSize = (Get-Item $completeFilename).Length
                Write-Host "Complete ZIA backup saved to $completeFilename (Size: $fileSize bytes)" -ForegroundColor Green
            } else {
                Write-Warning "Complete backup file was not created"
                return $false
            }
        }
        catch {
            Write-Error "Failed to create complete backup file: $($_.Exception.Message)"
            return $false
        }
        Write-Host "Backup operation summary:" -ForegroundColor Gray
        Write-Host "- Total configurations: $totalConfigs" -ForegroundColor Gray
        Write-Host "- Successful backups: $successCount" -ForegroundColor Gray
        Write-Host "- Failed backups: $failureCount" -ForegroundColor Gray
        Write-Host "- Backup directory: $backupDir" -ForegroundColor Gray
        Write-Host "Backup completed successfully!" -ForegroundColor Green
        return $true
    }
}

# Main execution
try {
    Write-Host "ZIA Configuration Backup Script" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Cyan
    # Log script initialization
    Write-Host "Script started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "Validating input parameters..." -ForegroundColor Gray
    # Log parameters (excluding sensitive data)
    Write-Host "Username: $Username" -ForegroundColor Gray
    Write-Host "Base URL: $BaseUrl" -ForegroundColor Gray
    Write-Host "Output Directory: $OutputDirectory" -ForegroundColor Gray
    Write-Host "Password: [PROTECTED]" -ForegroundColor Gray
    Write-Host "API Key: [PROTECTED]" -ForegroundColor Gray
    Write-Host "Creating ZIA backup instance..." -ForegroundColor Gray
    # Create backup instance
    $backup = [ZIABackup]::new($Username, $Password, $ApiKey, $BaseUrl)
    Write-Host "ZIA backup instance created successfully" -ForegroundColor Gray
    Write-Host "Initiating backup process..." -ForegroundColor Gray
    # Perform backup
    $success = $backup.FullBackup($OutputDirectory)
    if ($success) {
        Write-Host "`nBackup process completed successfully!" -ForegroundColor Green
        Write-Host "Script execution finished at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
        exit 0
    }
    else {
        Write-Error "Backup process failed!"
        Write-Host "Script execution failed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Red
        exit 1
    }
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    Write-Host "Error occurred at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Red
    Write-Host "Error type: $($_.Exception.GetType().Name)" -ForegroundColor Red
    Write-Host "Error details: $($_.Exception.ToString())" -ForegroundColor Red
    if ($_.Exception.InnerException) {
        Write-Host "Inner exception: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    }
    Write-Host "Stack trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}