function Write-LogMessage {
    <#
    .SYNOPSIS
        Writes structured log messages to console and file.
    
    .DESCRIPTION
        Unified logging function for the Migrate2GSA module. Supports multiple log levels,
        component tagging, color-coded console output, and optional file logging.
    
    .PARAMETER Message
        The log message to write. Can be empty string for spacing.
    
    .PARAMETER Level
        The log level: INFO, WARN, ERROR, SUCCESS, DEBUG, or SUMMARY.
    
    .PARAMETER Component
        Optional component identifier for the log entry (e.g., 'Main', 'Auth', 'Export').
    
    .PARAMETER LogPath
        Path to the log file. If not specified, attempts to use script-scoped $LogPath variable.
    
    .PARAMETER EnableDebugLogging
        Switch to enable DEBUG level messages. Can also read from script-scoped $EnableDebugLogging variable.
    
    .EXAMPLE
        Write-LogMessage "Starting process" -Level INFO -Component "Main"
    
    .EXAMPLE
        Write-LogMessage "Operation failed" -Level ERROR
    
    .NOTES
        Author: Andres Canello
        This function is used by multiple cmdlets in the Migrate2GSA module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'DEBUG', 'SUMMARY')]
        [string]$Level = 'INFO',
        
        [Parameter()]
        [string]$Component = '',
        
        [Parameter()]
        [string]$LogPath,
        
        [Parameter()]
        [switch]$EnableDebugLogging
    )
    
    try {
        # Check if DEBUG logging should be enabled from parent scope if not explicitly set
        $debugEnabled = $EnableDebugLogging.IsPresent
        if (-not $debugEnabled -and (Get-Variable -Name 'EnableDebugLogging' -Scope 1 -ErrorAction SilentlyContinue)) {
            $debugEnabled = (Get-Variable -Name 'EnableDebugLogging' -Scope 1).Value
        }
        
        # Skip DEBUG messages unless debug logging is enabled
        if ($Level -eq 'DEBUG' -and -not $debugEnabled) {
            return
        }
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # Handle empty messages for spacing
        if ([string]::IsNullOrEmpty($Message)) {
            Write-Host ""
            
            # Write empty line to log file if available
            if (-not [string]::IsNullOrEmpty($LogPath)) {
                try {
                    "" | Out-File -FilePath $LogPath -Append -Encoding UTF8
                }
                catch {
                    # Silently continue if log file write fails
                }
            }
            return
        }
        
        # Build log entry with optional component
        if ([string]::IsNullOrEmpty($Component)) {
            $logEntry = "[$timestamp] [$Level] $Message"
        }
        else {
            $logEntry = "[$timestamp] [$Level] [$Component] $Message"
        }
        
        # Color mapping for console output
        $colorMap = @{
            'INFO'    = 'White'
            'WARN'    = 'Yellow'
            'ERROR'   = 'Red'
            'SUCCESS' = 'Green'
            'DEBUG'   = 'Cyan'
            'SUMMARY' = 'Magenta'
        }
        
        # Write to console with color
        $color = $colorMap[$Level]
        if ($null -eq $color) { $color = 'White' }
        Write-Host $logEntry -ForegroundColor $color
        
        # Write to log file if LogPath is provided or available in parent scope
        $logFilePath = $LogPath
        if ([string]::IsNullOrEmpty($logFilePath)) {
            # Try to get LogPath from parent scope (for Convert-ZPA2EPA compatibility)
            if (Get-Variable -Name 'LogPath' -Scope 1 -ErrorAction SilentlyContinue) {
                $logFilePath = (Get-Variable -Name 'LogPath' -Scope 1).Value
            }
            # Try OutputBasePath + default log name (for Convert-ZPA2EPA compatibility)
            elseif (Get-Variable -Name 'OutputBasePath' -Scope 1 -ErrorAction SilentlyContinue) {
                $outputBase = (Get-Variable -Name 'OutputBasePath' -Scope 1).Value
                $callingFunction = (Get-PSCallStack)[1].Command
                if ($callingFunction -like '*ZPA*' -or $callingFunction -like '*Convert*') {
                    $logFilePath = Join-Path $outputBase "Convert-ZPA2EPA.log"
                }
                else {
                    $logFilePath = Join-Path $outputBase "Migrate2GSA.log"
                }
            }
        }
        
        if (-not [string]::IsNullOrEmpty($logFilePath)) {
            try {
                # Use Add-Content for consistency, suppress WhatIf
                Add-Content -Path $logFilePath -Value $logEntry -Encoding UTF8 -WhatIf:$false -ErrorAction Stop
            }
            catch {
                # Fallback to Out-File
                try {
                    $logEntry | Out-File -FilePath $logFilePath -Append -Encoding UTF8
                }
                catch {
                    Write-Warning "Failed to write to log file: $_"
                }
            }
        }
    }
    catch {
        # Fallback to basic Write-Host if logging fails
        Write-Host "[$Level] $Message"
    }
}
