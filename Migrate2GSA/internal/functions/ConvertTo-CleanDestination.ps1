function ConvertTo-CleanDestination {
    <#
    .SYNOPSIS
        Clean and normalize destination entries by removing unsupported components.
    
    .DESCRIPTION
        Cleans and normalizes destination strings for Entra Internet Access by removing
        or converting unsupported components such as:
        - HTTP/HTTPS schemas
        - Port numbers (for non-IP entries)
        - Query strings
        - Fragments
        - ZScaler wildcard format (.domain) to EIA format (*.domain)
        
        The function also validates that IPv4 addresses don't have ports or paths,
        as these are not supported in EIA.
        
        Returns $null if the destination becomes empty after cleaning or contains
        unsupported patterns.
    
    .PARAMETER Destination
        The destination string to clean and normalize
    
    .PARAMETER LogPath
        Path to the log file for writing debug messages
    
    .PARAMETER EnableDebugLogging
        Enable debug-level logging for detailed processing information
    
    .EXAMPLE
        ConvertTo-CleanDestination -Destination "https://example.com/path?query=1#fragment"
        Returns: "example.com/path"
    
    .EXAMPLE
        ConvertTo-CleanDestination -Destination ".contoso.com"
        Returns: "*.contoso.com"
        
        (Converts ZScaler wildcard format to EIA format)
    
    .EXAMPLE
        ConvertTo-CleanDestination -Destination "example.com:8080/path"
        Returns: "example.com/path"
        
        (Removes port number)
    
    .EXAMPLE
        ConvertTo-CleanDestination -Destination "192.168.1.1:8080"
        Returns: $null
        
        (IPv4 with port is not supported)
    
    .NOTES
        Author: Andres Canello
        Version: 1.0
        Date: 2025-11-17
        
        Known limitations:
        - IPv6 addresses are not supported
        - CIDR ranges are not supported
        - Port numbers on IP addresses are not supported
        - Query strings and fragments are removed
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Destination string to clean")]
        [string]$Destination,
        
        [Parameter(Mandatory = $true, HelpMessage = "Path to log file")]
        [string]$LogPath,
        
        [Parameter(HelpMessage = "Enable debug logging")]
        [bool]$EnableDebugLogging
    )
    
    Set-StrictMode -Version Latest
    
    if ([string]::IsNullOrWhiteSpace($Destination)) { return $null }
    
    $cleaned = $Destination.Trim()
    
    # Convert ZScaler leading dot wildcard (.domain) to EIA wildcard format (*.domain)
    if ($cleaned -match '^\.([a-zA-Z0-9][^/]*)'  -and $cleaned -notmatch '^\.\.') {
        Write-LogMessage "Converting ZScaler wildcard from '$cleaned' to '*.$($Matches[1])'" -Level "DEBUG" `
            -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
        $cleaned = "*.$($Matches[1])"
    }
    
    # Remove schema (http:// or https://)
    if ($cleaned -match '^https?://') {
        Write-LogMessage "Removing schema from: $Destination" -Level "DEBUG" `
            -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
        $cleaned = $cleaned -replace '^https?://', ''
    }
    
    # Check for IPv4 with port/path (should be skipped)
    if ($cleaned -match '^(\d{1,3}\.){3}\d{1,3}[:/]') {
        Write-LogMessage "Skipping IPv4 with port/path: $Destination" -Level "DEBUG" `
            -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
        return $null
    }
    
    # Remove port (for non-IP entries)
    # Only match port at the end of the string to avoid matching IPv6 colons
    if ($cleaned -match ':\d+$' -and $cleaned -notmatch '^(\d{1,3}\.){3}\d{1,3}(:\d+)?$') {
        Write-LogMessage "Removing port from: $Destination" -Level "DEBUG" `
            -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
        $cleaned = $cleaned -replace ':\d+$', ''
    }
    
    # Remove query string
    if ($cleaned.Contains('?')) {
        Write-LogMessage "Removing query string from: $Destination" -Level "DEBUG" `
            -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
        $cleaned = $cleaned.Split('?')[0]
    }
    
    # Remove fragment
    if ($cleaned.Contains('#')) {
        Write-LogMessage "Removing fragment from: $Destination" -Level "DEBUG" `
            -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
        $cleaned = $cleaned.Split('#')[0]
    }
    
    # Return null if cleaning resulted in empty string
    if ([string]::IsNullOrWhiteSpace($cleaned)) {
        Write-LogMessage "Destination became empty after cleaning: $Destination" -Level "DEBUG" `
            -Component "ConvertTo-CleanDestination" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
        return $null
    }
    
    return $cleaned
}
