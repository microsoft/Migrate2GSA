function Split-ByCharacterLimit {
    <#
    .SYNOPSIS
        Split destination arrays by character limit without truncating entries.
    
    .DESCRIPTION
        Splits an array of destination entries into multiple groups to comply with
        the Entra Internet Access 300-character limit per Destinations field.
        
        The function ensures that:
        - Individual entries are never truncated
        - Groups stay under the specified character limit (accounting for semicolon separators)
        - All entries are preserved across the groups
        
        This is used when creating web content filtering rules that have destination
        limits based on the combined length of all destinations in the rule.
    
    .PARAMETER Entries
        Array of destination entries to split (FQDNs, URLs, IP addresses)
    
    .PARAMETER MaxLength
        Maximum character length for the combined entries (default: 300)
        This accounts for semicolon separators between entries.
    
    .EXAMPLE
        $destinations = @("long-domain-name.com", "another-long-domain.com", "short.com")
        Split-ByCharacterLimit -Entries $destinations -MaxLength 50
        
        Returns array of groups where each group's combined length (with separators) <= 50
    
    .EXAMPLE
        $urls = @("*.example.com/very/long/path", "*.contoso.com", "*.microsoft.com")
        $groups = Split-ByCharacterLimit -Entries $urls
        
        Returns: @(
            @("*.example.com/very/long/path"),
            @("*.contoso.com", "*.microsoft.com")
        )
    
    .NOTES
        Author: Andres Canello
        Version: 1.0
        Date: 2025-11-17
        
        The 300-character limit applies to FQDN, URL, and ipAddress rule types.
        Web category rules (webCategory type) do not have this limit.
        
        Character count includes semicolon separators between entries but not
        surrounding quotes in CSV format.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Array of entries to split")]
        [array]$Entries,
        
        [Parameter(HelpMessage = "Maximum character length per group (default: 300)")]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$MaxLength = 300,
        
        [Parameter(HelpMessage = "Path to log file")]
        [string]$LogPath,
        
        [Parameter(HelpMessage = "Enable debug logging")]
        [switch]$EnableDebugLogging
    )
    
    Set-StrictMode -Version Latest
    
    Write-LogMessage "Split-ByCharacterLimit: Received $($Entries.Count) entries, MaxLength=$MaxLength" -Level "DEBUG" `
        -Component "Split-ByCharacterLimit" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
    
    $groups = @()
    $currentGroup = @()
    $currentLength = 0
    
    foreach ($entry in $Entries) {
        $entryLength = $entry.Length
        $separator = if ($currentGroup.Count -gt 0) { 1 } else { 0 }  # semicolon
        
        Write-LogMessage "Entry: '$entry' (length=$entryLength), currentLength=$currentLength, separator=$separator, would be=$($currentLength + $entryLength + $separator)" -Level "DEBUG" `
            -Component "Split-ByCharacterLimit" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
        
        if (($currentLength + $entryLength + $separator) -gt $MaxLength -and $currentGroup.Count -gt 0) {
            # Current group is full, start new group
            Write-LogMessage "Starting new group (current group has $($currentGroup.Count) entries, length=$currentLength)" -Level "DEBUG" `
                -Component "Split-ByCharacterLimit" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
            $groups += ,@($currentGroup)
            $currentGroup = @($entry)
            $currentLength = $entryLength
        }
        else {
            $currentGroup += $entry
            $currentLength += $entryLength + $separator
        }
    }
    
    # Add remaining group
    if ($currentGroup.Count -gt 0) {
        $groups += ,@($currentGroup)
    }
    
    Write-LogMessage "Split-ByCharacterLimit: Created $($groups.Count) group(s)" -Level "DEBUG" `
        -Component "Split-ByCharacterLimit" -LogPath $LogPath -EnableDebugLogging:$EnableDebugLogging
    
    # Return with comma operator to prevent PowerShell from flattening the array
    return ,$groups
}
