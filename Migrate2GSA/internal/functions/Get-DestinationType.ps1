function Get-DestinationType {
    <#
    .SYNOPSIS
        Classify destination entry as URL, FQDN, IPv4, or IPv6 address.
    
    .DESCRIPTION
        Analyzes a destination string to determine its type for proper categorization
        in web content filtering policies. Supports classification of URLs (with paths),
        FQDNs (domain names), IPv4 addresses, and IPv6 addresses.
        
        Classification logic:
        - IPv4: Matches standard IPv4 pattern (e.g., 192.168.1.1)
        - URL: Contains forward slash indicating path
        - IPv6: Contains multiple colons with hex characters
        - FQDN: Domain names with optional wildcard prefix
    
    .PARAMETER Destination
        The destination string to classify (URL, FQDN, IP address, etc.)
    
    .EXAMPLE
        Get-DestinationType -Destination "192.168.1.1"
        Returns: 'ipv4'
    
    .EXAMPLE
        Get-DestinationType -Destination "*.example.com/path"
        Returns: 'URL'
    
    .EXAMPLE
        Get-DestinationType -Destination "*.domain.com"
        Returns: 'FQDN'
    
    .EXAMPLE
        Get-DestinationType -Destination "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        Returns: 'ipv6'
    
    .NOTES
        Author: Andres Canello
        Version: 1.0
        Date: 2025-11-17
        
        This function is used by conversion scripts to properly classify destinations
        for Entra Internet Access web content filtering policies.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Destination string to classify")]
        [string]$Destination
    )
    
    Set-StrictMode -Version Latest
    
    # Empty check
    if ([string]::IsNullOrWhiteSpace($Destination)) { return $null }
    
    # IPv4 check (basic pattern matching)
    if ($Destination -match '^(\d{1,3}\.){3}\d{1,3}$') { return 'ipv4' }
    
    # Path check - URLs contain forward slash (check before IPv6 to avoid false positives)
    if ($Destination -like '*/*') { return 'URL' }
    
    # IPv6 detection (hex characters with colons, but no forward slashes)
    # Must have multiple colons and contain hex characters (0-9, a-f, A-F)
    if ($Destination -match '^[0-9a-fA-F:]+$' -and $Destination -match ':.*:') { return 'ipv6' }
    
    # Wildcard position check
    if ($Destination -like '*`**') {
        if ($Destination.StartsWith('*.')) { return 'FQDN' }
        else { return 'URL' }  # Wildcard elsewhere makes it URL pattern
    }
    
    # Default to FQDN
    return 'FQDN'
}
