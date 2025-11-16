function Test-ValidIPv4Address {
    <#
    .SYNOPSIS
        Validate IPv4 address format.
    
    .DESCRIPTION
        Validates that a string represents a properly formatted IPv4 address.
        Checks both the pattern (4 octets separated by dots) and that each
        octet is within the valid range of 0-255.
        
        Does not validate CIDR notation, port numbers, or other IP-related formats.
        Only validates standard IPv4 addresses like 192.168.1.1.
    
    .PARAMETER IpAddress
        The IP address string to validate
    
    .EXAMPLE
        Test-ValidIPv4Address -IpAddress "192.168.1.1"
        Returns: $true
    
    .EXAMPLE
        Test-ValidIPv4Address -IpAddress "256.1.1.1"
        Returns: $false (octet out of range)
    
    .EXAMPLE
        Test-ValidIPv4Address -IpAddress "192.168.1"
        Returns: $false (not enough octets)
    
    .EXAMPLE
        Test-ValidIPv4Address -IpAddress "192.168.1.1:8080"
        Returns: $false (contains port number)
    
    .NOTES
        Author: Andres Canello
        Version: 1.0
        Date: 2025-11-17
        
        This function is used during destination classification to ensure
        IP addresses are properly formatted before processing.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "IPv4 address to validate")]
        [string]$IpAddress
    )
    
    Set-StrictMode -Version Latest
    
    # Must match IPv4 pattern
    if ($IpAddress -notmatch '^(\d{1,3}\.){3}\d{1,3}$') { return $false }
    
    # Validate each octet is 0-255
    $octets = $IpAddress.Split('.')
    foreach ($octet in $octets) {
        $num = [int]$octet
        if ($num -lt 0 -or $num -gt 255) { return $false }
    }
    
    return $true
}
