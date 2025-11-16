function Get-BaseDomain {
    <#
    .SYNOPSIS
        Extract base domain (last 2 segments) for grouping destinations.
    
    .DESCRIPTION
        Extracts the base domain from a URL or FQDN by taking the last two segments
        (e.g., example.com from subdomain.example.com). This is used for grouping
        related destinations together when creating web content filtering rules.
        
        The function handles:
        - Wildcard prefixes (*.domain.com, .domain.com)
        - URLs with paths (removes path component)
        - Standard FQDNs
        
        Returns the last 2 segments for grouping purposes.
    
    .PARAMETER Domain
        The domain or URL string to process
    
    .EXAMPLE
        Get-BaseDomain -Domain "*.mail.google.com"
        Returns: "google.com"
    
    .EXAMPLE
        Get-BaseDomain -Domain "subdomain.example.com/path"
        Returns: "example.com"
    
    .EXAMPLE
        Get-BaseDomain -Domain ".contoso.com"
        Returns: "contoso.com"
    
    .EXAMPLE
        Get-BaseDomain -Domain "simple.co"
        Returns: "simple.co"
    
    .NOTES
        Author: Andres Canello
        Version: 1.0
        Date: 2025-11-17
        
        This function is used to group related destinations (e.g., multiple subdomains
        of the same base domain) for efficient rule organization.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Domain or URL to extract base domain from")]
        [string]$Domain
    )
    
    Set-StrictMode -Version Latest
    
    # Remove leading wildcards (both ZScaler .domain and standard *.domain formats)
    $cleanDomain = $Domain -replace '^\*\.', '' -replace '^\.', ''
    
    # Extract path-free domain for URLs
    if ($cleanDomain -like '*/*') {
        $cleanDomain = $cleanDomain.Split('/')[0]
    }
    
    # Get last 2 segments
    $segments = $cleanDomain.Split('.')
    if ($segments.Count -ge 2) {
        return "$($segments[-2]).$($segments[-1])"
    }
    
    return $cleanDomain
}
