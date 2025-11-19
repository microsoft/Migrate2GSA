function Get-GroupNameFromX500 {
    <#
    .SYNOPSIS
        Extracts group name from X500 AD-style path.
    
    .DESCRIPTION
        Parses an X500 path (e.g., "contoso.com.au/Groups/Finance/APP Finance Users") 
        and returns the last segment as the group name.
    
    .PARAMETER X500Path
        The X500 AD-style path to parse.
    
    .OUTPUTS
        System.String - The group name (last segment of path), or $null if parsing fails.
    
    .EXAMPLE
        Get-GroupNameFromX500 -X500Path "contoso.com.au/Groups/Finance/APP Finance Users"
        Returns: "APP Finance Users"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$X500Path
    )
    
    try {
        if ([string]::IsNullOrWhiteSpace($X500Path)) {
            return $null
        }
        
        # Split by forward slash and get last segment
        $segments = $X500Path -split '/'
        if ($segments.Count -eq 0) {
            return $null
        }
        
        $groupName = $segments[-1].Trim()
        
        if ([string]::IsNullOrWhiteSpace($groupName)) {
            return $null
        }
        
        return $groupName
    }
    catch {
        Write-Error "Failed to parse X500 path '$X500Path': $_"
        return $null
    }
}
