function ConvertTo-UserGroupKey {
    <#
    .SYNOPSIS
        Creates a unique key from user and group arrays for aggregation.
    
    .DESCRIPTION
        Generates a unique string key by combining sorted email addresses and group names
        in the format "emails|groups". Used for aggregating policies by assignment.
    
    .PARAMETER Emails
        Array of email addresses to include in the key.
    
    .PARAMETER Groups
        Array of group names to include in the key.
    
    .OUTPUTS
        System.String - Unique key in format "email1,email2|group1,group2"
    
    .EXAMPLE
        ConvertTo-UserGroupKey -Emails @("user1@domain.com", "user2@domain.com") -Groups @("Group1", "Group2")
        Returns: "user1@domain.com,user2@domain.com|Group1,Group2"
    
    .EXAMPLE
        ConvertTo-UserGroupKey -Emails @() -Groups @("Group1")
        Returns: "|Group1"
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$Emails = @(),
        
        [Parameter(Mandatory = $false)]
        [string[]]$Groups = @()
    )
    
    # Sort and join emails
    $emailKey = ($Emails | Sort-Object) -join ','
    
    # Sort and join groups
    $groupKey = ($Groups | Sort-Object) -join ','
    
    # Combine with pipe separator
    $combinedKey = "${emailKey}|${groupKey}"
    
    return $combinedKey
}
