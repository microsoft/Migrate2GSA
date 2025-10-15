function Test-WildcardMatch {
    <#
    .SYNOPSIS
        Tests if a text string matches a wildcard pattern.
    
    .DESCRIPTION
        Internal helper function for the Migrate2GSA module. Converts PowerShell-style
        wildcard patterns (* and ?) to regular expressions and tests if a text string
        matches the pattern. Used for filtering operations throughout the module.
    
    .PARAMETER Pattern
        Wildcard pattern string. Supports * (any characters) and ? (single character).
    
    .PARAMETER Text
        Text string to test against the pattern.
    
    .EXAMPLE
        Test-WildcardMatch -Pattern "Web*" -Text "WebApp-Prod"
        
        Returns $true because "WebApp-Prod" matches the "Web*" pattern.
    
    .EXAMPLE
        Test-WildcardMatch -Pattern "Test?" -Text "Test1"
        
        Returns $true because "Test1" matches the "Test?" pattern.
    
    .EXAMPLE
        Test-WildcardMatch -Pattern "App*Prod" -Text "AppService-Prod"
        
        Returns $true because "AppService-Prod" matches the "App*Prod" pattern.
    
    .OUTPUTS
        System.Boolean
        Returns $true if text matches pattern, $false otherwise.
    
    .NOTES
        Author: Andres Canello
        This function is used by multiple cmdlets in the Migrate2GSA module.
        Requires Write-LogMessage internal function for error logging.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Pattern,
        
        [Parameter(Mandatory = $true)]
        [string]$Text
    )
    
    try {
        # Convert wildcard pattern to regex
        $regexPattern = $Pattern.Replace('*', '.*').Replace('?', '.')
        return $Text -match "^$regexPattern$"
    }
    catch {
        Write-LogMessage "Error in wildcard matching: $_" -Level "ERROR"
        return $false
    }
}
