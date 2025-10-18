function New-IntCustomHeaders {
    <#
    .SYNOPSIS
        Creates a custom header for use in telemetry as the Entra PowerShell module.
    
    .DESCRIPTION
        The custom header created is a User-Agent with header value "<PowerShell version> EntraPowershell/<EntraPowershell version> <Entra PowerShell command>"
    
    .PARAMETER Command
        The command name to include in the User-Agent header.
    
    .EXAMPLE
        New-IntCustomHeaders -Command Get-EntraUser
        Creates custom headers with the specified command name.
    
    .OUTPUTS
        System.Collections.Generic.Dictionary[string,string] containing the custom headers.
    
    .NOTES
        This function is used internally to add telemetry headers to Graph API requests.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Command
    )
    
    begin {
        $psVersion = $global:PSVersionTable.PSVersion
        
        # Get module version, handling both module context and dot-sourced scenarios
        $entraVersion = if ($ExecutionContext.SessionState.Module) {
            $ExecutionContext.SessionState.Module.Version.ToString()
        } else {
            # Fallback: Try to get from loaded Migrate2GSA module
            $loadedModule = Get-Module -Name 'Migrate2GSA' -ErrorAction SilentlyContinue
            if ($loadedModule) {
                $loadedModule.Version.ToString()
            } else {
                # Last resort: Use a default version
                '1.0.0'
            }
        }
        
        # Write-Verbose "Creating custom headers for command: $Command (Version: $entraVersion)"
    }
    
    process {
        $userAgentHeaderValue = "PowerShell/$psVersion EntraPowershell/$entraVersion $Command"
        $customHeaders = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        $customHeaders["User-Agent"] = $userAgentHeaderValue

        # Write-Verbose "User-Agent header: $userAgentHeaderValue"
        
        return $customHeaders
    }
}