function Test-RequiredModules {
    <#
    .SYNOPSIS
        Validates that required PowerShell modules are installed.
    
    .DESCRIPTION
        This internal function checks if the specified PowerShell modules are available on the system.
        If any modules are missing, it logs detailed error messages listing all missing modules and
        throws a terminating error to stop script execution.
        
        The function uses Get-Module -ListAvailable to check for module presence and reports the
        version of each installed module. It does NOT attempt to import or install modules automatically.
    
    .PARAMETER RequiredModules
        Mandatory string array containing the names of PowerShell modules that must be installed.
        Each module name will be checked using Get-Module -ListAvailable.
    
    .OUTPUTS
        System.Boolean
        Returns $true if all required modules are installed.
        Throws a terminating error if any modules are missing.
    
    .EXAMPLE
        $modules = @(
            'Microsoft.Entra.Beta.Groups',
            'Microsoft.Entra.Beta.Authentication',
            'Microsoft.Entra.Beta.NetworkAccess'
        )
        Test-RequiredModules -RequiredModules $modules
        
        Validates that all three Microsoft Entra Beta modules are installed.
    
    .EXAMPLE
        try {
            Test-RequiredModules -RequiredModules @('Microsoft.Graph.Authentication')
        }
        catch {
            Write-Error "Module validation failed: $_"
            exit 1
        }
        
        Validates module availability with error handling.
    
    .EXAMPLE
        # Check multiple module families
        $requiredModules = @(
            'Microsoft.Entra.Beta.Groups',
            'Microsoft.Graph.Authentication'
        )
        Test-RequiredModules -RequiredModules $requiredModules
        
        Validates modules from different module families.
    
    .NOTES
        Author: Andres Canello
        Version: 1.0
        Date: October 22, 2025
        
        This function does not check PowerShell version as that is enforced by the module manifest.
        The function uses Write-LogMessage for all output to ensure consistent logging throughout
        the module. All messages use the "ModuleCheck" component identifier.
        
        Module availability errors are terminating to prevent execution without required dependencies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$RequiredModules
    )
    
    Write-LogMessage "Validating required PowerShell modules..." -Level INFO -Component "ModuleCheck"
    
    $missingModules = @()
    $installedModules = @()
    
    foreach ($moduleName in $RequiredModules) {
        try {
            $module = Get-Module -Name $moduleName -ListAvailable -ErrorAction Stop
            if ($module) {
                $installedModules += $moduleName
                $latestVersion = ($module | Sort-Object Version -Descending | Select-Object -First 1).Version
                Write-LogMessage "✅ $moduleName (v$latestVersion) - Available" -Level SUCCESS -Component "ModuleCheck"
            } else {
                $missingModules += $moduleName
            }
        }
        catch {
            $missingModules += $moduleName
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-LogMessage "❌ Missing required PowerShell modules:" -Level ERROR -Component "ModuleCheck"
        foreach ($missingModule in $missingModules) {
            Write-LogMessage "   - $missingModule" -Level ERROR -Component "ModuleCheck"
        }
        
        Write-LogMessage "Please install missing modules using the following command:" -Level INFO -Component "ModuleCheck"
        Write-LogMessage "Install-Module -Name Microsoft.Graph.Authentication -Force -AllowClobber" -Level INFO -Component "ModuleCheck"
        
        throw "Required PowerShell modules are missing: $($missingModules -join ', ')"
    }
    
    Write-LogMessage "All required PowerShell modules are installed" -Level SUCCESS -Component "ModuleCheck"
    
    return $true
}
