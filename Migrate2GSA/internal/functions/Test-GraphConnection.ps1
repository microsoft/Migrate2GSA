function Test-GraphConnection {
    <#
    .SYNOPSIS
        Validates Microsoft Graph PowerShell SDK connection and required permissions.
    
    .DESCRIPTION
        This internal function validates that an active Microsoft Graph PowerShell connection exists
        and that all required scopes are present in the current authentication context. It uses
        Get-MgContext from the Microsoft.Graph.Authentication module to check connection status.
        
        The function does NOT attempt to establish a connection automatically - it only validates
        an existing connection. Connection management is the caller's responsibility.
        
        If authentication is not present or required scopes are missing, the function provides
        clear error messages with connection commands and official documentation links to help
        users establish the correct connection.
    
    .PARAMETER RequiredScopes
        Mandatory string array containing the permission scopes required for the operation.
        The function validates that ALL specified scopes are present in the current context.
        
        Scope comparison is case-insensitive to handle variations in scope name casing.
        All missing scopes are reported in the error message, not just the first one found.
    
    .OUTPUTS
        System.Boolean
        Returns $true if authentication is valid and all required scopes are present.
        Throws a terminating error if validation fails.
    
    .EXAMPLE
        $requiredScopes = @(
            'NetworkAccessPolicy.ReadWrite.All',
            'Application.ReadWrite.All',
            'NetworkAccess.ReadWrite.All'
        )
        Test-GraphConnection -RequiredScopes $requiredScopes
        
        Validates that an active connection exists with all three specified scopes.
    
    .EXAMPLE
        try {
            Test-GraphConnection -RequiredScopes @('Directory.Read.All', 'Group.Read.All')
        }
        catch {
            Write-Error "Authentication validation failed: $_"
            throw
        }
        
        Validates connection with error handling to catch authentication failures.
    
    .EXAMPLE
        # For different operations requiring different scopes
        $readScopes = @('Directory.Read.All', 'Group.Read.All')
        Test-GraphConnection -RequiredScopes $readScopes
        
        $writeScopes = @('Directory.ReadWrite.All', 'Group.ReadWrite.All')
        Test-GraphConnection -RequiredScopes $writeScopes
        
        Demonstrates validating different scope requirements for read vs write operations.
    
    .NOTES
        Author: Andres Canello
        Version: 1.0
        Date: October 22, 2025
        
        This function assumes the Microsoft.Graph.Authentication module is already loaded.
        Module validation is handled separately by the Test-RequiredModules function.
        
        The function uses Write-LogMessage for all output to ensure consistent logging
        throughout the module. All messages use the "Auth" component identifier.
        
        Authentication errors are terminating to prevent cascading failures in operations
        that depend on valid authentication.
    
    .LINK
        https://learn.microsoft.com/powershell/microsoftgraph/get-started?view=graph-powershell-1.0#sign-in
    
    .LINK
        https://learn.microsoft.com/powershell/entra-powershell/installation?view=entra-powershell&tabs=powershell%2Cv1&pivots=windows#sign-in
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$RequiredScopes
    )
    
    Write-LogMessage "Validating Microsoft Graph authentication connection..." -Level INFO -Component "Auth"
    
    try {
        # Get current authentication context
        # Works for both Connect-MgGraph and Connect-Entra connections
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        # Check if authentication context exists
        if (-not $context) {
            Write-LogMessage "No active authentication connection found." -Level ERROR -Component "Auth"
            Write-LogMessage "Please connect using one of the following commands:" -Level ERROR -Component "Auth"
            Write-LogMessage "" -Level ERROR -Component "Auth"
            Write-LogMessage "Connect-Entra -Scopes '$($RequiredScopes -join "', '")' -ContextScope Process" -Level ERROR -Component "Auth"
            Write-LogMessage "" -Level ERROR -Component "Auth"
            Write-LogMessage "Or using Microsoft Graph PowerShell:" -Level ERROR -Component "Auth"
            Write-LogMessage "Connect-MgGraph -Scopes '$($RequiredScopes -join "', '")'" -Level ERROR -Component "Auth"
            Write-LogMessage "" -Level ERROR -Component "Auth"
            Write-LogMessage "For more information:" -Level ERROR -Component "Auth"
            Write-LogMessage "- Microsoft Graph PowerShell: https://learn.microsoft.com/powershell/microsoftgraph/get-started?view=graph-powershell-1.0#sign-in" -Level ERROR -Component "Auth"
            Write-LogMessage "- Entra PowerShell: https://learn.microsoft.com/powershell/entra-powershell/installation?view=entra-powershell&tabs=powershell%2Cv1&pivots=windows#sign-in" -Level ERROR -Component "Auth"
            
            throw "No active authentication connection found. Please connect using Connect-Entra or Connect-MgGraph."
        }
        
        # Log connection details
        Write-LogMessage "Connected to tenant: $($context.TenantId)" -Level INFO -Component "Auth"
        Write-LogMessage "Connected as: $($context.Account)" -Level INFO -Component "Auth"
        
        # Log which authentication module is being used if available
        if ($context.PSObject.Properties.Name -contains 'EntraPSModuleName' -and $context.EntraPSModuleName) {
            Write-LogMessage "Using $($context.EntraPSModuleName) v$($context.EntraPSVersion)" -Level INFO -Component "Auth"
        }
        
        # Validate required scopes are present in current context
        # Use case-insensitive comparison to handle scope name variations
        # Also accept ReadWrite scopes when Read-only scopes are required
        # (e.g., Application.ReadWrite.All satisfies Application.Read.All)
        $missingScopes = @()
        
        foreach ($requiredScope in $RequiredScopes) {
            # Check if this required scope exists in the context scopes (case-insensitive)
            $scopeFound = $false
            
            # Build list of acceptable scopes: the exact scope plus ReadWrite equivalent
            $acceptableScopes = @($requiredScope)
            if ($requiredScope -match '\.Read\.') {
                $acceptableScopes += $requiredScope -replace '\.Read\.', '.ReadWrite.'
            }
            
            foreach ($contextScope in $context.Scopes) {
                foreach ($acceptable in $acceptableScopes) {
                    if ($acceptable.ToLower() -eq $contextScope.ToLower()) {
                        $scopeFound = $true
                        break
                    }
                }
                if ($scopeFound) { break }
            }
            
            if (-not $scopeFound) {
                $missingScopes += $requiredScope
            }
        }
        
        # If any required scopes are missing, report all of them and throw error
        if ($missingScopes.Count -gt 0) {
            Write-LogMessage "Missing required scopes: $($missingScopes -join ', ')" -Level ERROR -Component "Auth"
            Write-LogMessage "Please reconnect with one of the following commands:" -Level ERROR -Component "Auth"
            Write-LogMessage "" -Level ERROR -Component "Auth"
            Write-LogMessage "Connect-Entra -Scopes '$($RequiredScopes -join "', '")' -ContextScope Process" -Level ERROR -Component "Auth"
            Write-LogMessage "" -Level ERROR -Component "Auth"
            Write-LogMessage "Or using Microsoft Graph PowerShell:" -Level ERROR -Component "Auth"
            Write-LogMessage "Connect-MgGraph -Scopes '$($RequiredScopes -join "', '")'" -Level ERROR -Component "Auth"
            Write-LogMessage "" -Level ERROR -Component "Auth"
            Write-LogMessage "For more information:" -Level ERROR -Component "Auth"
            Write-LogMessage "- Microsoft Graph PowerShell: https://learn.microsoft.com/powershell/microsoftgraph/get-started?view=graph-powershell-1.0#sign-in" -Level ERROR -Component "Auth"
            Write-LogMessage "- Entra PowerShell: https://learn.microsoft.com/powershell/entra-powershell/installation?view=entra-powershell&tabs=powershell%2Cv1&pivots=windows#sign-in" -Level ERROR -Component "Auth"
            
            throw "Missing required scopes: $($missingScopes -join ', '). Please reconnect with all required scopes."
        }
        
        # All validation passed
        Write-LogMessage "Authentication connection validated successfully" -Level SUCCESS -Component "Auth"
        return $true
    }
    catch {
        Write-LogMessage "Failed to validate authentication connection: $_" -Level ERROR -Component "Auth"
        throw
    }
}
