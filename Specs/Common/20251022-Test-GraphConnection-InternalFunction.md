# Specification: Test-GraphConnection Internal Function

**Date:** October 22, 2025  
**Status:** Draft  
**Author:** Andres Canello  
**Related Files:**
- `Migrate2GSA/internal/functions/Test-GraphConnection.ps1` (new file)
- `Migrate2GSA/functions/GSA/Start-EntraPrivateAccessProvisioning.ps1` (consumer)

## Overview

Extract the authentication validation logic from `Test-EntraConnection` into a reusable internal function named `Test-GraphConnection` that can validate Microsoft Graph PowerShell SDK connections with configurable required scopes.

## Background

Currently, authentication validation is embedded within individual functions. This creates duplication and makes it difficult to:
- Maintain consistent authentication checking across multiple functions
- Reuse the same validation logic for different required scopes
- Update authentication methods centrally

The new internal function will use `Get-MgContext` from the Microsoft.Graph.Authentication module as the standard for checking authentication status.

## Requirements

### Functional Requirements

1. **Function Name and Location**
   - Function name: `Test-GraphConnection`
   - Location: `Migrate2GSA/internal/functions/Test-GraphConnection.ps1`
   - Type: Internal function (not exported from module)

2. **Parameters**
   - `RequiredScopes` - Mandatory string array parameter containing the scopes needed for the operation
   - Should support PowerShell common parameters via `[CmdletBinding()]`

3. **Authentication Check**
   - Use `Get-MgContext` from Microsoft.Graph.Authentication module to check for active connection
   - Do NOT attempt to establish connection automatically
   - Validate only; connection establishment is the caller's responsibility

4. **Scope Validation**
   - Compare required scopes against the scopes in the current context
   - Check if ALL required scopes are present in the current context
   - Scope comparison should be case-insensitive
   - Report ALL missing scopes, not just the first one found

5. **Error Handling**
   - If no connection exists: Write ERROR message and throw terminating error
   - If scopes are missing: Write ERROR message and throw terminating error
   - Use `Write-LogMessage` for all output (INFO, WARN, ERROR, SUCCESS levels)
   - Terminating errors should stop script execution

6. **User Guidance**
   - When connection is missing or insufficient, provide:
     - Clear error message explaining the issue
     - Links to official Microsoft documentation:
       - Microsoft Graph PowerShell: https://learn.microsoft.com/powershell/microsoftgraph/get-started?view=graph-powershell-1.0#sign-in
       - Entra PowerShell: https://learn.microsoft.com/powershell/entra-powershell/installation?view=entra-powershell&tabs=powershell%2Cv1&pivots=windows#sign-in
     - Exact command needed to connect with required scopes

7. **Success Output**
   - On successful validation, log:
     - Tenant ID
     - Connected account
     - Success confirmation message
   - Return `$true` on success

8. **Module Dependencies**
   - Function assumes Microsoft.Graph.Authentication module is already loaded
   - Module validation is handled separately by existing `Test-RequiredModules` function
   - Do NOT include module checking logic in this function

### Non-Functional Requirements

1. **PowerShell Best Practices**
   - Follow PowerShell cmdlet development guidelines (per instructions)
   - Use approved verbs (`Test-`)
   - Implement comment-based help with SYNOPSIS, DESCRIPTION, PARAMETER, EXAMPLE, NOTES
   - Use proper error handling with try/catch blocks
   - Support `-Verbose` and `-Debug` common parameters

2. **Logging Integration**
   - Use internal `Write-LogMessage` function for all output
   - Component name: "Auth"
   - Log levels:
     - INFO: For validation steps and context information
     - SUCCESS: When validation passes
     - ERROR: When validation fails
     - WARN: Not expected in normal flow

3. **Code Quality**
   - Clear, descriptive variable names
   - Comprehensive inline comments for complex logic
   - Consistent formatting and indentation (4 spaces)

## Design Decisions

### Decision 1: Scope Parameter as Simple Array
**Rationale:** Keep the interface simple. The function validates scopes but doesn't attempt remediation. Connection management remains the caller's responsibility.

### Decision 2: Use Get-MgContext Only
**Rationale:** `Get-MgContext` provides access to the current authentication context for both Microsoft Graph and Entra PowerShell modules. The context object includes `Scopes`, `TenantId`, `Account`, and other authentication details needed for validation. This provides a unified way to check authentication status regardless of whether the user connected via `Connect-MgGraph` or `Connect-Entra`.

### Decision 3: Separate Module Validation
**Rationale:** Single Responsibility Principle. Module presence checking is already handled by `Test-RequiredModules`. This function focuses solely on authentication validation, assuming required modules are loaded.

### Decision 4: Always Throw on Failure
**Rationale:** Authentication is a critical prerequisite. If authentication fails, execution should stop immediately. This prevents cascading failures and provides clear feedback to the user.

### Decision 5: Always Use Write-LogMessage
**Rationale:** Consistent logging throughout the module. Using the internal `Write-LogMessage` function ensures all output follows the same format and writes to the configured log file.

### Decision 6: Provide Official Documentation Links
**Rationale:** Users may be unfamiliar with the connection commands. Providing official Microsoft Learn links gives them authoritative guidance for both Microsoft Graph and Entra PowerShell authentication methods.

## Function Signature

```powershell
function Test-GraphConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$RequiredScopes
    )
}
```

## Implementation Details

### Input Validation
- `RequiredScopes` must be a non-empty string array
- Use `[ValidateNotNullOrEmpty()]` attribute

### Authentication Check Logic
```powershell
# 1. Get current context (works for both Connect-MgGraph and Connect-Entra)
$context = Get-MgContext -ErrorAction SilentlyContinue

# 2. If no context exists
if (-not $context) {
    # Log error with guidance
    # Throw terminating error
}

# 3. Log tenant and account info
Write-LogMessage "Connected to tenant: $($context.TenantId)" -Level INFO -Component "Auth"
Write-LogMessage "Connected as: $($context.Account)" -Level INFO -Component "Auth"

# Optional: Log which module is being used
if ($context.EntraPSModuleName) {
    Write-LogMessage "Using $($context.EntraPSModuleName) v$($context.EntraPSVersion)" -Level INFO -Component "Auth"
}

# 4. Validate scopes (case-insensitive comparison)
$missingScopes = @()
foreach ($scope in $RequiredScopes) {
    # Case-insensitive comparison: convert both to lowercase
    $scopeFound = $false
    foreach ($contextScope in $context.Scopes) {
        if ($scope.ToLower() -eq $contextScope.ToLower()) {
            $scopeFound = $true
            break
        }
    }
    if (-not $scopeFound) {
        $missingScopes += $scope
    }
}

# 5. If scopes missing
if ($missingScopes.Count -gt 0) {
    # Log all missing scopes
    # Provide connection command with required scopes (use Connect-Entra as primary)
    # Throw terminating error
}

# 6. Success
Write-LogMessage "Authentication connection validated successfully" -Level SUCCESS -Component "Auth"
return $true
```

### Error Messages

**No Connection:**
```
No active authentication connection found.
Please connect using one of the following commands:

Connect-Entra -Scopes 'Scope1', 'Scope2', 'Scope3' -ContextScope Process

Or using Microsoft Graph PowerShell:
Connect-MgGraph -Scopes 'Scope1', 'Scope2', 'Scope3'

For more information:
- Microsoft Graph PowerShell: https://learn.microsoft.com/powershell/microsoftgraph/get-started?view=graph-powershell-1.0#sign-in
- Entra PowerShell: https://learn.microsoft.com/powershell/entra-powershell/installation?view=entra-powershell&tabs=powershell%2Cv1&pivots=windows#sign-in
```

**Missing Scopes:**
```
Missing required scopes: Scope1, Scope2
Please reconnect with one of the following commands:

Connect-Entra -Scopes 'Scope1', 'Scope2', 'Scope3' -ContextScope Process

Or using Microsoft Graph PowerShell:
Connect-MgGraph -Scopes 'Scope1', 'Scope2', 'Scope3'

For more information:
- Microsoft Graph PowerShell: https://learn.microsoft.com/powershell/microsoftgraph/get-started?view=graph-powershell-1.0#sign-in
- Entra PowerShell: https://learn.microsoft.com/powershell/entra-powershell/installation?view=entra-powershell&tabs=powershell%2Cv1&pivots=windows#sign-in
```

## Usage Examples

### Example 1: Basic Usage
```powershell
# Validate connection with specific scopes
$requiredScopes = @(
    'NetworkAccessPolicy.ReadWrite.All',
    'Application.ReadWrite.All',
    'NetworkAccess.ReadWrite.All'
)

Test-GraphConnection -RequiredScopes $requiredScopes
```

### Example 2: In Start-EntraPrivateAccessProvisioning
```powershell
# Replace existing Test-EntraConnection call
try {
    $requiredScopes = @(
        'NetworkAccessPolicy.ReadWrite.All',
        'Application.ReadWrite.All',
        'NetworkAccess.ReadWrite.All'
    )
    Test-GraphConnection -RequiredScopes $requiredScopes
}
catch {
    Write-LogMessage "Authentication validation failed: $_" -Level ERROR -Component "Main"
    throw
}
```

### Example 3: Different Scopes for Different Operations
```powershell
# For read-only operations
$readScopes = @(
    'Directory.Read.All',
    'Group.Read.All'
)
Test-GraphConnection -RequiredScopes $readScopes

# For write operations
$writeScopes = @(
    'Directory.ReadWrite.All',
    'Group.ReadWrite.All'
)
Test-GraphConnection -RequiredScopes $writeScopes
```

## Testing Considerations

### Test Scenarios

1. **No Active Connection**
   - Context: `Get-MgContext` returns `$null`
   - Expected: Error message with connection guidance, terminating error thrown

2. **Valid Connection with All Scopes**
   - Context: Active connection with all required scopes
   - Expected: Success message logged, function returns `$true`

3. **Valid Connection with Missing Scopes**
   - Context: Active connection but missing one or more required scopes
   - Expected: Error message listing missing scopes, terminating error thrown

4. **Case-Insensitive Scope Matching**
   - Context: Scopes differ only in case (e.g., "user.read" vs "User.Read")
   - Expected: Should match correctly regardless of case

5. **Multiple Missing Scopes**
   - Context: Connection missing several required scopes
   - Expected: All missing scopes reported in error message

6. **Empty Scopes Array**
   - Context: RequiredScopes parameter is empty array
   - Expected: Should be caught by `[ValidateNotNullOrEmpty()]` attribute

## Migration Strategy

### Phase 1: Create Internal Function
1. Create new file: `Migrate2GSA/internal/functions/Test-GraphConnection.ps1`
2. Implement function per specification
3. Add comprehensive comment-based help
4. Add to module auto-loading (internal functions are dot-sourced automatically)

### Phase 2: Update Start-EntraPrivateAccessProvisioning
1. Remove embedded `Test-EntraConnection` function
2. Replace call with `Test-GraphConnection` using appropriate scopes
3. Update error handling to use the new function's exceptions

### Phase 3: Future Consumers
1. Other functions requiring Graph authentication can use `Test-GraphConnection`
2. Document usage pattern in module documentation
3. Consider creating wrapper functions for common scope combinations

## Open Questions

None - all design decisions finalized based on user input.

## References

- Microsoft Graph PowerShell Get Started: https://learn.microsoft.com/powershell/microsoftgraph/get-started?view=graph-powershell-1.0#sign-in
- Entra PowerShell Installation: https://learn.microsoft.com/powershell/entra-powershell/installation?view=entra-powershell&tabs=powershell%2Cv1&pivots=windows#sign-in
- PowerShell Cmdlet Guidelines: .github/instructions/powershell.instructions.md
- Related Spec: 20251012-GraphRequestsFunction.md (for Graph API calls after authentication)

## Acceptance Criteria

- [ ] Function created in `Migrate2GSA/internal/functions/Test-GraphConnection.ps1`
- [ ] Function accepts `RequiredScopes` string array parameter
- [ ] Function uses `Get-MgContext` to check authentication
- [ ] Function validates all required scopes are present (case-insensitive)
- [ ] Function uses `Write-LogMessage` for all output
- [ ] Function throws terminating error on validation failure
- [ ] Error messages include connection commands and documentation links
- [ ] Success case logs tenant, account, and confirmation message
- [ ] Comment-based help is comprehensive with examples
- [ ] Function follows PowerShell best practices per module guidelines
- [ ] `Start-EntraPrivateAccessProvisioning` updated to use new function
- [ ] Testing confirms all error and success scenarios work correctly
