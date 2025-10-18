---
applyTo: '**/*.ps1,**/*.psm1'
description: 'PowerShell cmdlet and scripting best practices based on Microsoft guidelines'
---  

# PowerShell Cmdlet Development Guidelines

This guide provides PowerShell-specific instructions to help GitHub Copilot generate idiomatic, safe, and maintainable scripts. It aligns with Microsoft’s PowerShell cmdlet development guidelines.

## Naming Conventions

- **Verb-Noun Format:**
  - Use approved PowerShell verbs (Get-Verb)
  - Use singular nouns
  - PascalCase for both verb and noun
  - Avoid special characters and spaces

- **Parameter Names:**
  - Use PascalCase
  - Choose clear, descriptive names
  - Use singular form unless always multiple
  - Follow PowerShell standard names

- **Variable Names:**
  - Use PascalCase for public variables
  - Use camelCase for private variables
  - Avoid abbreviations
  - Use meaningful names

- **Alias Avoidance:**
  - Use full cmdlet names
  - Avoid using aliases in scripts (e.g., use Get-ChildItem instead of gci)
  - Document any custom aliases
  - Use full parameter names

### Example

```powershell
function Get-UserProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Username,

        [Parameter()]
        [ValidateSet('Basic', 'Detailed')]
        [string]$ProfileType = 'Basic'
    )

    process {
        # Logic here
    }
}
```

## Parameter Design

- **Standard Parameters:**
  - Use common parameter names (`Path`, `Name`, `Force`)
  - Follow built-in cmdlet conventions
  - Use aliases for specialized terms
  - Document parameter purpose

- **Parameter Names:**
  - Use singular form unless always multiple
  - Choose clear, descriptive names
  - Follow PowerShell conventions
  - Use PascalCase formatting

- **Type Selection:**
  - Use common .NET types
  - Implement proper validation
  - Consider ValidateSet for limited options
  - Enable tab completion where possible

- **Switch Parameters:**
  - Use [switch] for boolean flags
  - Avoid $true/$false parameters
  - Default to $false when omitted
  - Use clear action names

### Common Parameters

Common parameters are **automatically available** on any function or cmdlet that uses `[CmdletBinding()]` or `[Parameter()]` attributes. You don't need to declare them explicitly—PowerShell adds them for you.

**Available Common Parameters:**
- `Debug` (db) - Displays programmer-level debugging information
- `ErrorAction` (ea) - Controls how cmdlet responds to non-terminating errors
- `ErrorVariable` (ev) - Stores errors in specified variable
- `InformationAction` (infa) - Controls information stream display
- `InformationVariable` (iv) - Stores information records
- `OutVariable` (ov) - Stores output objects in variable
- `OutBuffer` (ob) - Number of objects to buffer before sending through pipeline
- `PipelineVariable` (pv) - Stores current pipeline value in named variable
- `ProgressAction` (proga) - Controls progress bar behavior (PowerShell 7.4+)
- `Verbose` (vb) - Displays detailed operation information
- `WarningAction` (wa) - Controls warning message display
- `WarningVariable` (wv) - Stores warnings in variable

**Key Points:**
- Common parameters are implemented by PowerShell, not by you
- They work automatically when you use `[CmdletBinding()]`
- Don't create parameters with these reserved names
- You can pass them through to other cmdlets using splatting
- They override preference variables for the current command only

**When Passing Common Parameters:**
```powershell
# Common parameters can be passed through splatting
function Invoke-MyCommand {
    [CmdletBinding()]
    param(
        [string]$Name
    )
    
    $params = @{
        Filter = "name eq '$Name'"
    }
    
    # Pass through common parameters like -Debug, -Verbose, -ErrorAction
    # Check if they're present in bound parameters
    if ($PSBoundParameters.ContainsKey('Debug')) {
        $params['Debug'] = $true
    }
    
    # Alternative: Check preference variables
    if ($DebugPreference -eq 'Continue') {
        $params['Debug'] = $true
    }
    
    Get-SomeObject @params
}
```

**ErrorAction Values:**
- `Stop` - Treat as terminating error, stop execution
- `Continue` (default) - Display error and continue
- `SilentlyContinue` - Suppress error and continue
- `Ignore` - Suppress error, don't add to `$Error` variable
- `Inquire` - Prompt user for action
- `Break` - Enter debugger
- `Suspend` - For workflows only (deprecated)

**Best Practices:**
- Let PowerShell handle common parameters automatically
- Use `-ErrorAction Stop` in try/catch blocks for proper error handling
- Use `-Verbose` to show operational details with `Write-Verbose`
- Use `-Debug` to show debug information with `Write-Debug`
- Never create your own parameters with common parameter names
- When calling other cmdlets, consider passing through Debug/Verbose based on preference variables

### Example

```powershell
function Set-ResourceConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter()]
        [ValidateSet('Dev', 'Test', 'Prod')]
        [string]$Environment = 'Dev',
        
        [Parameter()]
        [switch]$Force,
        
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$Tags
    )
    
    process {
        # Logic here
    }
}
```

## Pipeline and Output

- **Pipeline Input:**
  - Use `ValueFromPipeline` for direct object input
  - Use `ValueFromPipelineByPropertyName` for property mapping
  - Implement Begin/Process/End blocks for pipeline handling
  - Document pipeline input requirements

- **Output Objects:**
  - Return rich objects, not formatted text
  - Use PSCustomObject for structured data
  - Avoid Write-Host for data output
  - Enable downstream cmdlet processing

- **Pipeline Streaming:**
  - Output one object at a time
  - Use process block for streaming
  - Avoid collecting large arrays
  - Enable immediate processing

- **PassThru Pattern:**
  - Default to no output for action cmdlets
  - Implement `-PassThru` switch for object return
  - Return modified/created object with `-PassThru`
  - Use verbose/warning for status updates

### Example

```powershell
function Update-ResourceStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('Active', 'Inactive', 'Maintenance')]
        [string]$Status,

        [Parameter()]
        [switch]$PassThru
    )

    begin {
        Write-Verbose "Starting resource status update process"
        $timestamp = Get-Date
    }

    process {
        # Process each resource individually
        Write-Verbose "Processing resource: $Name"
        
        $resource = [PSCustomObject]@{
            Name = $Name
            Status = $Status
            LastUpdated = $timestamp
            UpdatedBy = $env:USERNAME
        }

        # Only output if PassThru is specified
        if ($PassThru) {
            Write-Output $resource
        }
    }

    end {
        Write-Verbose "Resource status update process completed"
    }
}
 ```

## Error Handling and Safety

- **ShouldProcess Implementation:**
  - Use `[CmdletBinding(SupportsShouldProcess = $true)]`
  - Set appropriate `ConfirmImpact` level
  - Call `$PSCmdlet.ShouldProcess()` for system changes
  - Use `ShouldContinue()` for additional confirmations

- **Message Streams:**
  - `Write-Verbose` for operational details with `-Verbose`
  - `Write-Warning` for warning conditions
  - `Write-Error` for non-terminating errors
  - `throw` for terminating errors
  - Avoid `Write-Host` except for user interface text

- **Error Handling Pattern:**
  - Use try/catch blocks for error management
  - Set appropriate ErrorAction preferences
  - Return meaningful error messages
  - Use ErrorVariable when needed
  - Include proper terminating vs non-terminating error handling

- **Non-Interactive Design:**
  - Accept input via parameters
  - Avoid `Read-Host` in scripts
  - Support automation scenarios
  - Document all required inputs

### Example

```powershell
function Remove-UserAccount {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$Username,

        [Parameter()]
        [switch]$Force
    )

    begin {
        Write-Verbose "Starting user account removal process"
        $ErrorActionPreference = 'Stop'
    }

    process {
        try {
            # Validation
            if (-not (Test-UserExists -Username $Username)) {
                Write-Error "User account '$Username' not found"
                return
            }

            # Confirmation
            $shouldProcessMessage = "Remove user account '$Username'"
            if ($Force -or $PSCmdlet.ShouldProcess($Username, $shouldProcessMessage)) {
                Write-Verbose "Removing user account: $Username"
                
                # Main operation
                Remove-ADUser -Identity $Username -ErrorAction Stop
                Write-Warning "User account '$Username' has been removed"
            }
        }
        catch [Microsoft.ActiveDirectory.Management.ADException] {
            Write-Error "Active Directory error: $_"
            throw
        }
        catch {
            Write-Error "Unexpected error removing user account: $_"
            throw
        }
    }

    end {
        Write-Verbose "User account removal process completed"
    }
}
```

## Documentation and Style

- **Comment-Based Help:** Include comment-based help for any public-facing function or cmdlet. Inside the function, add a `<# ... #>` help comment with at least:
  - `.SYNOPSIS` Brief description
  - `.DESCRIPTION` Detailed explanation
  - `.EXAMPLE` sections with practical usage
  - `.PARAMETER` descriptions
  - `.OUTPUTS` Type of output returned
  - `.NOTES` Additional information

- **Consistent Formatting:**
  - Follow consistent PowerShell style
  - Use proper indentation (4 spaces recommended)
  - Opening braces on same line as statement
  - Closing braces on new line
  - Use line breaks after pipeline operators
  - PascalCase for function and parameter names
  - Avoid unnecessary whitespace

- **Pipeline Support:**
  - Implement Begin/Process/End blocks for pipeline functions
  - Use ValueFromPipeline where appropriate
  - Support pipeline input by property name
  - Return proper objects, not formatted text

- **Avoid Aliases:** Use full cmdlet names and parameters
  - Avoid using aliases in scripts (e.g., use Get-ChildItem instead of gci); aliases are acceptable for interactive shell use.
  - Use `Where-Object` instead of `?` or `where`
  - Use `ForEach-Object` instead of `%`
  - Use `Get-ChildItem` instead of `ls` or `dir`

## Full Example: End-to-End Cmdlet Pattern

```powershell
function New-Resource {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        [ValidateSet('Development', 'Production')]
        [string]$Environment = 'Development'
    )
    
    begin {
        Write-Verbose "Starting resource creation process"
    }
    
    process {
        try {
            if ($PSCmdlet.ShouldProcess($Name, "Create new resource")) {
                # Resource creation logic here
                Write-Output ([PSCustomObject]@{
                    Name = $Name
                    Environment = $Environment
                    Created = Get-Date
                })
            }
        }
        catch {
            Write-Error "Failed to create resource: $_"
        }
    }
    
    end {
        Write-Verbose "Completed resource creation process"
    }
}
```
