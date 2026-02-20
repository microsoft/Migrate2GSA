# Shared Functions Implementation Summary

## Overview
This document describes the extraction and implementation of shared logging and progress functions into the Migrate2GSA PowerShell module's internal functions library.

## Date
October 9, 2025

## Changes Made

### 1. Created Internal Shared Functions

#### `Write-LogMessage.ps1`
- **Location**: `Migrate2GSA/internal/functions/Write-LogMessage.ps1`
- **Purpose**: Unified logging function for structured console and file logging
- **Features**:
  - Multiple log levels: INFO, WARN, ERROR, SUCCESS, DEBUG, SUMMARY
  - Component tagging for log categorization
  - Color-coded console output
  - Automatic file logging with UTF-8 encoding
  - Smart scope-based parameter detection (reads `$LogPath`, `$OutputBasePath`, `$EnableDebugLogging` from parent scope)
  - DEBUG level message filtering
  - Empty message support for spacing

#### `Write-ProgressUpdate.ps1`
- **Location**: `Migrate2GSA/internal/functions/Write-ProgressUpdate.ps1`
- **Purpose**: Progress bar display with ETA calculation
- **Features**:
  - Percentage complete calculation
  - Elapsed time tracking
  - Estimated time remaining (ETA)
  - Automatic `$ProvisioningStats.StartTime` detection from parent scope
  - Graceful error handling (fails silently to not interrupt main flow)

### 2. Updated Existing Functions

#### `Convert-ZPA2EPA.ps1`
- **Change**: Replaced all `Write-Log` calls with `Write-LogMessage`
- **Method**: PowerShell regex replacement (148+ occurrences)
- **Result**: No code changes required in calling patterns - parameter names and structure already matched

#### `Start-EntraPrivateAccessProvisioning.ps1`
- **Change**: Removed internal `Write-LogMessage` and `Write-ProgressUpdate` function definitions
- **Result**: Now uses shared internal functions from module
- **Benefit**: No calling code changes required - function signatures are identical

### 3. Module Integration

The `Migrate2GSA.psm1` file already includes automatic dot-sourcing of internal functions:
```powershell
foreach ($file in Get-ChildItem -Path "$PSScriptRoot/internal/functions" -Filter *.ps1 -Recurse) {
    . $file.FullName
}
```

This means the new shared functions are automatically available to all module functions.

## Benefits

### Code Reusability
- Single source of truth for logging and progress reporting
- Consistent behavior across all module functions
- Easier maintenance and updates

### No Breaking Changes
- Function names are identical
- Parameters are compatible
- No changes required to calling code in either file

### Enhanced Features
- `Write-LogMessage` is more robust than the original `Write-Log`
- Better error handling in both functions
- Smart scope-based parameter detection reduces boilerplate

### Future Scalability
- New functions can easily adopt these shared utilities
- Consistent logging format across the entire module
- Centralized updates benefit all consumers

## Testing Recommendations

1. **Test Convert-ZPA2EPA**:
   ```powershell
   Import-Module .\Migrate2GSA\Migrate2GSA.psd1 -Force
   Convert-ZPA2EPA -AppSegmentPath "test.json" -EnableDebugLogging
   ```

2. **Test Start-EntraPrivateAccessProvisioning**:
   ```powershell
   Import-Module .\Migrate2GSA\Migrate2GSA.psd1 -Force
   Start-EntraPrivateAccessProvisioning -ProvisioningConfigPath "test.csv" -WhatIf
   ```

3. **Verify Logging**:
   - Check console output for colored messages
   - Verify log files are created correctly
   - Confirm DEBUG messages are filtered appropriately

4. **Verify Progress**:
   - Ensure progress bars display correctly
   - Verify ETA calculations are accurate
   - Confirm progress doesn't break on errors

## Files Modified

1. `Migrate2GSA/internal/functions/Write-LogMessage.ps1` *(created)*
2. `Migrate2GSA/internal/functions/Write-ProgressUpdate.ps1` *(created)*
3. `Migrate2GSA/functions/ZScaler/Convert-ZPA2EPA.ps1` *(modified)*
4. `Migrate2GSA/functions/GSA/Start-EntraPrivateAccessProvisioning.ps1` *(modified)*

## Compatibility

- **PowerShell Version**: 5.1+ (Write-LogMessage), 7.0+ (Start-EntraPrivateAccessProvisioning per existing requirements)
- **Breaking Changes**: None
- **Dependencies**: None (pure PowerShell)

## Future Enhancements

Consider adding these shared internal functions in the future:
- Error handling wrapper functions
- Configuration validation helpers
- Common API retry logic
- File I/O helper functions
- Data transformation utilities
