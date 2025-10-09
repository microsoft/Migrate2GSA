function Write-ProgressUpdate {
    <#
    .SYNOPSIS
        Updates progress bar with ETA calculation.
    
    .DESCRIPTION
        Displays a progress bar with percentage complete, elapsed time, and estimated time remaining.
        Automatically calculates ETA based on processing speed.
    
    .PARAMETER Current
        Current item number being processed.
    
    .PARAMETER Total
        Total number of items to process.
    
    .PARAMETER Activity
        Description of the activity being performed.
    
    .PARAMETER Status
        Current status message. Defaults to "Processing...".
    
    .PARAMETER StartTime
        The start time of the operation. If not provided, attempts to use script-scoped
        $ProvisioningStats.StartTime or calculates based on current progress.
    
    .EXAMPLE
        Write-ProgressUpdate -Current 5 -Total 20 -Activity "Processing segments"
    
    .EXAMPLE
        Write-ProgressUpdate -Current $i -Total $total -Activity "Creating apps" -Status "Working on app $appName"
    
    .NOTES
        Author: Andres Canello
        This function is used by multiple cmdlets in the Migrate2GSA module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Current,
        
        [Parameter(Mandatory = $true)]
        [int]$Total,
        
        [Parameter(Mandatory = $true)]
        [string]$Activity,
        
        [Parameter()]
        [string]$Status = "Processing...",
        
        [Parameter()]
        [datetime]$StartTime
    )
    
    try {
        # Validate inputs
        if ($Total -le 0) {
            Write-Warning "Write-ProgressUpdate: Total must be greater than 0"
            return
        }
        
        # Get start time from parameter or parent scope
        $operationStartTime = $StartTime
        if ($operationStartTime -eq [datetime]::MinValue -or $null -eq $operationStartTime) {
            # Try to get from parent scope ProvisioningStats
            if (Get-Variable -Name 'ProvisioningStats' -Scope 1 -ErrorAction SilentlyContinue) {
                $stats = (Get-Variable -Name 'ProvisioningStats' -Scope 1).Value
                if ($stats.PSObject.Properties.Name -contains 'StartTime') {
                    $operationStartTime = $stats.StartTime
                }
            }
            
            # If still not found, use current time (won't have accurate ETA but won't fail)
            if ($operationStartTime -eq [datetime]::MinValue -or $null -eq $operationStartTime) {
                $operationStartTime = Get-Date
            }
        }
        
        $percentComplete = [math]::Round(($Current / $Total) * 100, 2)
        $elapsed = (Get-Date) - $operationStartTime
        
        # Calculate ETA
        if ($Current -gt 0) {
            $estimatedTotal = $elapsed.TotalSeconds * ($Total / $Current)
            $remaining = [TimeSpan]::FromSeconds($estimatedTotal - $elapsed.TotalSeconds)
            $eta = "ETA: {0:mm\:ss}" -f $remaining
        }
        else {
            $eta = "ETA: Calculating..."
        }
        
        # Display progress
        Write-Progress -Activity $Activity `
                       -Status "$Status - $eta" `
                       -PercentComplete $percentComplete `
                       -CurrentOperation "Item $Current of $Total"
    }
    catch {
        # Fail silently - progress updates should never break the main flow
        Write-Verbose "Write-ProgressUpdate error: $_"
    }
}
