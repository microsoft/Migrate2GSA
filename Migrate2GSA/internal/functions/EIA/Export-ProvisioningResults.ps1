function Export-ProvisioningResults {
    <#
    .SYNOPSIS
        Exports provisioning results to CSV file with updated Provision field.
    
    .DESCRIPTION
        Exports all provisioning results (from $Global:ProvisioningResults) to a CSV file.
        Updates the Provision field based on provisioning outcomes:
        - Successfully provisioned or reused items: Provision=no (skip on re-run)
        - Failed, filtered, or skipped items: Provision=yes (retry on re-run)
    
    .PARAMETER OutputPath
        Path to the output CSV file.
    
    .PARAMETER ConfigType
        Type of configuration: 'Policies' or 'SecurityProfiles'.
    
    .OUTPUTS
        None. Exports CSV file to specified path.
    
    .EXAMPLE
        Export-ProvisioningResults -OutputPath ".\policies_results.csv" -ConfigType "Policies"
    
    .NOTES
        Author: Andres Canello
        Output CSV can be used as input for re-runs to retry only failed items.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('Policies', 'SecurityProfiles')]
        [string]$ConfigType
    )
    
    try {
        Write-LogMessage "Exporting provisioning results to: $OutputPath" -Level INFO -Component "Export"
        
        # Filter results based on config type
        $resultsToExport = @()
        
        foreach ($record in $Global:ProvisioningResults) {
            # Filter by config type
            if ($ConfigType -eq 'Policies') {
                # Policies have PolicyType property
                if ($record.PSObject.Properties.Name -contains 'PolicyType') {
                    $resultsToExport += $record
                }
            }
            elseif ($ConfigType -eq 'SecurityProfiles') {
                # Security Profiles have SecurityProfileName property
                if ($record.PSObject.Properties.Name -contains 'SecurityProfileName') {
                    $resultsToExport += $record
                }
            }
        }
        
        if ($resultsToExport.Count -eq 0) {
            Write-LogMessage "No results to export for $ConfigType" -Level WARN -Component "Export"
            return
        }
        
        # Update Provision field based on provisioning result
        foreach ($record in $resultsToExport) {
            $result = $record.ProvisioningResult
            
            # Determine new Provision value
            if ([string]::IsNullOrWhiteSpace($result)) {
                # No provisioning attempted (shouldn't happen, but default to retry)
                $record.Provision = 'yes'
            }
            elseif ($result -match '^(Provisioned|Reused|Skipped):') {
                # Successfully provisioned, reused, or intentionally skipped
                $record.Provision = 'no'
            }
            elseif ($result -match '^(Failed|Filtered|Partial):') {
                # Failed or filtered - retain for retry
                $record.Provision = 'yes'
            }
            else {
                # Unknown result - default to retry
                $record.Provision = 'yes'
            }
        }
        
        # Export to CSV
        $resultsToExport | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        
        Write-LogMessage "Exported $($resultsToExport.Count) results to: $OutputPath" -Level SUCCESS -Component "Export"
    }
    catch {
        Write-LogMessage "Error exporting provisioning results: $_" -Level ERROR -Component "Export"
        throw
    }
}
