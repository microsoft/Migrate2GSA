function Export-DataToFile {
    <#
    .SYNOPSIS
        Exports data to a file in JSON or CSV format.
    
    .DESCRIPTION
        Internal helper function for the Migrate2GSA module. Exports data arrays to files
        in either JSON or CSV format with automatic directory creation and error handling.
    
    .PARAMETER Data
        Array of objects to export. Must not be null or empty.
    
    .PARAMETER FilePath
        Full path to the output file. Parent directory will be created if it doesn't exist.
    
    .PARAMETER Format
        Export format. Valid values: JSON, CSV.
    
    .EXAMPLE
        Export-DataToFile -Data $results -FilePath "C:\Output\results.json" -Format "JSON"
        
        Exports the results array to a JSON file.
    
    .EXAMPLE
        Export-DataToFile -Data $segments -FilePath "C:\Output\segments.csv" -Format "CSV"
        
        Exports the segments array to a CSV file.
    
    .OUTPUTS
        System.Boolean
        Returns $true if export succeeds, $false otherwise.
    
    .NOTES
        Author: Andres Canello
        This function is used by multiple cmdlets in the Migrate2GSA module.
        Requires Write-LogMessage internal function for logging.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Data,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("JSON", "CSV")]
        [string]$Format
    )
    
    try {
        # Create output directory if it doesn't exist
        $outputDir = Split-Path $FilePath -Parent
        if (-not (Test-Path $outputDir)) {
            New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
            Write-LogMessage "Created output directory: $outputDir" -Level "INFO"
        }
        
        # Handle empty datasets
        if ($null -eq $Data -or $Data.Count -eq 0) {
            Write-LogMessage "No data to export to $FilePath" -Level "WARN"
            return $false
        }
        
        # Export data based on format
        switch ($Format) {
            "JSON" {
                $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath -Encoding UTF8
            }
            "CSV" {
                $Data | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
            }
        }
        
        Write-LogMessage "Successfully exported $($Data.Count) records to $FilePath" -Level "INFO"
        return $true
    }
    catch {
        Write-LogMessage "Failed to export data to $FilePath : $_" -Level "ERROR"
        return $false
    }
}
