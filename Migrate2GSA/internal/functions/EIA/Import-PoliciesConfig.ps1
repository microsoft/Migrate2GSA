function Import-PoliciesConfig {
    <#
    .SYNOPSIS
        Loads and validates policies CSV configuration for Entra Internet Access provisioning.
    
    .DESCRIPTION
        Imports and validates the policies CSV file containing web content filtering policies,
        TLS inspection policies, and their rules. Performs structural validation, filters rows
        based on Provision field and optional PolicyName filter, and creates lookup hashtables
        for efficient provisioning.
    
    .PARAMETER ConfigPath
        Path to the policies CSV file.
    
    .PARAMETER PolicyFilter
        Optional exact policy name to filter (case-insensitive).
    
    .OUTPUTS
        Returns array of validated policy rule objects ready for provisioning.
    
    .EXAMPLE
        Import-PoliciesConfig -ConfigPath ".\policies.csv"
    
    .EXAMPLE
        Import-PoliciesConfig -ConfigPath ".\policies.csv" -PolicyFilter "Finance_WebFilter"
    
    .NOTES
        Author: Andres Canello
        This function performs Phase 1 validation (structural) during CSV import.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$ConfigPath,
        
        [Parameter(Mandatory = $false)]
        [string]$PolicyFilter = ""
    )
    
    try {
        Write-LogMessage "Loading policies configuration from: $ConfigPath" -Level DEBUG -Component "Config"
        
        # Import CSV
        $csvData = Import-Csv -Path $ConfigPath -ErrorAction Stop
        
        if ($null -eq $csvData -or $csvData.Count -eq 0) {
            throw "CSV file is empty or contains no data rows"
        }
        
        Write-LogMessage "Loaded $($csvData.Count) rows from CSV" -Level DEBUG -Component "Config"
        
        #region Validate Required Columns
        $requiredColumns = @(
            'PolicyName',
            'PolicyType',
            'PolicyAction',
            'RuleType',
            'RuleDestinations',
            'RuleName',
            'Provision'
        )
        
        $actualColumns = $csvData[0].PSObject.Properties.Name
        $missingColumns = $requiredColumns | Where-Object { $_ -notin $actualColumns }
        
        if ($missingColumns.Count -gt 0) {
            throw "Missing required columns: $($missingColumns -join ', ')"
        }
        
        Write-LogMessage "All required columns present: $($requiredColumns -join ', ')" -Level DEBUG -Component "Config"
        #endregion
        
        #region Validate Policy Metadata Consistency
        Write-LogMessage "Validating policy metadata consistency..." -Level DEBUG -Component "Config"
        
        $policyGroups = $csvData | Group-Object PolicyName
        foreach ($policyGroup in $policyGroups) {
            $policyName = $policyGroup.Name
            $rows = $policyGroup.Group
            
            # Check PolicyType consistency
            $distinctTypes = $rows.PolicyType | Select-Object -Unique
            if ($distinctTypes.Count -gt 1) {
                throw "Policy '$policyName' has inconsistent PolicyType values: $($distinctTypes -join ', '). All rows for the same policy must have the same PolicyType."
            }
            
            # Check PolicyAction consistency
            $distinctActions = $rows.PolicyAction | Select-Object -Unique
            if ($distinctActions.Count -gt 1) {
                throw "Policy '$policyName' has inconsistent PolicyAction values: $($distinctActions -join ', '). All rows for the same policy must have the same PolicyAction."
            }
            
            # Check Description consistency (optional field, but should be consistent if present)
            $distinctDescriptions = $rows.Description | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
            if ($distinctDescriptions.Count -gt 1) {
                Write-LogMessage "Policy '$policyName' has inconsistent Description values. Using first non-empty description." -Level WARN -Component "Config"
            }
        }
        
        Write-LogMessage "Policy metadata consistency validated successfully" -Level DEBUG -Component "Config"
        #endregion
        
        #region Add Tracking Fields
        $processedData = @()
        $rowIndex = 0
        
        foreach ($row in $csvData) {
            $rowIndex++
            
            # Add UniqueRecordId
            $row | Add-Member -MemberType NoteProperty -Name 'UniqueRecordId' -Value ([guid]::NewGuid().ToString()) -Force
            
            # Add ProvisioningResult tracking field
            $row | Add-Member -MemberType NoteProperty -Name 'ProvisioningResult' -Value '' -Force
            
            # Add ObjectId fields for tracking created resources
            $row | Add-Member -MemberType NoteProperty -Name 'PolicyId' -Value '' -Force
            $row | Add-Member -MemberType NoteProperty -Name 'RuleId' -Value '' -Force
            
            $processedData += $row
        }
        #endregion
        
        #region Filter Rows
        $filteredData = @()
        $filterReasons = @{}
        
        foreach ($row in $processedData) {
            # Filter by Provision field
            if ($row.Provision -eq 'no') {
                $reason = "Provision set to 'no'"
                $row.ProvisioningResult = "Filtered: $reason"
                
                if (-not $filterReasons.ContainsKey($reason)) {
                    $filterReasons[$reason] = 0
                }
                $filterReasons[$reason]++
                
                # Add to global results for export
                $Global:ProvisioningResults += $row
                continue
            }
            
            # Filter by PolicyName if filter specified
            if (-not [string]::IsNullOrWhiteSpace($PolicyFilter)) {
                if ($row.PolicyName -ne $PolicyFilter) {
                    $reason = "Policy name does not match filter '$PolicyFilter'"
                    $row.ProvisioningResult = "Filtered: $reason"
                    
                    if (-not $filterReasons.ContainsKey($reason)) {
                        $filterReasons[$reason] = 0
                    }
                    $filterReasons[$reason]++
                    
                    # Add to global results for export
                    $Global:ProvisioningResults += $row
                    continue
                }
            }
            
            # Row passed all filters
            $filteredData += $row
        }
        
        # Report filtered rows grouped by reason
        $totalFiltered = ($filterReasons.Values | Measure-Object -Sum).Sum
        if ($totalFiltered -gt 0) {
            foreach ($reason in $filterReasons.Keys) {
                Write-LogMessage "Filtered $($filterReasons[$reason]) rows: $reason" -Level INFO -Component "Config"
            }
        }
        
        Write-LogMessage "Remaining rows for provisioning: $($filteredData.Count)" -Level DEBUG -Component "Config"
        
        $Global:ProvisioningStats.FilteredRecords += $totalFiltered
        #endregion
        
        #region Create Global Lookup Hashtable
        foreach ($row in $processedData) {
            $Global:RecordLookup[$row.UniqueRecordId] = $row
        }
        
        Write-LogMessage "Created global lookup hashtable with $($Global:RecordLookup.Count) records" -Level DEBUG -Component "Config"
        #endregion
        
        #region Validate Filtered Data
        if ($filteredData.Count -eq 0) {
            Write-LogMessage "No rows remaining after filtering. Nothing to provision." -Level WARN -Component "Config"
            
            # Export filtered results
            $outputPath = Join-Path $PWD "policies_filtered_only.csv"
            $processedData | Export-Csv -Path $outputPath -NoTypeInformation -Force
            Write-LogMessage "Filtered results exported to: $outputPath" -Level INFO -Component "Export"
            
            return $null
        }
        #endregion
        
        #region Data Parsing and Normalization
        foreach ($row in $filteredData) {
            # Split RuleDestinations by semicolon and trim
            if (-not [string]::IsNullOrWhiteSpace($row.RuleDestinations)) {
                $destinations = $row.RuleDestinations -split ';' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                $row | Add-Member -MemberType NoteProperty -Name 'ParsedDestinations' -Value $destinations -Force
            }
            else {
                $row | Add-Member -MemberType NoteProperty -Name 'ParsedDestinations' -Value @() -Force
            }
            
            # Convert PolicyAction to lowercase for API compatibility
            if (-not [string]::IsNullOrWhiteSpace($row.PolicyAction)) {
                $row.PolicyAction = $row.PolicyAction.ToLower()
            }
            
            # Add to global results tracking
            $Global:ProvisioningResults += $row
        }
        #endregion
        
        Write-LogMessage "Loaded $($filteredData.Count) policy rules from policies CSV" -Level INFO -Component "Config"
        
        return $filteredData
    }
    catch {
        Write-LogMessage "Failed to import policies configuration: $_" -Level ERROR -Component "Config"
        throw
    }
}
