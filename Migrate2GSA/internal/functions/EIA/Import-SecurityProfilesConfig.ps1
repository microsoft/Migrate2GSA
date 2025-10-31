function Import-SecurityProfilesConfig {
    <#
    .SYNOPSIS
        Loads and validates security profiles CSV configuration for Entra Internet Access provisioning.
    
    .DESCRIPTION
        Imports and validates the security profiles CSV file containing security profiles with policy links
        and Conditional Access policies. Performs structural validation, filters rows based on Provision field,
        and creates lookup hashtables for efficient provisioning.
    
    .PARAMETER ConfigPath
        Path to the security profiles CSV file.
    
    .OUTPUTS
        Returns array of validated security profile objects ready for provisioning.
    
    .EXAMPLE
        Import-SecurityProfilesConfig -ConfigPath ".\security_profiles.csv"
    
    .NOTES
        Author: Andres Canello
        This function performs Phase 1 validation (structural) during CSV import.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$ConfigPath
    )
    
    try {
        Write-LogMessage "Loading security profiles configuration from: $ConfigPath" -Level DEBUG -Component "Config"
        
        # Import CSV
        $csvData = Import-Csv -Path $ConfigPath -ErrorAction Stop
        
        if ($null -eq $csvData -or $csvData.Count -eq 0) {
            throw "CSV file is empty or contains no data rows"
        }
        
        Write-LogMessage "Loaded $($csvData.Count) rows from CSV" -Level DEBUG -Component "Config"
        
        #region Validate Required Columns
        $requiredColumns = @(
            'SecurityProfileName',
            'Priority',
            'SecurityProfileLinks',
            'CADisplayName',
            'EntraUsers',
            'EntraGroups',
            'Provision'
        )
        
        $actualColumns = $csvData[0].PSObject.Properties.Name
        $missingColumns = $requiredColumns | Where-Object { $_ -notin $actualColumns }
        
        if ($missingColumns.Count -gt 0) {
            throw "Missing required columns: $($missingColumns -join ', ')"
        }
        
        Write-LogMessage "All required columns present: $($requiredColumns -join ', ')" -Level DEBUG -Component "Config"
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
            $row | Add-Member -MemberType NoteProperty -Name 'SecurityProfileId' -Value '' -Force
            $row | Add-Member -MemberType NoteProperty -Name 'CAPolicyId' -Value '' -Force
            
            $processedData += $row
        }
        #endregion
        
        #region Filter and Validate Rows
        $filteredData = @()
        $filterReasons = @{}
        
        foreach ($row in $processedData) {
            $shouldFilter = $false
            $filterReason = ""
            
            # Filter by Provision field
            if ($row.Provision -eq 'no') {
                $shouldFilter = $true
                $filterReason = "Provision set to 'no'"
            }
            # Validate SecurityProfileName is present
            elseif ([string]::IsNullOrWhiteSpace($row.SecurityProfileName)) {
                $shouldFilter = $true
                $filterReason = "Missing required field SecurityProfileName"
            }
            # Validate Priority is present and is a valid integer
            elseif ([string]::IsNullOrWhiteSpace($row.Priority)) {
                $shouldFilter = $true
                $filterReason = "Missing required field Priority"
            }
            elseif (-not ($row.Priority -as [int])) {
                $shouldFilter = $true
                $filterReason = "Invalid Priority value (must be an integer)"
            }
            # Filter empty SecurityProfileLinks
            elseif ([string]::IsNullOrWhiteSpace($row.SecurityProfileLinks)) {
                $shouldFilter = $true
                $filterReason = "No policy links specified"
            }
            # Validate CADisplayName requirement based on users/groups
            else {
                $hasUsers = -not [string]::IsNullOrWhiteSpace($row.EntraUsers)
                $hasGroups = -not [string]::IsNullOrWhiteSpace($row.EntraGroups)
                
                if (($hasUsers -or $hasGroups) -and [string]::IsNullOrWhiteSpace($row.CADisplayName)) {
                    $shouldFilter = $true
                    $filterReason = "CADisplayName is required when users or groups are specified"
                }
            }
            
            if ($shouldFilter) {
                # Determine severity prefix
                $prefix = if ($filterReason -match '^(Missing|Invalid|CADisplayName)') { "Failed" } else { "Filtered" }
                $row.ProvisioningResult = "${prefix}: $filterReason"
                
                # Track reason for grouping
                if (-not $filterReasons.ContainsKey($filterReason)) {
                    $filterReasons[$filterReason] = 0
                }
                $filterReasons[$filterReason]++
                
                # Add to global results for export
                $Global:ProvisioningResults += $row
                continue
            }
            
            # Row passed all filters and validations
            $filteredData += $row
        }
        
        # Report filtered rows grouped by reason
        $totalFiltered = ($filterReasons.Values | Measure-Object -Sum).Sum
        if ($totalFiltered -gt 0) {
            foreach ($reason in $filterReasons.Keys) {
                $prefix = if ($reason -match '^(Missing|Invalid|CADisplayName)') { "Validation error" } else { "Filtered" }
                Write-LogMessage "$prefix ($($filterReasons[$reason]) rows): $reason" -Level INFO -Component "Config"
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
            $outputPath = Join-Path $PWD "security_profiles_filtered_only.csv"
            $processedData | Export-Csv -Path $outputPath -NoTypeInformation -Force
            Write-LogMessage "Filtered results exported to: $outputPath" -Level INFO -Component "Export"
            
            return $null
        }
        #endregion
        
        #region Data Parsing
        foreach ($row in $filteredData) {
            # Parse SecurityProfileLinks: "PolicyName1:Priority1;PolicyName2:Priority2"
            if (-not [string]::IsNullOrWhiteSpace($row.SecurityProfileLinks)) {
                $links = $row.SecurityProfileLinks -split ';' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                $parsedLinks = @()
                
                foreach ($link in $links) {
                    if ($link -match '^(.+):(\d+)$') {
                        $parsedLinks += @{
                            PolicyName = $Matches[1].Trim()
                            Priority   = [int]$Matches[2]
                        }
                    }
                    else {
                        Write-LogMessage "Invalid policy link format: '$link' in profile '$($row.SecurityProfileName)'. Expected format: 'PolicyName:Priority'" -Level WARN -Component "Config"
                    }
                }
                
                $row | Add-Member -MemberType NoteProperty -Name 'ParsedPolicyLinks' -Value $parsedLinks -Force
            }
            else {
                $row | Add-Member -MemberType NoteProperty -Name 'ParsedPolicyLinks' -Value @() -Force
            }
            
            # Parse EntraUsers
            if (-not [string]::IsNullOrWhiteSpace($row.EntraUsers)) {
                $users = $row.EntraUsers -split ';' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -ne '_Replace_Me' }
                $row | Add-Member -MemberType NoteProperty -Name 'ParsedUsers' -Value $users -Force
            }
            else {
                $row | Add-Member -MemberType NoteProperty -Name 'ParsedUsers' -Value @() -Force
            }
            
            # Parse EntraGroups
            if (-not [string]::IsNullOrWhiteSpace($row.EntraGroups)) {
                $groups = $row.EntraGroups -split ';' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -ne '_Replace_Me' }
                $row | Add-Member -MemberType NoteProperty -Name 'ParsedGroups' -Value $groups -Force
            }
            else {
                $row | Add-Member -MemberType NoteProperty -Name 'ParsedGroups' -Value @() -Force
            }
            
            # Add to global results tracking
            $Global:ProvisioningResults += $row
        }
        #endregion
        
        Write-LogMessage "Loaded $($filteredData.Count) security profiles from security profiles CSV" -Level INFO -Component "Config"
        
        return $filteredData
    }
    catch {
        Write-LogMessage "Failed to import security profiles configuration: $_" -Level ERROR -Component "Config"
        throw
    }
}
