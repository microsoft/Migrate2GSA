param(
    [Parameter(Mandatory=$true)]
    [string]$AppSegmentsFile,
    
    [Parameter(Mandatory=$true)]
    [string]$SegmentGroupsFile,
    
    [Parameter(Mandatory=$false)]
    [switch]$DetailedReport = $false
)

# Function to write colored output
function Write-ColorOutput {
    param(
        [string]$Text,
        [string]$Color = "White"
    )
    Write-Host $Text -ForegroundColor $Color
}

# Function to validate file exists
function Test-FileExists {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) {
        Write-ColorOutput "ERROR: File not found: $FilePath" "Red"
        exit 1
    }
}

# Main script
Write-ColorOutput "=== App Segments and Segment Groups Comparison Script ===" "Cyan"
Write-ColorOutput "App Segments File: $AppSegmentsFile" "Yellow"
Write-ColorOutput "Segment Groups File: $SegmentGroupsFile" "Yellow"
Write-ColorOutput ""

# Validate input files
Test-FileExists $AppSegmentsFile
Test-FileExists $SegmentGroupsFile

try {
    # Load JSON files
    Write-ColorOutput "Loading JSON files..." "Gray"
    $appSegmentsData = Get-Content $AppSegmentsFile -Raw | ConvertFrom-Json
    $segmentGroupsData = Get-Content $SegmentGroupsFile -Raw | ConvertFrom-Json
    
    # Debug app segments data structure
    Write-ColorOutput "DEBUG: App Segments Data Type: $($appSegmentsData.GetType().Name)" "Magenta"
    if ($appSegmentsData -is [array]) {
        Write-ColorOutput "DEBUG: App Segments Data is array with $($appSegmentsData.Count) elements" "Magenta"
        if ($appSegmentsData.Count -gt 0) {
            Write-ColorOutput "DEBUG: First element type: $($appSegmentsData[0].GetType().Name)" "Magenta"
            if ($appSegmentsData[0]) {
                Write-ColorOutput "DEBUG: First element properties: $($appSegmentsData[0] | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name)" "Magenta"
            } else {
                Write-ColorOutput "DEBUG: First element is NULL!" "Red"
            }
        }
    } else {
        Write-ColorOutput "DEBUG: App Segments Data Properties: $($appSegmentsData | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name)" "Magenta"
    }
    
    # Extract app segments - handle both single object and array with 'list' property
    if ($appSegmentsData -is [array] -and $appSegmentsData.Count -gt 0) {
        $appSegments = $appSegmentsData
        Write-ColorOutput "DEBUG: Using appSegmentsData as array directly" "Magenta"
    } elseif ($appSegmentsData.list -and $appSegmentsData.list.Count -gt 0) {
        $appSegments = $appSegmentsData.list
        Write-ColorOutput "DEBUG: Using appSegmentsData.list property" "Magenta"
    } else {
        $appSegments = @($appSegmentsData)
        Write-ColorOutput "DEBUG: Wrapping appSegmentsData in array" "Magenta"
    }
    
    # Extract segment groups - handle both single object and array
    Write-ColorOutput "DEBUG: Segment Groups Data Type: $($segmentGroupsData.GetType().Name)" "Magenta"
    Write-ColorOutput "DEBUG: Segment Groups Data Properties: $($segmentGroupsData | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name)" "Magenta"
    
    if ($segmentGroupsData -is [array]) {
        $segmentGroups = $segmentGroupsData
        Write-ColorOutput "DEBUG: Using segmentGroupsData as array directly" "Magenta"
    } elseif ($segmentGroupsData.list) {
        $segmentGroups = $segmentGroupsData.list
        Write-ColorOutput "DEBUG: Using segmentGroupsData.list property" "Magenta"
    } else {
        $segmentGroups = @($segmentGroupsData)
        Write-ColorOutput "DEBUG: Wrapping segmentGroupsData in array" "Magenta"
    }
    
    # Filter out any null elements from arrays
    Write-ColorOutput "DEBUG: Filtering null elements..." "Magenta"
    $appSegments = @($appSegments | Where-Object { $_ -ne $null })
    $segmentGroups = @($segmentGroups | Where-Object { $_ -ne $null })
    Write-ColorOutput "DEBUG: After filtering - App Segments: $($appSegments.Count), Segment Groups: $($segmentGroups.Count)" "Magenta"
    
    Write-ColorOutput "Loaded $($appSegments.Count) app segments and $($segmentGroups.Count) segment groups" "Gray"
    Write-ColorOutput ""
    
    # Debug: Show sample data
    Write-ColorOutput "=== DEBUG INFO ===" "Magenta"
    if ($appSegments.Count -gt 0) {
        $sampleAppSeg = $appSegments[0]
        Write-ColorOutput "Sample App Segment:" "Magenta"
        if ($sampleAppSeg) {
            Write-ColorOutput "  Sample App Segment Type: $($sampleAppSeg.GetType().Name)" "Gray"
            Write-ColorOutput "  Sample App Segment Properties: $($sampleAppSeg | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name)" "Gray"
            
            if ($sampleAppSeg.id -ne $null) {
                Write-ColorOutput "  ID: '$($sampleAppSeg.id)' (Type: $($sampleAppSeg.id.GetType().Name))" "Gray"
            } else {
                Write-ColorOutput "  ID: [NULL]" "Red"
            }
            
            if ($sampleAppSeg.name -ne $null) {
                Write-ColorOutput "  Name: '$($sampleAppSeg.name)' (Type: $($sampleAppSeg.name.GetType().Name))" "Gray"
            } else {
                Write-ColorOutput "  Name: [NULL]" "Red"
            }
        } else {
            Write-ColorOutput "  First app segment is NULL!" "Red"
        }
    } else {
        Write-ColorOutput "  No app segments found!" "Red"
    }
    
    Write-ColorOutput "Segment Groups Count: $($segmentGroups.Count)" "Magenta"
    if ($segmentGroups.Count -gt 0) {
        $sampleSegGroup = $segmentGroups[0]
        Write-ColorOutput "Sample Segment Group:" "Magenta"
        if ($sampleSegGroup) {
            Write-ColorOutput "  Segment Group Type: $($sampleSegGroup.GetType().Name)" "Gray"
            Write-ColorOutput "  Segment Group Properties: $($sampleSegGroup | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name)" "Gray"
            
            if ($sampleSegGroup.name -ne $null) {
                Write-ColorOutput "  Name: '$($sampleSegGroup.name)'" "Gray"
            } else {
                Write-ColorOutput "  Name: [NULL]" "Red"
            }
            
            if ($sampleSegGroup.applications -ne $null) {
                Write-ColorOutput "  Applications Count: $($sampleSegGroup.applications.Count)" "Gray"
                Write-ColorOutput "  Applications Property Type: $($sampleSegGroup.applications.GetType().Name)" "Gray"
                
                if ($sampleSegGroup.applications.Count -gt 0) {
                    $sampleApp = $sampleSegGroup.applications[0]
                    Write-ColorOutput "  Sample Application in Segment Group:" "Magenta"
                    if ($sampleApp) {
                        Write-ColorOutput "    Application Type: $($sampleApp.GetType().Name)" "Gray"
                        Write-ColorOutput "    Application Properties: $($sampleApp | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name)" "Gray"
                        
                        if ($sampleApp.id -ne $null) {
                            Write-ColorOutput "    ID: '$($sampleApp.id)' (Type: $($sampleApp.id.GetType().Name))" "Gray"
                        } else {
                            Write-ColorOutput "    ID: [NULL]" "Red"
                        }
                        
                        if ($sampleApp.name -ne $null) {
                            Write-ColorOutput "    Name: '$($sampleApp.name)' (Type: $($sampleApp.name.GetType().Name))" "Gray"
                        } else {
                            Write-ColorOutput "    Name: [NULL]" "Red"
                        }
                    } else {
                        Write-ColorOutput "    First application in segment group is NULL!" "Red"
                    }
                } else {
                    Write-ColorOutput "  No applications found in first segment group" "Red"
                }
            } else {
                Write-ColorOutput "  Applications property is [NULL]" "Red"
            }
        } else {
            Write-ColorOutput "  First segment group is NULL!" "Red"
        }
    } else {
        Write-ColorOutput "No segment groups found!" "Red"
    }
    Write-ColorOutput ""

    # Create hashtables for faster lookups using only ID
    $appSegmentLookup = @{}
    
    foreach ($appSeg in $appSegments) {
        if ($appSeg -and $appSeg.id -ne $null) {
            # Normalize: convert to string
            $normalizedId = [string]$appSeg.id
            $appSegmentLookup[$normalizedId] = $appSeg
        }
    }
    
    # Extract all applications referenced in segment groups using only ID
    $referencedApps = @{}
    foreach ($segGroup in $segmentGroups) {
        if ($segGroup -and $segGroup.applications -ne $null) {
            foreach ($app in $segGroup.applications) {
                if ($app -and $app.id -ne $null) {
                    # Normalize: convert to string
                    $normalizedId = [string]$app.id
                    $appName = if ($app.name) { [string]$app.name } else { "Unknown" }
                    
                    if (-not $referencedApps.ContainsKey($normalizedId)) {
                        $referencedApps[$normalizedId] = @{
                            id = $normalizedId
                            name = $appName
                            segmentGroups = @()
                        }
                    }
                    $referencedApps[$normalizedId].segmentGroups += $segGroup.name
                }
            }
        }
    }
    
    Write-ColorOutput "=== ANALYSIS RESULTS ===" "Cyan"
    Write-ColorOutput ""
    
    # Check 1: App segments not referenced in any segment group
    Write-ColorOutput "1. App Segments NOT referenced in any Segment Group:" "Yellow"
    Write-ColorOutput ("=" * 60) "Yellow"
    
    $unreferencedSegments = @()
    $unreferencedTable = @()
    
    foreach ($appSeg in $appSegments) {
        if ($appSeg -and $appSeg.id -ne $null) {
            # Normalize for comparison using only ID
            $normalizedId = [string]$appSeg.id
            
            if (-not $referencedApps.ContainsKey($normalizedId)) {
                $unreferencedSegments += $appSeg
                
                $unreferencedTable += [PSCustomObject]@{
                    ID = $normalizedId
                    Name = if ($appSeg.name) { [string]$appSeg.name } else { "Unknown" }
                    Description = if ($appSeg.description) { $appSeg.description } else { "" }
                    Domain = if ($appSeg.domain) { $appSeg.domain } else { "" }
                }
            }
        }
    }
    
    if ($unreferencedSegments.Count -eq 0) {
        Write-ColorOutput "  ✓ All app segments are referenced in segment groups!" "Green"
    } else {
        Write-ColorOutput "  Found $($unreferencedSegments.Count) app segments not referenced in any segment group:" "Red"
        Write-ColorOutput ""
        $unreferencedTable | Format-Table -Property ID, Name, Description, Domain -AutoSize -Wrap
    }
    Write-ColorOutput ""
    
    # Check 2: Applications referenced in segment groups but not found in app segments
    Write-ColorOutput "2. Applications referenced in Segment Groups but NOT found in App Segments:" "Yellow"
    Write-ColorOutput ("=" * 70) "Yellow"
    
    $missingAppSegments = @()
    $missingAppTable = @()
    
    foreach ($refApp in $referencedApps.GetEnumerator()) {
        $appId = $refApp.Key
        if (-not $appSegmentLookup.ContainsKey($appId)) {
            $missingAppSegments += $refApp.Value
            
            $missingAppTable += [PSCustomObject]@{
                ID = $refApp.Value.id
                Name = $refApp.Value.name
                SegmentGroups = $refApp.Value.segmentGroups -join ', '
            }
        }
    }
    
    if ($missingAppSegments.Count -eq 0) {
        Write-ColorOutput "  ✓ All applications referenced in segment groups exist in app segments!" "Green"
    } else {
        Write-ColorOutput "  Found $($missingAppSegments.Count) applications referenced in segment groups but missing from app segments:" "Red"
        Write-ColorOutput ""
        $missingAppTable | Format-Table -Property ID, Name, SegmentGroups -AutoSize -Wrap
    }
    Write-ColorOutput ""
    
    # Summary
    Write-ColorOutput "=== SUMMARY ===" "Cyan"
    Write-ColorOutput "Total App Segments: $($appSegments.Count)" "White"
    Write-ColorOutput "Total Segment Groups: $($segmentGroups.Count)" "White"
    Write-ColorOutput "Total Applications Referenced in Segment Groups: $($referencedApps.Count)" "White"
    Write-ColorOutput "App Segments not referenced anywhere: $($unreferencedSegments.Count)" $(if ($unreferencedSegments.Count -gt 0) { "Red" } else { "Green" })
    Write-ColorOutput "Referenced Apps missing from App Segments: $($missingAppSegments.Count)" $(if ($missingAppSegments.Count -gt 0) { "Red" } else { "Green" })
    
    if ($unreferencedSegments.Count -eq 0 -and $missingAppSegments.Count -eq 0) {
        Write-ColorOutput "" 
        Write-ColorOutput "🎉 Perfect! All references are consistent between App Segments and Segment Groups." "Green"
    }
    
    # Only show detailed breakdown if requested
    if ($DetailedReport) {
        Write-ColorOutput ""
        Write-ColorOutput "=== DETAILED SEGMENT GROUP BREAKDOWN ===" "Cyan"
        
        $segmentGroupTable = @()
        foreach ($segGroup in $segmentGroups) {
            if ($segGroup -and $segGroup.applications -ne $null) {
                foreach ($app in $segGroup.applications) {
                    if ($app -and $app.id -ne $null) {
                        # Use only ID for comparison
                        $normalizedId = [string]$app.id
                        
                        $status = if ($appSegmentLookup.ContainsKey($normalizedId)) { "✓" } else { "✗" }
                        $appName = if ($app.name) { [string]$app.name } else { "Unknown" }
                        
                        $segmentGroupTable += [PSCustomObject]@{
                            Status = $status
                            ID = $normalizedId
                            Name = $appName
                            SegmentGroup = $segGroup.name
                        }
                    }
                }
            }
        }
        
        # Show all applications in segment groups in a table
        Write-ColorOutput "All applications referenced in Segment Groups:" "White"
        Write-ColorOutput ""
        $segmentGroupTable | Format-Table -Property Status, ID, Name, SegmentGroup -AutoSize -Wrap
        
        # Summary by segment group
        Write-ColorOutput "Summary by Segment Group:" "White"
        foreach ($segGroup in $segmentGroups) {
            $appCount = if ($segGroup.applications) { $segGroup.applications.Count } else { 0 }
            Write-ColorOutput "  $($segGroup.name): $appCount applications" "Gray"
            if ($segGroup.description) {
                Write-ColorOutput "    Description: $($segGroup.description)" "DarkGray"
            }
        }
    } else {
        Write-ColorOutput ""
        Write-ColorOutput "💡 Use -DetailedReport parameter to see detailed breakdown of all applications in segment groups" "DarkGray"
    }

} catch {
    Write-ColorOutput "ERROR: Failed to process JSON files" "Red"
    Write-ColorOutput "Error details: $($_.Exception.Message)" "Red"
    exit 1
}

Write-ColorOutput "Script completed successfully." "Green"
