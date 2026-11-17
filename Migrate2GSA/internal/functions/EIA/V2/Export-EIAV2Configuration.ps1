function Export-EIAV2Configuration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$LogPath,
        [switch]$IncludeConditionalAccessPolicies
    )

    $folder = Join-Path $OutputPath "EIA-OMv2-Export_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff')"
    New-Item -Path $folder -ItemType Directory -ErrorAction Stop | Out-Null
    if (-not $LogPath) { $LogPath = Join-Path $folder 'EIA_OMv2_Export.log' }
    $script:LogPath = $LogPath
    $baseUri = '/beta/networkAccess'
    $prefix = '#microsoft.graph.networkaccess.'
    $actions = @{
        "${prefix}webFilteringActionAllow" = 'Allow'
        "${prefix}webFilteringActionBlock" = 'Block'
        "${prefix}webFilteringActionContinueEvaluation" = 'ContinueEvaluation'
    }
    $types = @{
        "${prefix}webFilteringUrlDestination" = 'URL'
        "${prefix}webFilteringWebCategoryDestination" = 'webCategory'
    }
    $policyRows = [System.Collections.Generic.List[object]]::new()
    $profileRows = [System.Collections.Generic.List[object]]::new()
    try {
        Test-RequiredModules -RequiredModules @('Microsoft.Graph.Authentication') | Out-Null
        $scopes = @('NetworkAccess.Read.All')
        if ($IncludeConditionalAccessPolicies) { $scopes += 'Policy.Read.All' }
        Test-GraphConnection -RequiredScopes $scopes | Out-Null
        Write-LogMessage 'Exporting OMv2 web policies and linked profiles. API errors stop the export; no OMv1 fallback.' -LogPath $LogPath
        $policies = @(Invoke-InternalGraphRequest -Method GET -Uri "$baseUri/webFilteringPolicies")
        $policyLookup = @{}
        foreach ($policy in $policies) {
            if (-not $policy.id) { throw 'OMv2 policy response has no ID.' }
            $policyLookup[$policy.id] = $policy
            $rules = @(Invoke-InternalGraphRequest -Method GET -Uri "$baseUri/webFilteringPolicies/$($policy.id)/policyRules")
            # A default-only policy must survive an export/import round trip.
            if ($rules.Count -eq 0) { $rules = @($null) }
            foreach ($rule in $rules) {
                $targets = @($rule.matchingConditions.destinations.targets | Where-Object { $_ })
                $type = if (-not $rule) { 'None' } elseif ($targets.Count -eq 1) { $types[$targets[0].'@odata.type'] } else { $null }
                if ($rule -and (-not $type -or @($targets.values | Where-Object { $_ -match ';' }).Count -gt 0)) { $type = 'Unsupported' }
                $row = [pscustomobject][ordered]@{
                    SchemaVersion = 'EIA-OMv2/1.0'
                    PolicyName = $policy.name
                    Description = $policy.description
                    PolicyDefaultAction = $(if ($actions.ContainsKey([string]$policy.settings.defaultAction.'@odata.type')) { $actions[$policy.settings.defaultAction.'@odata.type'] } else { 'Unsupported' })
                    RuleName = $rule.name
                    RuleDescription = $rule.description
                    RulePriority = $rule.priority
                    RuleStatus = $rule.settings.status
                    RuleAction = $(if ($rule) { $actions[[string]$rule.action.'@odata.type'] } else { '' })
                    RuleType = $type
                    RuleDestinations = $(if ($rule) { $targets.values -join ';' } else { '' })
                    ReviewNeeded = 'Yes'
                    ReviewDetails = 'Review before provisioning. Export does not validate enforcement or migrate non-web policies.'
                    UnsupportedDetails = ''
                    SourcePolicyId = $policy.id
                    SourceRuleId = $rule.id
                    SourcePolicyJson = ConvertTo-Json -InputObject $policy -Depth 50 -Compress
                    SourceRuleJson = ConvertTo-Json -InputObject $rule -Depth 50 -Compress
                    Provision = 'No'
                }
                try {
                    Assert-EIAV2Equivalent -Expected (ConvertTo-EIAV2Body $row Policy) -Actual $policy -Kind Policy -Name $policy.name
                    if ($rule) {
                        Assert-EIAV2Equivalent -Expected (ConvertTo-EIAV2Body $row Rule) -Actual $rule -Kind Rule -Name $rule.name
                    }
                }
                catch {
                    $row.UnsupportedDetails = $_.Exception.Message
                    Write-LogMessage "Exported '$($policy.name)/$($rule.name)' for review only: $($row.UnsupportedDetails)" -Level WARN -LogPath $LogPath
                }
                $policyRows.Add($row)
            }
        }
        $profiles = @(Invoke-InternalGraphRequest -Method GET -Uri "$baseUri/filteringProfiles")
        foreach ($profile in $profiles) {
            if (-not $profile.id) { throw 'Security profile response has no ID.' }
            $links = @(Invoke-InternalGraphRequest -Method GET -Uri "$baseUri/filteringProfiles/$($profile.id)/policies?`$expand=policy")
            $webLinks = @($links | Where-Object { $_.'@odata.type' -eq "${prefix}webFilteringPolicyLink" })
            if ($webLinks.Count -eq 0) { continue }
            if ($webLinks.Count -gt 1) { throw "Profile '$($profile.name)' has multiple OMv2 links; cannot represent it as one policy." }
            $link = $webLinks[0]
            if (-not $policyLookup.ContainsKey([string]$link.policy.id)) { throw "Profile '$($profile.name)' has an unresolved OMv2 policy link." }
            $policy = $policyLookup[$link.policy.id]
            $expanded = Invoke-InternalGraphRequest -Method GET -Uri "$baseUri/filteringProfiles/$($profile.id)?`$expand=conditionalAccessPolicies"
            if (-not $expanded.id) { throw "Unable to read profile '$($profile.name)' assignments." }
            $caBodies = @(
                if ($IncludeConditionalAccessPolicies) {
                    foreach ($ca in $expanded.conditionalAccessPolicies) {
                        if (-not $ca.id) { throw "Profile '$($profile.name)' has a CA reference without an ID." }
                        $actual = Invoke-InternalGraphRequest -Method GET -Uri "/beta/identity/conditionalAccess/policies/$($ca.id)"
                        if (-not $actual.id) { throw "Unable to read Conditional Access policy '$($ca.id)'." }
                        Get-EIAV2WritableBody -Object $actual -Kind ConditionalAccess
                    }
                }
            )
            $row = [pscustomobject][ordered]@{
                SchemaVersion = 'EIA-OMv2/1.0'
                SecurityProfileName = $profile.name
                Description = $profile.description
                Priority = $profile.priority
                ProfileState = $profile.state
                LinkState = $link.state
                WebFilteringPolicyName = $policy.name
                PolicyDefaultAction = $actions[[string]$policy.settings.defaultAction.'@odata.type']
                CADisplayName = @($expanded.conditionalAccessPolicies.displayName) -join ';'
                EntraUsers = ''
                EntraGroups = ''
                ConditionalAccessPoliciesJson = $(if ($IncludeConditionalAccessPolicies) { ConvertTo-Json -InputObject @($caBodies) -Depth 50 -Compress } else { '' })
                SourceSecurityProfileLinks = @($links | ForEach-Object { "$($_.policy.name):$($_.policy.id)" }) -join ';'
                ReviewNeeded = 'Yes'
                ReviewDetails = 'Non-web and OMv1 links are references only and are not provisioned or removed. CA assignments require -IncludeConditionalAccessPolicies on export or manual mapping.'
                UnsupportedDetails = ''
                SourceProfileId = $profile.id
                SourceProfileJson = ConvertTo-Json -InputObject $expanded -Depth 50 -Compress
                SourceLinksJson = ConvertTo-Json -InputObject @($links) -Depth 50 -Compress
                Provision = 'No'
            }
            try {
                Assert-EIAV2Equivalent -Expected (ConvertTo-EIAV2Body $row Profile) -Actual $profile -Kind Profile -Name $profile.name
                Assert-EIAV2Equivalent -Expected @{ state = $link.state; policy = @{ id = $policy.id } } -Actual $link -Kind Link -Name $profile.name
            }
            catch {
                $row.UnsupportedDetails = $_.Exception.Message
                Write-LogMessage "Exported profile '$($profile.name)' for review only: $($row.UnsupportedDetails)" -Level WARN -LogPath $LogPath
            }
            $profileRows.Add($row)
        }
        $policiesPath = Join-Path $folder 'EIA_OMv2_Policies.csv'
        $profilesPath = Join-Path $folder 'EIA_OMv2_SecurityProfiles.csv'
        $policyRows | Export-Csv -LiteralPath $policiesPath -NoTypeInformation -Encoding utf8BOM -ErrorAction Stop
        $profileRows | Export-Csv -LiteralPath $profilesPath -NoTypeInformation -Encoding utf8BOM -ErrorAction Stop
        Write-LogMessage "Exported $($policyRows.Count) policy rows and $($profileRows.Count) profiles. All rows have Provision=No." -LogPath $LogPath
        [pscustomobject]@{
            SchemaVersion = 'EIA-OMv2/1.0'
            PoliciesCsvPath = $policiesPath
            SecurityProfilesCsvPath = $profilesPath
            LogPath = $LogPath
        }
    }
    catch {
        Write-LogMessage "OMv2 export failed. Do not use partial output in '$folder': $($_.Exception.Message)" -Level ERROR -LogPath $LogPath
        throw
    }
}
