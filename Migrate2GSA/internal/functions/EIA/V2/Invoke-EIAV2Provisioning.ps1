function Invoke-EIAV2Provisioning {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)][string]$PoliciesCsvPath,
        [string]$SecurityProfilesCsvPath,
        [string]$PolicyName,
        [switch]$SkipCAPoliciesProvisioning,
        [Parameter(Mandatory)][string]$LogPath
    )

    $configuration = Import-EIAV2Configuration -PoliciesCsvPath $PoliciesCsvPath `
        -SecurityProfilesCsvPath $SecurityProfilesCsvPath -PolicyName $PolicyName
    if ($configuration.Policies.Count -eq 0) {
        Write-LogMessage 'No reviewed OMv2 rows selected for provisioning.' -Level INFO -LogPath $LogPath
        return
    }
    $resultFolder = Join-Path (Split-Path ([IO.Path]::GetFullPath($LogPath)) -Parent) "EIA-OMv2-Results_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff')"
    $baseUri = '/beta/networkAccess'
    $prefix = '#microsoft.graph.networkaccess.'
    $completed = $false
    $selectedRows = @($configuration.Policies | ForEach-Object { $_.Rows }) +
        @($configuration.Profiles | ForEach-Object { $_.Row })

    function Find-UniqueObject {
        param([object[]]$Objects, [string]$Name, [string]$Property = 'name')
        $matches = @($Objects | Where-Object { $_.$Property -eq $Name })
        if ($matches.Count -gt 1) { throw "OMv2 conflict: duplicate tenant objects named '$Name'." }
        if ($matches.Count -eq 1) {
            if (-not $matches[0].id) { throw "Tenant object '$Name' has no ID." }
            return $matches[0]
        }
    }

    function New-VerifiedObject {
        param([string]$Uri, [hashtable]$Body, [string]$Kind)
        $created = Invoke-InternalGraphRequest -Method POST -Uri $Uri -Body ($Body | ConvertTo-Json -Depth 50)
        if (-not $created.id) { throw "Creation at '$Uri' returned no ID. Re-run to discover whether the object was created." }
        if ($Kind -eq 'Link') {
            $links = @(Invoke-InternalGraphRequest -Method GET -Uri "$Uri`?`$expand=policy")
            $matchingLinks = @($links | Where-Object id -EQ $created.id)
            if ($matchingLinks.Count -ne 1) { throw "Unable to verify the new policy link '$($created.id)'." }
            $actual = $matchingLinks[0]
        }
        else {
            $actual = Invoke-InternalGraphRequest -Method GET -Uri "$Uri/$([uri]::EscapeDataString($created.id))"
        }
        if (-not $actual.id) { throw "Unable to read back the created $Kind at '$Uri'." }
        Assert-EIAV2Equivalent -Expected $Body -Actual $actual -Kind $Kind -Name $created.id
        return $actual
    }

    function Get-LinkBody {
        param([object]$Profile)
        @{
            '@odata.type' = "${prefix}webFilteringPolicyLink"
            state = $Profile.Row.LinkState.ToLowerInvariant()
            policy = @{ id = $Profile.Policy.Existing.id; '@odata.type' = "${prefix}webFilteringPolicy" }
        }
    }

    try {
        Test-RequiredModules -RequiredModules @('Microsoft.Graph.Authentication') | Out-Null
        $scopes = @('NetworkAccess.ReadWrite.All')
        if ($configuration.Profiles.Count -gt 0 -and -not $SkipCAPoliciesProvisioning) {
            $scopes += @('Policy.ReadWrite.ConditionalAccess', 'User.Read.All', 'Group.Read.All')
        }
        Test-GraphConnection -RequiredScopes $scopes | Out-Null
        Write-LogMessage 'Preflighting OMv2 configuration. API/feature errors are fatal; no fallback to OMv1.' -LogPath $LogPath
        $existingPolicies = @(Invoke-InternalGraphRequest -Method GET -Uri "$baseUri/webFilteringPolicies")
        foreach ($policy in $configuration.Policies) {
            $policy.Existing = Find-UniqueObject $existingPolicies $policy.Body.name
            $existingRules = @()
            if ($policy.Existing) {
                Assert-EIAV2Equivalent -Expected $policy.Body -Actual $policy.Existing -Kind Policy -Name $policy.Body.name
                $existingRules = @(Invoke-InternalGraphRequest -Method GET -Uri "$baseUri/webFilteringPolicies/$($policy.Existing.id)/policyRules")
            }
            elseif (@($policy.Rows | Where-Object Provision -EQ Yes).Count -eq 0) {
                throw "Policy '$($policy.Name)' is missing but has no rows selected for creation."
            }
            $expectedNames = @($policy.Rules | ForEach-Object { $_.Body.name })
            $extras = @($existingRules | Where-Object { $_.name -notin $expectedNames })
            if ($extras.Count -gt 0) {
                throw "OMv2 conflict: policy '$($policy.Name)' contains extra rules: $($extras.name -join ', '). They will not be deleted."
            }
            foreach ($rule in $policy.Rules) {
                $rule.Existing = Find-UniqueObject $existingRules $rule.Body.name
                if ($rule.Existing) {
                    Assert-EIAV2Equivalent -Expected $rule.Body -Actual $rule.Existing -Kind Rule -Name "$($policy.Name)/$($rule.Body.name)"
                }
                elseif ($rule.Row.Provision -ne 'Yes') {
                    throw "Rule '$($policy.Name)/$($rule.Body.name)' is missing but Provision is No."
                }
            }
        }

        $existingProfiles = @()
        $existingCA = @()
        if ($configuration.Profiles.Count -gt 0) {
            $existingProfiles = @(Invoke-InternalGraphRequest -Method GET -Uri "$baseUri/filteringProfiles")
            if (-not $SkipCAPoliciesProvisioning) {
                $existingCA = @(Invoke-InternalGraphRequest -Method GET -Uri '/beta/identity/conditionalAccess/policies')
            }
        }
        $caNames = @{}
        foreach ($profile in $configuration.Profiles) {
            $profile.Existing = Find-UniqueObject $existingProfiles $profile.Body.name
            $priorityConflict = @($existingProfiles | Where-Object { $_.priority -eq $profile.Body.priority -and $_.name -ne $profile.Body.name })
            if ($priorityConflict.Count -gt 0) { throw "OMv2 conflict: profile priority $($profile.Body.priority) is already in use." }
            if ($profile.Existing) {
                Assert-EIAV2Equivalent -Expected $profile.Body -Actual $profile.Existing -Kind Profile -Name $profile.Body.name
                $uri = "$baseUri/filteringProfiles/$($profile.Existing.id)"
                $links = @(Invoke-InternalGraphRequest -Method GET -Uri "$uri/policies?`$expand=policy")
                if ($profile.Policy.Existing -and @($links | Where-Object {
                    $_.policy.id -eq $profile.Policy.Existing.id -and $_.'@odata.type' -ne "${prefix}webFilteringPolicyLink"
                }).Count -gt 0) {
                    throw "OMv2 conflict: unexpected link type for the target web policy in '$($profile.Body.name)'."
                }
                $webLinks = @($links | Where-Object { $_.'@odata.type' -eq "${prefix}webFilteringPolicyLink" })
                if ($webLinks.Count -gt 1) { throw "OMv2 conflict: profile '$($profile.Body.name)' has multiple OMv2 links." }
                if ($webLinks.Count -eq 1) {
                    if (-not $profile.Policy.Existing -or $webLinks[0].policy.id -ne $profile.Policy.Existing.id) {
                        throw "OMv2 conflict: profile '$($profile.Body.name)' links to a different web-filtering policy."
                    }
                    Assert-EIAV2Equivalent -Expected (Get-LinkBody $profile) -Actual $webLinks[0] -Kind Link -Name $profile.Body.name
                    $profile.Link = $webLinks[0]
                }
                else {
                    $expanded = Invoke-InternalGraphRequest -Method GET -Uri "$uri`?`$expand=conditionalAccessPolicies"
                    if (-not $expanded.id) { throw "Unable to inspect CA links for '$($profile.Body.name)'." }
                    if (@($expanded.conditionalAccessPolicies | Where-Object { $_ }).Count -gt 0) {
                        throw "OMv2 conflict: cannot add a policy link to CA-linked profile '$($profile.Body.name)'."
                    }
                }
            }
            if (-not $SkipCAPoliciesProvisioning) {
                foreach ($body in @(Get-EIAV2ConditionalAccessBody -Row $profile.Row)) {
                    if ($caNames.ContainsKey($body.displayName)) { throw "Duplicate CA policy name '$($body.displayName)' in selected profiles." }
                    $caNames[$body.displayName] = $true
                    $existing = Find-UniqueObject $existingCA $body.displayName 'displayName'
                    if ($existing) {
                        if (-not $profile.Existing) { throw "CA policy '$($body.displayName)' exists but the target profile does not." }
                        $body.sessionControls.globalSecureAccessFilteringProfile.profileId = $profile.Existing.id
                        Assert-EIAV2Equivalent -Expected $body -Actual $existing -Kind ConditionalAccess -Name $body.displayName
                    }
                    $profile.ConditionalAccess += [pscustomobject]@{ Body = $body; Existing = $existing }
                }
            }
        }
        Write-LogMessage "OMv2 preflight passed: $($configuration.Policies.Count) policies, $($configuration.Profiles.Count) profiles. Existing OMv1 and non-web links remain untouched." -LogPath $LogPath
        foreach ($policy in $configuration.Policies) {
            $operation = if ($policy.Existing) { 'Reuse' } else { 'Create' }
            Write-LogMessage "$operation policy '$($policy.Body.name)'." -LogPath $LogPath
            foreach ($rule in $policy.Rules) {
                $operation = if ($rule.Existing) { 'Reuse' } else { 'Create' }
                Write-LogMessage "$operation rule '$($rule.Body.name)' (priority $($rule.Body.priority), $($rule.Body.settings.status))." -LogPath $LogPath
            }
        }
        foreach ($profile in $configuration.Profiles) {
            $operation = if ($profile.Existing) { 'Reuse' } else { 'Create' }
            Write-LogMessage "$operation profile '$($profile.Body.name)' ($($profile.Body.state)); web link $($profile.Row.LinkState)." -LogPath $LogPath
            foreach ($ca in $profile.ConditionalAccess) {
                $operation = if ($ca.Existing) { 'Reuse' } else { 'Create' }
                Write-LogMessage "$operation CA policy '$($ca.Body.displayName)' ($($ca.Body.state))." -LogPath $LogPath
            }
        }
        if (-not $PSCmdlet.ShouldProcess('Reviewed OMv2 configuration in the connected Graph tenant', 'Create missing objects; reuse equivalent objects; never update/delete')) {
            return
        }

        foreach ($policy in $configuration.Policies) {
            $uri = "$baseUri/webFilteringPolicies"
            if (-not $policy.Existing) { $policy.Existing = New-VerifiedObject $uri $policy.Body Policy }
            foreach ($rule in $policy.Rules) {
                if (-not $rule.Existing) {
                    $rule.Existing = New-VerifiedObject "$uri/$($policy.Existing.id)/policyRules" $rule.Body Rule
                    $rule.Row.ProvisioningResult = 'Provisioned: Rule created and verified'
                }
                else { $rule.Row.ProvisioningResult = 'Reused: Equivalent rule' }
                $rule.Row.Provision = 'No'
            }
            foreach ($row in ($policy.Rows | Where-Object RuleType -EQ None)) {
                $row.ProvisioningResult = 'Reused: Default-only policy verified'
                $row.Provision = 'No'
            }
        }
        foreach ($profile in $configuration.Profiles) {
            if (-not $profile.Existing) {
                $profile.Existing = New-VerifiedObject "$baseUri/filteringProfiles" $profile.Body Profile
            }
            if (-not $profile.Link) {
                $profile.Link = New-VerifiedObject "$baseUri/filteringProfiles/$($profile.Existing.id)/policies" (Get-LinkBody $profile) Link
            }
            foreach ($ca in $profile.ConditionalAccess) {
                if (-not $ca.Existing) {
                    $ca.Body.sessionControls.globalSecureAccessFilteringProfile.profileId = $profile.Existing.id
                    $ca.Existing = New-VerifiedObject '/beta/identity/conditionalAccess/policies' $ca.Body ConditionalAccess
                }
            }
            $profile.Row.ProvisioningResult = 'Provisioned: Profile, web link and requested CA policies verified'
            $profile.Row.Provision = 'No'
        }
        $completed = $true
    }
    catch {
        Write-LogMessage "OMv2 provisioning stopped: $($_.Exception.Message)" -Level ERROR -LogPath $LogPath
        foreach ($row in ($selectedRows | Where-Object { $_.Provision -eq 'Yes' })) {
            $row.ProvisioningResult = "Failed: $($_.Exception.Message)"
        }
        throw
    }
    finally {
        # WhatIf must not change retry selection or emit success-shaped result files.
        if (-not $WhatIfPreference) {
            New-Item -Path $resultFolder -ItemType Directory -ErrorAction Stop | Out-Null
            $configuration.PolicyRows | Export-Csv -LiteralPath (Join-Path $resultFolder 'EIA_OMv2_Policies.csv') -NoTypeInformation -Encoding utf8BOM -ErrorAction Stop
            if ($configuration.ProfileRows.Count -gt 0) {
                $configuration.ProfileRows | Export-Csv -LiteralPath (Join-Path $resultFolder 'EIA_OMv2_SecurityProfiles.csv') -NoTypeInformation -Encoding utf8BOM -ErrorAction Stop
            }
            Write-LogMessage "OMv2 retry CSVs: $resultFolder. Completed: $completed." -LogPath $LogPath
        }
    }
    [pscustomobject]@{
        Completed = $completed
        PoliciesCsvPath = Join-Path $resultFolder 'EIA_OMv2_Policies.csv'
        SecurityProfilesCsvPath = $(if ($configuration.ProfileRows.Count -gt 0) { Join-Path $resultFolder 'EIA_OMv2_SecurityProfiles.csv' })
        LogPath = $LogPath
    }
}
