function Import-EIAV2Configuration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PoliciesCsvPath,
        [string]$SecurityProfilesCsvPath,
        [string]$PolicyName
    )

    function Import-V2Rows {
        param([string]$Path, [string[]]$RequiredColumns)
        $rows = @(Import-Csv -LiteralPath $Path -ErrorAction Stop)
        if ($rows.Count -eq 0) { return @() }
        $missing = @($RequiredColumns | Where-Object { $_ -notin $rows[0].PSObject.Properties.Name })
        if ($missing.Count -gt 0) { throw "OMv2 CSV '$Path' is missing columns: $($missing -join ', ')." }
        foreach ($row in $rows) {
            if ($row.SchemaVersion -cne 'EIA-OMv2/1.0') { throw "Unsupported OMv2 schema '$($row.SchemaVersion)' in '$Path'." }
            if ($row.Provision -notin @('Yes', 'No') -or $row.ReviewNeeded -notin @('Yes', 'No')) {
                throw "Invalid Provision or ReviewNeeded in '$Path'; expected Yes/No."
            }
            $row | Add-Member -NotePropertyName ProvisioningResult -NotePropertyValue 'Not attempted' -Force
        }
        return $rows
    }

    $policyRows = @(Import-V2Rows $PoliciesCsvPath @(
        'SchemaVersion', 'PolicyName', 'PolicyDefaultAction', 'RuleName', 'RulePriority',
        'RuleStatus', 'RuleAction', 'RuleType', 'RuleDestinations', 'ReviewNeeded', 'Provision'
    ))
    $profileRows = @()
    if ($SecurityProfilesCsvPath) {
        $profileRows = @(Import-V2Rows $SecurityProfilesCsvPath @(
            'SchemaVersion', 'SecurityProfileName', 'Priority', 'ProfileState', 'LinkState',
            'WebFilteringPolicyName', 'PolicyDefaultAction', 'ReviewNeeded', 'Provision'
        ))
    }
    $policies = @{}
    $referencedNames = @($profileRows | Where-Object Provision -EQ Yes | ForEach-Object { $_.WebFilteringPolicyName })
    foreach ($group in ($policyRows | Group-Object PolicyName)) {
        $name = $group.Name
        $selected = (@($group.Group | Where-Object Provision -EQ Yes).Count -gt 0 -and (-not $PolicyName -or $name -eq $PolicyName)) -or $name -in $referencedNames
        if (-not $selected) { continue }
        if ([string]::IsNullOrWhiteSpace($name) -or $name -ne $name.Trim()) { throw 'PolicyName must be non-empty without surrounding whitespace.' }
        if (@($group.Group | Where-Object { $_.UnsupportedDetails }).Count -gt 0) {
            throw "Policy '$name' contains unsupported configuration. Resolve UnsupportedDetails before provisioning."
        }
        $body = ConvertTo-EIAV2Body $group.Group[0] Policy
        $rules = @()
        $names = @{}
        $priorities = @{}
        foreach ($row in $group.Group) {
            Assert-EIAV2Equivalent -Expected $body -Actual (ConvertTo-EIAV2Body $row Policy) -Kind Policy -Name $name
            # Unreviewed unsupported rows remain available for review, but cannot be selected.
            if ($row.ReviewNeeded -eq 'Yes' -and $row.Provision -eq 'No') { continue }
            if ($row.ReviewNeeded -ne 'No') { throw "Policy '$name' still requires review." }
            $ruleBody = ConvertTo-EIAV2Body $row Rule
            if ($ruleBody) {
                if ($names.ContainsKey($ruleBody.name) -or $priorities.ContainsKey($ruleBody.priority)) {
                    throw "Duplicate rule name or priority in policy '$name'."
                }
                $names[$ruleBody.name] = $true
                $priorities[$ruleBody.priority] = $true
                $rules += [pscustomobject]@{ Row = $row; Body = $ruleBody; Existing = $null }
            }
        }
        if (@($group.Group | Where-Object RuleType -EQ None).Count -gt 0 -and $group.Count -ne 1) {
            throw "Default-only policy '$name' must have exactly one row."
        }
        $policies[$name] = [pscustomobject]@{
            Name = $name; Body = $body; Rows = @($group.Group); Rules = $rules
            Selected = $true
            Existing = $null
        }
    }
    $profiles = @()
    $names = @{}
    $priorities = @{}
    foreach ($row in ($profileRows | Where-Object Provision -EQ Yes)) {
        $name = $row.SecurityProfileName
        if ([string]::IsNullOrWhiteSpace($name) -or $name -ne $name.Trim()) { throw 'SecurityProfileName must be non-empty without surrounding whitespace.' }
        if ($row.ReviewNeeded -ne 'No') { throw "Profile '$name' still requires review." }
        if ($row.UnsupportedDetails) { throw "Profile '$name' contains unsupported configuration: $($row.UnsupportedDetails)" }
        $body = ConvertTo-EIAV2Body $row Profile
        if ($names.ContainsKey($name) -or $priorities.ContainsKey($body.priority)) { throw 'Duplicate profile name or priority in selected CSV rows.' }
        $names[$name] = $true
        $priorities[$body.priority] = $true
        if (-not $policies.ContainsKey($row.WebFilteringPolicyName)) { throw "Profile '$name' references a policy missing from the OMv2 CSV." }
        $policy = $policies[$row.WebFilteringPolicyName]
        if ($row.PolicyDefaultAction -ne $policy.Rows[0].PolicyDefaultAction) { throw "Profile '$name' has a conflicting policy default." }
        $policy.Selected = $true
        $profiles += [pscustomobject]@{ Row = $row; Body = $body; Policy = $policy; Existing = $null; Link = $null; ConditionalAccess = @() }
    }
    foreach ($policy in ($policies.Values | Where-Object Selected)) {
        if (@($policy.Rows | Where-Object ReviewNeeded -NE No).Count -gt 0) {
            throw "Policy '$($policy.Name)' has unreviewed rows. Review the complete policy before provisioning or linking it."
        }
        if (@($policy.Rows | Where-Object { $_.UnsupportedDetails }).Count -gt 0) {
            throw "Policy '$($policy.Name)' contains unsupported configuration. Resolve UnsupportedDetails before provisioning."
        }
        if (-not $policy.Body.name.EndsWith('[Migrate2GSA]', [StringComparison]::OrdinalIgnoreCase)) {
            $policy.Body.name += '[Migrate2GSA]'
        }
    }
    foreach ($profile in $profiles) {
        if (-not $profile.Body.name.EndsWith('[Migrate2GSA]', [StringComparison]::OrdinalIgnoreCase)) {
            $profile.Body.name += '[Migrate2GSA]'
        }
    }
    $targetNames = @{}
    foreach ($policy in ($policies.Values | Where-Object Selected)) {
        if ($targetNames.ContainsKey($policy.Body.name)) { throw "Duplicate normalized policy name '$($policy.Body.name)'." }
        $targetNames[$policy.Body.name] = $true
    }
    $targetNames = @{}
    foreach ($profile in $profiles) {
        if ($targetNames.ContainsKey($profile.Body.name)) { throw "Duplicate normalized profile name '$($profile.Body.name)'." }
        $targetNames[$profile.Body.name] = $true
    }
    if ($PolicyName -and $PolicyName -notin @($policyRows.PolicyName)) { throw "Policy '$PolicyName' was not found in the CSV." }
    [pscustomobject]@{
        Policies = @($policies.Values | Where-Object Selected | Sort-Object Name)
        Profiles = $profiles
        PolicyRows = $policyRows
        ProfileRows = $profileRows
    }
}
