function Get-EIAV2ConditionalAccessBody {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Row)

    $bodies = @()
    if ($Row.ConditionalAccessPoliciesJson) {
        $definitions = @($Row.ConditionalAccessPoliciesJson | ConvertFrom-Json -AsHashtable -ErrorAction Stop)
        foreach ($definition in $definitions) {
            $body = Get-EIAV2WritableBody -Object $definition -Kind ConditionalAccess
            if ([string]::IsNullOrWhiteSpace($body.displayName) -or -not $body.conditions -or
                $body.state -notin @('disabled', 'enabled', 'enabledForReportingButNotEnforced')) {
                throw "Invalid ConditionalAccessPoliciesJson for '$($Row.SecurityProfileName)'."
            }
            if (-not $body.sessionControls.globalSecureAccessFilteringProfile) {
                throw 'Conditional Access definitions must reference a Global Secure Access filtering profile.'
            }
            $bodies += $body
        }
    }
    elseif ($Row.CADisplayName -or $Row.EntraUsers -or $Row.EntraGroups) {
        if ([string]::IsNullOrWhiteSpace($Row.CADisplayName)) { throw 'CADisplayName is required when assigning users/groups.' }
        $assignments = @{ includeUsers = @(); includeGroups = @() }
        foreach ($mapping in @(
            @{ Column = 'EntraUsers'; Collection = 'users'; Property = 'userPrincipalName'; Target = 'includeUsers' },
            @{ Column = 'EntraGroups'; Collection = 'groups'; Property = 'displayName'; Target = 'includeGroups' }
        )) {
            foreach ($name in ($Row.($mapping.Column) -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                if ($name -match '_Replace_Me') { throw "Unresolved Conditional Access assignment '$name'." }
                $filter = [uri]::EscapeDataString("$($mapping.Property) eq '$($name.Replace("'", "''"))'")
                $matches = @(Invoke-InternalGraphRequest -Method GET -Uri "/beta/$($mapping.Collection)?`$filter=$filter&`$select=id")
                if ($matches.Count -ne 1 -or -not $matches[0].id) { throw "Assignment '$name' must resolve to exactly one $($mapping.Collection) object." }
                $assignments[$mapping.Target] += $matches[0].id
            }
        }
        if ($assignments.includeUsers.Count + $assignments.includeGroups.Count -eq 0) {
            throw "No CA assignments for '$($Row.CADisplayName)'. Supply assignments or use -SkipCAPoliciesProvisioning."
        }
        $bodies += @{
            displayName = $Row.CADisplayName
            state = 'disabled'
            conditions = @{
                clientAppTypes = @('all')
                users = $assignments
                applications = @{ includeApplications = @('5dc48733-b5df-475c-a49b-fa307ef00853') }
            }
            sessionControls = @{ globalSecureAccessFilteringProfile = @{ profileId = ''; isEnabled = $true } }
        }
    }
    foreach ($body in $bodies) {
        if (-not $body.displayName.EndsWith('[Migrate2GSA]', [StringComparison]::OrdinalIgnoreCase)) {
            $body.displayName += '[Migrate2GSA]'
        }
        $body.sessionControls.globalSecureAccessFilteringProfile.profileId = ''
        $body
    }
}
