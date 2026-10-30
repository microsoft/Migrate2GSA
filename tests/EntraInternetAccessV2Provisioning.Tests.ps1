BeforeAll {
    $previousTelemetryOptOut = $env:MIGRATE2GSA_TELEMETRY_OPTOUT
    $env:MIGRATE2GSA_TELEMETRY_OPTOUT = '1'
    Import-Module "$PSScriptRoot/../Migrate2GSA/Migrate2GSA.psd1" -Force
}

AfterAll {
    $env:MIGRATE2GSA_TELEMETRY_OPTOUT = $previousTelemetryOptOut
}

Describe 'OMv2 provisioning and export' {
    BeforeEach {
        $baseUri = '/beta/networkAccess'
        $prefix = '#microsoft.graph.networkaccess.'
        $store = @{
            "$baseUri/webFilteringPolicies" = [System.Collections.Generic.List[object]]::new()
            "$baseUri/filteringProfiles" = [System.Collections.Generic.List[object]]::new()
            '/beta/identity/conditionalAccess/policies' = [System.Collections.Generic.List[object]]::new()
        }
        $calls = [System.Collections.Generic.List[object]]::new()
        $failure = @{ Pattern = ''; Method = 'POST' }
        Mock -ModuleName Migrate2GSA Test-RequiredModules {}
        Mock -ModuleName Migrate2GSA Test-GraphConnection { $true }
        Mock -ModuleName Migrate2GSA Write-LogMessage {}
        Mock -ModuleName Migrate2GSA Invoke-InternalGraphRequest {
            param($Method, $Uri, $Body)
            $calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Body = $Body })
            if ($failure.Pattern -and $Method -eq $failure.Method -and $Uri -like $failure.Pattern) { throw 'Simulated Graph failure' }
            $path = $Uri.Split('?')[0]
            if ($Method -eq 'POST') {
                if (-not $store.ContainsKey($path)) { throw "Unexpected POST $Uri" }
                $item = $Body | ConvertFrom-Json -AsHashtable
                if ($path -eq '/beta/identity/conditionalAccess/policies' -and -not $item.conditions.Contains('clientAppTypes')) {
                    $item.conditions.clientAppTypes = @('all')
                }
                $item.id = [guid]::NewGuid().ToString()
                $store[$path].Add($item)
                if ($path -eq "$baseUri/webFilteringPolicies") { $store["$path/$($item.id)/policyRules"] = [System.Collections.Generic.List[object]]::new() }
                if ($path -eq "$baseUri/filteringProfiles") { $store["$path/$($item.id)/policies"] = [System.Collections.Generic.List[object]]::new() }
                return ($item | ConvertTo-Json -Depth 50 | ConvertFrom-Json)
            }
            if ($Method -ne 'GET') { throw "Unexpected mutation $Method $Uri" }
            if ($path -in @('/beta/users', '/beta/groups')) { return [pscustomobject]@{ id = 'synthetic-assignment' } }
            if ($store.ContainsKey($path)) {
                foreach ($item in $store[$path]) { $item | ConvertTo-Json -Depth 50 | ConvertFrom-Json }
                return
            }
            $lastSlash = $path.LastIndexOf('/')
            $collection = $path.Substring(0, $lastSlash)
            $id = $path.Substring($lastSlash + 1)
            if ($store.ContainsKey($collection)) {
                $found = @($store[$collection] | Where-Object id -EQ $id)
                if ($found.Count -eq 1) { return ($found[0] | ConvertTo-Json -Depth 50 | ConvertFrom-Json) }
            }
            throw "Unexpected GET $Uri"
        }
        $policies = @'
SchemaVersion,PolicyName,Description,PolicyDefaultAction,RuleName,RuleDescription,RulePriority,RuleStatus,RuleAction,RuleType,RuleDestinations,ReviewNeeded,Provision
EIA-OMv2/1.0,Finance web,,ContinueEvaluation,Allow reports,,100,Enabled,Allow,URL,https://example.com/Reports;https://example.com/Other,No,Yes
EIA-OMv2/1.0,Finance web,,ContinueEvaluation,Block categories,,200,Disabled,Block,webCategory,Gambling;Games,No,Yes
'@ | ConvertFrom-Csv
        $profiles = @'
SchemaVersion,SecurityProfileName,Description,Priority,ProfileState,LinkState,WebFilteringPolicyName,PolicyDefaultAction,CADisplayName,EntraUsers,EntraGroups,ConditionalAccessPoliciesJson,ReviewNeeded,Provision
EIA-OMv2/1.0,Finance,,1000,Disabled,Enabled,Finance web,ContinueEvaluation,,,,,No,Yes
'@ | ConvertFrom-Csv
        $casePath = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -Path $casePath -ItemType Directory | Out-Null
        $policiesPath = Join-Path $casePath 'policies.csv'
        $profilesPath = Join-Path $casePath 'profiles.csv'
        $policies | Export-Csv $policiesPath -NoTypeInformation
        $profiles | Export-Csv $profilesPath -NoTypeInformation
        $parameters = @{
            PoliciesCsvPath = $policiesPath
            SecurityProfilesCsvPath = $profilesPath
            PolicyModel = 'OMv2'
            SkipCAPoliciesProvisioning = $true
            LogPath = Join-Path $casePath 'provision.log'
            Force = $true
        }
    }

    It 'creates typed OMv2 policies, ordered rules and links, then reuses equivalent objects' {
        $result = Start-EntraInternetAccessProvisioning @parameters
        $result.Completed | Should -BeTrue
        $policy = $store["$baseUri/webFilteringPolicies"][0]
        $policy.name | Should -Be 'Finance web[Migrate2GSA]'
        $policy.settings.defaultAction.'@odata.type' | Should -Be "${prefix}webFilteringActionContinueEvaluation"
        $rules = $store["$baseUri/webFilteringPolicies/$($policy.id)/policyRules"]
        $rules[0].matchingConditions.destinations.targets[0].'@odata.type' | Should -Be "${prefix}webFilteringUrlDestination"
        $rules[0].action.'@odata.type' | Should -Be "${prefix}webFilteringActionAllow"
        $rules[1].settings.status | Should -Be 'disabled'
        $profile = $store["$baseUri/filteringProfiles"][0]
        $link = $store["$baseUri/filteringProfiles/$($profile.id)/policies"][0]
        $link.'@odata.type' | Should -Be "${prefix}webFilteringPolicyLink"
        $link.Contains('priority') | Should -BeFalse
        @($calls | Where-Object Method -EQ POST).Count | Should -Be 5
        $calls.Clear()
        $rules[0].matchingConditions.destinations.targets[0].values = @('https://example.com/Other', 'https://example.com/Reports')
        $rules[0].action.headerSettings = $null
        Start-EntraInternetAccessProvisioning @parameters | Out-Null
        @($calls | Where-Object Method -NE GET).Count | Should -Be 0
    }

    It 'stops before writes on changed <Field>' -ForEach @(
        @{ Field = 'RuleDestinations'; Value = 'https://example.com/reports' }
        @{ Field = 'RuleAction'; Value = 'Block' }
        @{ Field = 'RulePriority'; Value = '101' }
        @{ Field = 'RuleStatus'; Value = 'Disabled' }
        @{ Field = 'Description'; Value = 'changed policy description' }
    ) {
        Start-EntraInternetAccessProvisioning @parameters | Out-Null
        $calls.Clear()
        if ($Field -eq 'Description') { $policies | ForEach-Object { $_.Description = $Value } }
        else { $policies[0].$Field = $Value }
        $policies | Export-Csv $policiesPath -NoTypeInformation
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*OMv2 conflict*'
        @($calls | Where-Object Method -NE GET).Count | Should -Be 0
    }

    It 'stops on changed defaults, profile settings and link state' {
        Start-EntraInternetAccessProvisioning @parameters | Out-Null
        $calls.Clear()
        $policies | ForEach-Object { $_.PolicyDefaultAction = 'Block' }
        $profiles.PolicyDefaultAction = 'Block'
        $policies | Export-Csv $policiesPath -NoTypeInformation
        $profiles | Export-Csv $profilesPath -NoTypeInformation
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*settings*'
        $policies | ForEach-Object { $_.PolicyDefaultAction = 'ContinueEvaluation' }
        $profiles.PolicyDefaultAction = 'ContinueEvaluation'
        $policies | Export-Csv $policiesPath -NoTypeInformation
        $profiles.ProfileState = 'Enabled'
        $profiles | Export-Csv $profilesPath -NoTypeInformation
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*state*'
        $profiles.ProfileState = 'Disabled'
        $profiles.LinkState = 'Disabled'
        $profiles | Export-Csv $profilesPath -NoTypeInformation
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*state*'
        @($calls | Where-Object Method -NE GET).Count | Should -Be 0
    }

    It 'rejects extra rules and duplicate tenant names instead of choosing the first' {
        Start-EntraInternetAccessProvisioning @parameters | Out-Null
        $calls.Clear()
        $policy = $store["$baseUri/webFilteringPolicies"][0]
        $store["$baseUri/webFilteringPolicies/$($policy.id)/policyRules"].Add(@{ id = 'extra'; name = 'Unexpected rule' })
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*extra rules*'
        $store["$baseUri/webFilteringPolicies"].Add($policy)
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*duplicate tenant objects*'
        @($calls | Where-Object Method -NE GET).Count | Should -Be 0
    }

    It 'rejects priority and different-policy link conflicts before creating policies' {
        $store["$baseUri/filteringProfiles"].Add(@{ id = 'occupied'; name = 'Other profile'; priority = 1000; state = 'disabled' })
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*priority*already in use*'
        @($calls | Where-Object Method -NE GET).Count | Should -Be 0
        $store["$baseUri/filteringProfiles"].Clear()
        Start-EntraInternetAccessProvisioning @parameters | Out-Null
        $calls.Clear()
        $profile = $store["$baseUri/filteringProfiles"][0]
        $store["$baseUri/filteringProfiles/$($profile.id)/policies"][0].policy.id = 'different-policy'
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*different web-filtering policy*'
        @($calls | Where-Object Method -NE GET).Count | Should -Be 0
    }

    It 'allows an equivalent CA-linked profile but refuses adding its missing web link' {
        Start-EntraInternetAccessProvisioning @parameters | Out-Null
        $profile = $store["$baseUri/filteringProfiles"][0]
        $profile.conditionalAccessPolicies = @(@{ id = 'ca-reference' })
        $calls.Clear()
        Start-EntraInternetAccessProvisioning @parameters | Out-Null
        @($calls | Where-Object Method -NE GET).Count | Should -Be 0
        $store["$baseUri/filteringProfiles/$($profile.id)/policies"].Clear()
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*CA-linked profile*'
        @($calls | Where-Object Method -NE GET).Count | Should -Be 0
    }

    It 'preflights under WhatIf even with Force but never writes to Graph or creates retry files' {
        Start-EntraInternetAccessProvisioning @parameters -WhatIf | Out-Null
        @($calls | Where-Object Method -EQ GET).Count | Should -BeGreaterThan 0
        @($calls | Where-Object Method -NE GET).Count | Should -Be 0
        @(Get-ChildItem $casePath -Directory -Filter 'EIA-OMv2-Results*').Count | Should -Be 0
    }

    It 'stops on unavailable endpoints without falling back or claiming success' {
        $failure.Method = 'GET'
        $failure.Pattern = '*webFilteringPolicies'
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*Simulated Graph failure*'
        @($calls | Where-Object Method -NE GET).Count | Should -Be 0
        @($calls | Where-Object Uri -Match '/filteringPolicies').Count | Should -Be 0
    }

    It 'does not replace unsupported ContinueEvaluation with another default' {
        $failure.Pattern = '*webFilteringPolicies'
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*Simulated Graph failure*'
        $posts = @($calls | Where-Object Method -EQ POST)
        $posts.Count | Should -Be 1
        ($posts[0].Body | ConvertFrom-Json).settings.defaultAction.'@odata.type' | Should -Be "${prefix}webFilteringActionContinueEvaluation"
    }

    It 'writes retry CSVs after a partial failure and resumes without duplicating the policy' {
        $failure.Pattern = '*/policies'
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*Simulated Graph failure*'
        $folder = Get-ChildItem $casePath -Directory -Filter 'EIA-OMv2-Results*' | Select-Object -Last 1
        $retryPolicies = Join-Path $folder.FullName 'EIA_OMv2_Policies.csv'
        $retryProfiles = Join-Path $folder.FullName 'EIA_OMv2_SecurityProfiles.csv'
        @(Import-Csv $retryPolicies | Where-Object Provision -NE No).Count | Should -Be 0
        (Import-Csv $retryProfiles).Provision | Should -Be 'Yes'
        $failure.Pattern = ''
        $calls.Clear()
        $parameters.PoliciesCsvPath = $retryPolicies
        $parameters.SecurityProfilesCsvPath = $retryProfiles
        $result = Start-EntraInternetAccessProvisioning @parameters
        $result.Completed | Should -BeTrue
        @($calls | Where-Object Method -EQ POST).Count | Should -Be 1
        (Import-Csv $result.SecurityProfilesCsvPath).Provision | Should -Be 'No'
    }

    It 'rejects unreviewed, invalid schema and duplicate priorities without Graph calls' {
        $policies[0].ReviewNeeded = 'Yes'
        $policies | Export-Csv $policiesPath -NoTypeInformation
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*requires review*'
        $policies[0].ReviewNeeded = 'No'
        $policies[0].SchemaVersion = 'EIA-OMv2-Plan/0.1'
        $policies | Export-Csv $policiesPath -NoTypeInformation
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*Unsupported OMv2 schema*'
        $policies[0].SchemaVersion = 'EIA-OMv2/1.0'
        $policies[0].RulePriority = '200'
        $policies | Export-Csv $policiesPath -NoTypeInformation
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*Duplicate rule name or priority*'
        $calls.Count | Should -Be 0
    }

    It 'round trips exported policy defaults, rules, profiles and links without duplicate suffixes' {
        Start-EntraInternetAccessProvisioning @parameters | Out-Null
        $export = Export-EntraInternetAccessConfig -PolicyModel OMv2 -OutputPath $TestDrive
        $exportedPolicies = @(Import-Csv $export.PoliciesCsvPath)
        $exportedProfiles = @(Import-Csv $export.SecurityProfilesCsvPath)
        $exportedPolicies.Count | Should -Be 2
        @($exportedPolicies | Where-Object { $_.UnsupportedDetails }).Count | Should -Be 0
        $exportedProfiles[0].UnsupportedDetails | Should -BeNullOrEmpty
        $exportedPolicies | ForEach-Object { $_.ReviewNeeded = 'No'; $_.Provision = 'Yes' }
        $exportedProfiles | ForEach-Object { $_.ReviewNeeded = 'No'; $_.Provision = 'Yes' }
        $exportedPolicies | Export-Csv $policiesPath -NoTypeInformation
        $exportedProfiles | Export-Csv $profilesPath -NoTypeInformation
        $calls.Clear()
        Start-EntraInternetAccessProvisioning @parameters | Out-Null
        @($calls | Where-Object Method -NE GET).Count | Should -Be 0
    }

    It 'preserves unsupported matching conditions in export and refuses lossy provisioning' {
        Start-EntraInternetAccessProvisioning @parameters | Out-Null
        $policy = $store["$baseUri/webFilteringPolicies"][0]
        $rule = $store["$baseUri/webFilteringPolicies/$($policy.id)/policyRules"][0]
        $rule.matchingConditions.destinations.httpRequestMethod = 'post'
        $export = Export-EntraInternetAccessConfig -PolicyModel OMv2 -OutputPath $TestDrive
        $rows = @(Import-Csv $export.PoliciesCsvPath)
        $rows[0].UnsupportedDetails | Should -Match 'matchingConditions'
        $rows[0].SourceRuleJson | Should -Match 'httpRequestMethod'
        $rows | ForEach-Object { $_.ReviewNeeded = 'No'; $_.Provision = 'Yes' }
        $rows | Export-Csv $policiesPath -NoTypeInformation
        $parameters.Remove('SecurityProfilesCsvPath')
        $calls.Clear()
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*unsupported configuration*'
        $calls.Count | Should -Be 0
    }

    It 'creates and round trips a default-only policy' {
        $policies = @($policies[0])
        foreach ($field in @('RuleName', 'RuleDescription', 'RulePriority', 'RuleStatus', 'RuleAction', 'RuleDestinations')) { $policies[0].$field = '' }
        $policies[0].RuleType = 'None'
        $policies | Export-Csv $policiesPath -NoTypeInformation
        Start-EntraInternetAccessProvisioning @parameters | Out-Null
        $export = Export-EntraInternetAccessConfig -PolicyModel OMv2 -OutputPath $TestDrive
        $row = Import-Csv $export.PoliciesCsvPath
        $row.RuleType | Should -Be 'None'
        $row.UnsupportedDetails | Should -BeNullOrEmpty
        $row.PolicyDefaultAction | Should -Be 'ContinueEvaluation'
    }

    It 'creates disabled CA assignments with Graph defaults and detects subsequent condition conflicts' {
        $parameters.SkipCAPoliciesProvisioning = $false
        $profiles.CADisplayName = 'Finance CA'
        $profiles.EntraUsers = 'user@example.com'
        $profiles | Export-Csv $profilesPath -NoTypeInformation
        $result = Start-EntraInternetAccessProvisioning @parameters
        $result.Completed | Should -BeTrue
        $ca = $store['/beta/identity/conditionalAccess/policies'][0]
        $ca.state | Should -Be 'disabled'
        $ca.conditions.users.includeUsers | Should -Contain 'synthetic-assignment'
        $calls.Clear()
        Start-EntraInternetAccessProvisioning @parameters | Out-Null
        @($calls | Where-Object Method -NE GET).Count | Should -Be 0
        $ca.conditions.clientAppTypes = @('browser')
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*conditions*clientAppTypes*'
        @($calls | Where-Object Method -NE GET).Count | Should -Be 0
        $ca.conditions.clientAppTypes = @('all')
        $ca.conditions.users.includeUsers = @('portal-edited-assignment')
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*conditions*'
        @($calls | Where-Object Method -NE GET).Count | Should -Be 0
    }

    It 'round trips full CA conditions and detects a false Boolean changed in the portal' {
        $parameters.SkipCAPoliciesProvisioning = $false
        $profiles.CADisplayName = 'Finance CA'
        $profiles.EntraGroups = 'Finance'
        $profiles | Export-Csv $profilesPath -NoTypeInformation
        Start-EntraInternetAccessProvisioning @parameters | Out-Null
        $profile = $store["$baseUri/filteringProfiles"][0]
        $ca = $store['/beta/identity/conditionalAccess/policies'][0]
        $profile.conditionalAccessPolicies = @(@{ id = $ca.id; displayName = $ca.displayName })
        $ca.conditions.users.excludeUsers = @('excluded-user')
        $ca.sessionControls.signInFrequency = @{ isEnabled = $false; value = 0; type = 'hours' }
        $export = Export-EntraInternetAccessConfig -PolicyModel OMv2 -OutputPath $TestDrive -IncludeConditionalAccessPolicies
        $exportedPolicies = @(Import-Csv $export.PoliciesCsvPath)
        $exportedProfiles = @(Import-Csv $export.SecurityProfilesCsvPath)
        $exportedProfiles[0].ConditionalAccessPoliciesJson | Should -Match 'excluded-user'
        $exportedPolicies | ForEach-Object { $_.ReviewNeeded = 'No'; $_.Provision = 'Yes' }
        $exportedProfiles | ForEach-Object { $_.ReviewNeeded = 'No'; $_.Provision = 'Yes' }
        $exportedPolicies | Export-Csv $policiesPath -NoTypeInformation
        $exportedProfiles | Export-Csv $profilesPath -NoTypeInformation
        $calls.Clear()
        Start-EntraInternetAccessProvisioning @parameters | Out-Null
        @($calls | Where-Object Method -NE GET).Count | Should -Be 0
        $ca.sessionControls.signInFrequency.Remove('isEnabled')
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*sessionControls*'
        @($calls | Where-Object Method -NE GET).Count | Should -Be 0
    }

    It 'does not turn failed post-create verification into successful retry rows' {
        $failure.Pattern = '*/policyRules/*'
        $failure.Method = 'GET'
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*Simulated Graph failure*'
        $folder = Get-ChildItem $casePath -Directory -Filter 'EIA-OMv2-Results*'
        $retry = @(Import-Csv (Join-Path $folder.FullName 'EIA_OMv2_Policies.csv'))
        @($retry | Where-Object Provision -NE Yes).Count | Should -Be 0
        $failure.Pattern = ''
        $calls.Clear()
        Start-EntraInternetAccessProvisioning @parameters | Out-Null
        # First rule was created despite its failed readback. Only the second rule is missing.
        @($calls | Where-Object { $_.Method -eq 'POST' -and $_.Uri -like '*/policyRules' }).Count | Should -Be 1
    }

    It 'keeps unselected unsupported exports out of a selected policy run' {
        $extra = $policies[0].PSObject.Copy()
        $extra.PolicyName = 'Unsupported unselected policy'
        $extra.PolicyDefaultAction = 'Unsupported'
        $extra.ReviewNeeded = 'Yes'
        $extra.Provision = 'No'
        @($policies) + @($extra) | Export-Csv $policiesPath -NoTypeInformation
        Start-EntraInternetAccessProvisioning @parameters | Out-Null
        $store["$baseUri/webFilteringPolicies"].Count | Should -Be 1
    }

    It 'preflights all selected policies before making the first write' {
        $extra = $policies[0].PSObject.Copy()
        $extra.PolicyName = 'Earlier new policy'
        @($policies) + @($extra) | Export-Csv $policiesPath -NoTypeInformation
        $store["$baseUri/webFilteringPolicies"].Add(@{
            id = 'conflicting-policy'; name = 'Finance web[Migrate2GSA]'
            settings = @{ defaultAction = @{ '@odata.type' = "${prefix}webFilteringActionBlock" } }
        })
        { Start-EntraInternetAccessProvisioning @parameters } | Should -Throw '*OMv2 conflict*'
        @($calls | Where-Object Method -NE GET).Count | Should -Be 0
    }

    It 'provisions reviewed output from the conversion stage without changing vendor converters' {
        @'
PolicyName,PolicyType,PolicyAction,RuleName,RuleType,RuleDestinations,Provision
Block sites,WebContentFiltering,Block,Sites,URL,https://example.com/reports,Yes
'@ | Set-Content $policiesPath
        @'
SecurityProfileName,Priority,SecurityProfileLinks,Provision
Finance,1000,Block sites:100,Yes
'@ | Set-Content $profilesPath
        $plan = ConvertTo-EntraInternetAccessV2Plan -PoliciesCsvPath $policiesPath `
            -SecurityProfilesCsvPath $profilesPath -DefaultAction ContinueEvaluation -OutputPath $TestDrive
        $reviewedRules = @(Import-Csv $plan.PoliciesCsvPath)
        $reviewedProfiles = @(Import-Csv $plan.SecurityProfilesCsvPath)
        $reviewedRules | ForEach-Object { $_.ReviewNeeded = 'No'; $_.Provision = 'Yes' }
        $reviewedProfiles | ForEach-Object { $_.ReviewNeeded = 'No'; $_.Provision = 'Yes' }
        $reviewedRules | Export-Csv $policiesPath -NoTypeInformation
        $reviewedProfiles | Export-Csv $profilesPath -NoTypeInformation
        $result = Start-EntraInternetAccessProvisioning @parameters
        $result.Completed | Should -BeTrue
        $store["$baseUri/webFilteringPolicies"][0].name | Should -Be 'Finance-WebFilteringV2[Migrate2GSA]'
    }

    It 'leaves OMv1 provisioning and export as the default paths' {
        Mock -ModuleName Migrate2GSA Invoke-EIAV2Provisioning { throw 'Explicit V2 dispatch' }
        Mock -ModuleName Migrate2GSA Export-EIAV2Configuration { throw 'Explicit V2 export' }
        Mock -ModuleName Migrate2GSA Get-IntGSATenantStatus { throw 'V1 path reached' }
        Start-EntraInternetAccessProvisioning -PoliciesCsvPath $policiesPath -Force -LogPath $parameters.LogPath
        { Export-EntraInternetAccessConfig -OutputPath $TestDrive } | Should -Throw '*V1 path reached*'
        Should -Invoke Get-IntGSATenantStatus -ModuleName Migrate2GSA -Times 2 -Exactly
        Should -Invoke Invoke-EIAV2Provisioning -ModuleName Migrate2GSA -Times 0 -Exactly
        Should -Invoke Export-EIAV2Configuration -ModuleName Migrate2GSA -Times 0 -Exactly
    }
}
