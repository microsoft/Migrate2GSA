BeforeAll {
    $previousTelemetryOptOut = $env:MIGRATE2GSA_TELEMETRY_OPTOUT
    $env:MIGRATE2GSA_TELEMETRY_OPTOUT = '1'
    Import-Module "$PSScriptRoot/../Migrate2GSA/Migrate2GSA.psd1" -Force
}

AfterAll {
    $env:MIGRATE2GSA_TELEMETRY_OPTOUT = $previousTelemetryOptOut
}

Describe 'Offline OMv2 review plan' {
    BeforeEach {
        $policies = @'
PolicyName,PolicyType,PolicyAction,RuleName,RuleType,RuleDestinations,Provision,ReviewNeeded,ReviewDetails
Block categories,WebContentFiltering,Block,Categories,webCategory,Gambling;Games,Yes,No,
Allow sites,WebContentFiltering,Allow,Host,FQDN,*.example.com,Yes,No,
Allow sites,WebContentFiltering,Allow,Path,URL,https://example.com/reports?view=all,No,Yes,Check exception
TLS policy,TLSInspection,Inspect,Bypass,bypass,internal.example.com,Yes,No,
'@ | ConvertFrom-Csv
        $profiles = @'
SecurityProfileName,Priority,SecurityProfileLinks,CADisplayName,EntraUsers,EntraGroups,Provision
Finance,200,Block categories:200;Allow sites:100;TLS policy,Finance CA,finance@example.com,Finance,Yes
Research,100,Block categories:100,Research CA,,Research,No
'@ | ConvertFrom-Csv
        $policiesPath = Join-Path $TestDrive 'policies.csv'
        $profilesPath = Join-Path $TestDrive 'profiles.csv'
        $outputPath = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $policies | Export-Csv $policiesPath -NoTypeInformation
        $profiles | Export-Csv $profilesPath -NoTypeInformation
        $parameters = @{
            PoliciesCsvPath = $policiesPath
            SecurityProfilesCsvPath = $profilesPath
            DefaultAction = 'Block'
            OutputPath = $outputPath
        }
        Mock -ModuleName Migrate2GSA Test-GraphConnection { throw 'Offline plans must not connect to Graph.' }
    }

    It 'combines policies per profile in link-priority order and preserves source provenance' {
        $before = (Get-FileHash $policiesPath).Hash
        $result = ConvertTo-EntraInternetAccessV2Plan @parameters
        $rules = @(Import-Csv $result.PoliciesCsvPath)
        $targets = @(Import-Csv $result.SecurityProfilesCsvPath)
        $rules.Count | Should -Be 4
        $finance = @($rules | Where-Object SecurityProfileName -EQ Finance)
        @($finance.PolicyName | Select-Object -Unique).Count | Should -Be 1
        ($finance.RulePriority -join ',') | Should -Be '100,200,300'
        ($finance.RuleAction -join ',') | Should -Be 'Allow,Allow,Block'
        ($finance.SourceRow -join ',') | Should -Be '2,3,1'
        ($finance.SourcePolicyLinkPriority -join ',') | Should -Be '100,100,200'
        $finance[0].RuleType | Should -Be 'URL'
        $finance[0].RuleDestinations | Should -Be '*.example.com'
        $finance[0].SourceRuleType | Should -Be 'FQDN'
        $finance[0].ReviewDetails | Should -Match 'matching semantics differ'
        $finance[1].RuleDestinations | Should -Be 'https://example.com/reports?view=all'
        $finance[1].SourceProvision | Should -Be 'No'
        $finance[1].ReviewDetails | Should -Match 'Check exception'
        $finance[2].RuleType | Should -Be 'webCategory'
        $finance[2].RuleDestinations | Should -Be 'Gambling;Games'
        $targets[0].SecurityProfileName | Should -Be 'Research'
        $targets[0].SourceProvision | Should -Be 'No'
        $targets[1].EntraUsers | Should -Be 'finance@example.com'
        $targets[1].SourceSecurityProfileLinks | Should -Be $profiles[0].SecurityProfileLinks
        $targets[1].ReviewDetails | Should -Match 'Non-web policy not converted'
        @($rules | Where-Object { $_.RuleStatus -ne 'Disabled' -or $_.Provision -ne 'No' -or $_.ReviewNeeded -ne 'Yes' }).Count | Should -Be 0
        @($targets | Where-Object { $_.Provision -ne 'No' -or $_.ReviewNeeded -ne 'Yes' }).Count | Should -Be 0
        @($rules | Where-Object PolicyDefaultAction -NE Block).Count | Should -Be 0
        (Get-FileHash $policiesPath).Hash | Should -Be $before
        Test-Path $result.LogPath | Should -BeTrue
        Should -Invoke Test-GraphConnection -ModuleName Migrate2GSA -Times 0 -Exactly
    }

    It 'retains unsupported actions, IP rules and empty destinations as explicit review rows' {
        $policies[0].PolicyAction = 'Alert'
        $policies[0].RuleType = 'ipAddress'
        $policies[0].RuleDestinations = ''
        $policies | Export-Csv $policiesPath -NoTypeInformation
        $result = ConvertTo-EntraInternetAccessV2Plan @parameters
        $unsupported = @(Import-Csv $result.PoliciesCsvPath | Where-Object SourcePolicyName -EQ 'Block categories')
        $unsupported.Count | Should -Be 2
        $unsupported[0].RuleAction | Should -Be 'Unsupported'
        $unsupported[0].SourcePolicyAction | Should -Be 'Alert'
        $unsupported[0].RuleType | Should -Be 'Unsupported'
        $unsupported[0].SourceRuleType | Should -Be 'ipAddress'
        $unsupported[0].ReviewDetails | Should -Match 'Source destinations are empty'
        $unsupported[0].Provision | Should -Be 'No'
    }

    It 'supports singleton CSVs and requires an explicit proposed default rather than inferring it' {
        $policies[0] | Export-Csv $policiesPath -NoTypeInformation
        $profiles[1] | Export-Csv $profilesPath -NoTypeInformation
        $parameters.DefaultAction = 'Allow'
        $result = ConvertTo-EntraInternetAccessV2Plan @parameters
        $rules = @(Import-Csv $result.PoliciesCsvPath)
        $rules.Count | Should -Be 1
        $rules[0].PolicyDefaultAction | Should -Be 'Allow'
        $rules[0].RuleAction | Should -Be 'Block'
        $rules[0].ReviewDetails | Should -Match 'cross-profile evaluation'
        (Get-Command ConvertTo-EntraInternetAccessV2Plan).Parameters.DefaultAction.Attributes.Mandatory | Should -Contain $true
        $parameters.DefaultAction = 'ContinueEvaluation'
        $result = ConvertTo-EntraInternetAccessV2Plan @parameters
        (Import-Csv $result.PoliciesCsvPath).PolicyDefaultAction | Should -Be 'ContinueEvaluation'
    }

    It 'rejects ContinueEvaluation for a baseline profile' {
        $profiles[0].Priority = '65000'
        $profiles | Export-Csv $profilesPath -NoTypeInformation
        $parameters.DefaultAction = 'ContinueEvaluation'
        { ConvertTo-EntraInternetAccessV2Plan @parameters } | Should -Throw '*Baseline*cannot use ContinueEvaluation*'
    }

    It 'does not write files in WhatIf mode' {
        $result = ConvertTo-EntraInternetAccessV2Plan @parameters -WhatIf
        $result | Should -BeNullOrEmpty
        Test-Path $outputPath | Should -BeFalse
    }

    It 'retains profiles and source links when filters omit rules, with exclusion winning' {
        $result = ConvertTo-EntraInternetAccessV2Plan @parameters -IncludePolicyName '*' -ExcludePolicyName 'Block*'
        $rules = @(Import-Csv $result.PoliciesCsvPath)
        $targets = @(Import-Csv $result.SecurityProfilesCsvPath)
        $rules.Count | Should -Be 2
        $targets[0].WebFilteringPolicyName | Should -BeNullOrEmpty
        $targets[0].PolicyDefaultAction | Should -BeNullOrEmpty
        $targets[0].ReviewDetails | Should -Match 'plan is incomplete'
        $targets[0].SourceSecurityProfileLinks | Should -Be 'Block categories:100'
    }

    It 'fails rather than writing an empty plan when all web policies are filtered out' {
        { ConvertTo-EntraInternetAccessV2Plan @parameters -ExcludePolicyName '*' } | Should -Throw '*No linked*'
        Test-Path $outputPath | Should -BeFalse
    }

    It 'preserves an unresolved unprioritized non-web link without guessing its type' {
        $profiles[0].SecurityProfileLinks += ';External policy'
        $profiles | Export-Csv $profilesPath -NoTypeInformation
        $result = ConvertTo-EntraInternetAccessV2Plan @parameters
        $target = Import-Csv $result.SecurityProfilesCsvPath | Where-Object SecurityProfileName -EQ Finance
        $target.SourceSecurityProfileLinks | Should -Match 'External policy'
        $target.ReviewDetails | Should -Match 'Unresolved unprioritized link'
    }

    It 'rejects ambiguous or broken profile references: <Case>' -ForEach @(
        @{ Case = 'missing policy'; Links = 'Missing:100'; Error = '*missing policy*' }
        @{ Case = 'missing web priority'; Links = 'Allow sites'; Error = '*needs a priority*' }
        @{ Case = 'priority collision'; Links = 'Allow sites:100;Block categories:100'; Error = '*Duplicate web policy-link priority*' }
        @{ Case = 'duplicate policy'; Links = 'Allow sites:100;allow sites:200'; Error = '*Duplicate policy link*' }
        @{ Case = 'malformed link'; Links = 'Allow sites:wrong'; Error = '*Invalid policy link*' }
        @{ Case = 'overflow priority'; Links = 'Allow sites:99999999999'; Error = '*Invalid policy-link priority*' }
    ) {
        $profiles[0].SecurityProfileLinks = $Links
        $profiles | Export-Csv $profilesPath -NoTypeInformation
        { ConvertTo-EntraInternetAccessV2Plan @parameters } | Should -Throw $Error
        Test-Path $outputPath | Should -BeFalse
    }

    It 'rejects inconsistent policy metadata instead of choosing an arbitrary action' {
        $policies[2].PolicyAction = 'Block'
        $policies | Export-Csv $policiesPath -NoTypeInformation
        { ConvertTo-EntraInternetAccessV2Plan @parameters } | Should -Throw '*inconsistent PolicyType or PolicyAction*'
        Test-Path $outputPath | Should -BeFalse
    }

    It 'rejects invalid profile metadata: <Case>' -ForEach @(
        @{ Case = 'duplicate name'; Field = 'SecurityProfileName'; Value = 'Research'; Error = '*Duplicate security profile*' }
        @{ Case = 'duplicate priority'; Field = 'Priority'; Value = '100'; Error = '*Duplicate security profile priority*' }
        @{ Case = 'invalid priority'; Field = 'Priority'; Value = 'NaN'; Error = '*invalid priority*' }
        @{ Case = 'unknown provision'; Field = 'Provision'; Value = 'Maybe'; Error = '*invalid Provision*' }
    ) {
        $profiles[0].$Field = $Value
        $profiles | Export-Csv $profilesPath -NoTypeInformation
        { ConvertTo-EntraInternetAccessV2Plan @parameters } | Should -Throw $Error
    }

    It 'rejects a missing input column' {
        $policies | Select-Object -ExcludeProperty PolicyAction | Export-Csv $policiesPath -NoTypeInformation
        { ConvertTo-EntraInternetAccessV2Plan @parameters } | Should -Throw '*missing required columns: PolicyAction*'
    }

    It 'keeps the versioned output incompatible with V1 provisioning and prevents re-conversion' {
        $result = ConvertTo-EntraInternetAccessV2Plan @parameters
        $parameters.PoliciesCsvPath = $result.PoliciesCsvPath
        { ConvertTo-EntraInternetAccessV2Plan @parameters } | Should -Throw '*accepts only OMv1 CSVs*'
        {
            & (Get-Module Migrate2GSA) {
                param($Path)
                Import-PoliciesConfig -ConfigPath $Path
            } $result.PoliciesCsvPath
        } | Should -Throw '*Missing required columns*PolicyType*PolicyAction*'
    }

    It 'converts the shipped EIA examples without modifying the V1 provisioning interface' {
        $parameters.PoliciesCsvPath = "$PSScriptRoot/../Samples/EIA/sample_policies.rename_to_csv"
        $parameters.SecurityProfilesCsvPath = "$PSScriptRoot/../Samples/EIA/sample_security_profiles.rename_to_csv"
        $result = ConvertTo-EntraInternetAccessV2Plan @parameters
        $targets = @(Import-Csv $result.SecurityProfilesCsvPath)
        $targets.Count | Should -Be 5
        @($targets.WebFilteringPolicyName | Select-Object -Unique).Count | Should -Be 5
        $rules = @(Import-Csv $result.PoliciesCsvPath)
        @($rules | Where-Object SourcePolicyName -Like 'TLS*').Count | Should -Be 0
        $rules.Count | Should -Be 22
        Get-Command Start-EntraInternetAccessProvisioning | Should -Not -BeNullOrEmpty
    }
}
