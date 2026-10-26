BeforeAll {
    $env:MIGRATE2GSA_TELEMETRY_OPTOUT = '1'
    $root = Split-Path -Parent $PSScriptRoot
    Import-Module "$root/Migrate2GSA/Migrate2GSA.psd1" -Force
    $samples = "$root/Samples/NSWG2EIA"
    $profileId = '11111111-1111-4111-8111-111111111111'
    $exceptionId = '22222222-2222-4222-8222-222222222222'
    $regexId = '33333333-3333-4333-8333-333333333333'

    function Write-TestJson {
        param($Value, [string]$Path)
        ConvertTo-Json -InputObject $Value -Depth 20 | Set-Content -LiteralPath $Path
    }

    function Invoke-TestConversion {
        param([hashtable]$Parameters)
        $result = Convert-NSWG2EIAV2 @Parameters
        [PSCustomObject]@{
            Result = $result
            Policies = @(Import-Csv $result.PoliciesCsvPath)
            Profiles = @(Import-Csv $result.SecurityProfilesCsvPath)
        }
    }
}

Describe 'Netskope Destination Profile review conversion' {
    BeforeEach {
        Mock Write-LogMessage -ModuleName Migrate2GSA {}
        $work = New-Item -ItemType Directory -Path "$TestDrive/$([guid]::NewGuid().ToString('N'))"
        $destinations = Get-Content "$samples/DestinationProfiles/destinations.rename_to_json" -Raw | ConvertFrom-Json
        $categories = Get-Content "$samples/DestinationProfiles/custom_categories.rename_to_json" -Raw | ConvertFrom-Json
        $parameters = @{
            RealTimeProtectionPoliciesPath = "$samples/DestinationProfiles/real_time_protection_policies.rename_to_json"
            UrlListsPath = "$samples/sample_url_lists.rename_to_json"
            DestinationProfilesPath = "$work/destinations.json"
            CustomCategoriesPath = "$work/categories.json"
            CategoryMappingsPath = "$samples/Netskope-to-GSA-CategoryMapping.rename_to_csv"
            OutputBasePath = $work.FullName
        }
        Write-TestJson $destinations $parameters.DestinationProfilesPath
        Write-TestJson $categories $parameters.CustomCategoriesPath
    }

    It 'normalizes legacy statuses with trailing whitespace in the preview' {
        $parameters.Remove('DestinationProfilesPath')
        $parameters.RealTimeProtectionPoliciesPath = "$samples/sample_real_time_protection_policies.rename_to_json"
        $parameters.CustomCategoriesPath = "$samples/sample_custom_categories.rename_to_json"
        $output = Invoke-TestConversion $parameters
        $output.Policies.Count | Should -Be 28
        $output.Profiles.Count | Should -Be 4
        @($output.Policies | Where-Object ReviewNeeded -eq Yes).Count | Should -Be 5
        $whitelist = @($output.Policies | Where-Object PolicyName -eq 'Whitelist URLs-Allow')
        $whitelist.Count | Should -Be 6
        $whitelist.RuleDestinations | Should -Contain '*.zoom.us'
        @($output.Profiles | Where-Object Provision -eq No).Count | Should -Be 0
    }

    It 'runs both public converters without overwriting artifacts or changing normalized legacy output' {
        Mock Get-Date -ModuleName Migrate2GSA -ParameterFilter { $Format -eq 'yyyyMMdd_HHmmss' } { '20261026_120000' }
        $parameters.Remove('DestinationProfilesPath')
        $parameters.CustomCategoriesPath = "$samples/sample_custom_categories.rename_to_json"
        $rtp = Get-Content "$samples/sample_real_time_protection_policies.rename_to_json" -Raw | ConvertFrom-Json
        foreach ($policy in $rtp.data) { $policy.status = ([string]$policy.status).Trim() }
        $parameters.RealTimeProtectionPoliciesPath = "$work/normalized-rtp.json"
        Write-TestJson $rtp $parameters.RealTimeProtectionPoliciesPath

        $original = Convert-NSWG2EIA @parameters -WarningVariable originalWarnings
        $originalCsv = Get-Content $original.PoliciesCsvPath -Raw
        $preview = Convert-NSWG2EIAV2 @parameters -WarningVariable previewWarnings -WarningAction SilentlyContinue
        $original.PoliciesCsvPath | Should -Not -Be $preview.PoliciesCsvPath
        $original.SecurityProfilesCsvPath | Should -Not -Be $preview.SecurityProfilesCsvPath
        $original.LogFilePath | Should -Not -Be $preview.LogFilePath
        (Get-Content $original.PoliciesCsvPath -Raw) | Should -BeExactly $originalCsv
        $originalWarnings | Should -BeNullOrEmpty
        ($previewWarnings -join ' ') | Should -Match 'EXPERIMENTAL.*not yet validated'
        $original.PoliciesCreated | Should -Be 28
        $original.SecurityProfilesCreated | Should -Be 4

        $legacyRows = @(Import-Csv $original.PoliciesCsvPath | Sort-Object PolicyName, RuleName, RuleDestinations)
        $previewRows = @(Import-Csv $preview.PoliciesCsvPath | Sort-Object PolicyName, RuleName, RuleDestinations)
        ($previewRows | ConvertTo-Json -Depth 5) | Should -BeExactly ($legacyRows | ConvertTo-Json -Depth 5)
        # Ordinal profile names depend on hashtable enumeration, not source identity.
        $profileFields = @('EntraGroups', 'EntraUsers', 'SecurityProfileLinks', 'Description', 'Provision', 'Notes')
        $legacyProfiles = @(Import-Csv $original.SecurityProfilesCsvPath |
            Select-Object -Property $profileFields | Sort-Object EntraGroups, EntraUsers)
        $previewProfiles = @(Import-Csv $preview.SecurityProfilesCsvPath |
            Select-Object -Property $profileFields | Sort-Object EntraGroups, EntraUsers)
        ($previewProfiles | ConvertTo-Json -Depth 5) | Should -BeExactly ($legacyProfiles | ConvertTo-Json -Depth 5)
    }

    It 'keeps same-named URL Lists and Destination Profiles distinct and gates both assignment types' {
        $output = Invoke-TestConversion $parameters
        $output.Policies.Count | Should -Be 17
        $output.Profiles.Count | Should -Be 2
        @($output.Policies | Where-Object PolicyName -eq 'Whitelist URLs-Block').Count | Should -Be 6
        @($output.Policies | Where-Object PolicyName -eq "DestinationProfile-$profileId-Block").Count | Should -Be 7
        @($output.Policies | Where-Object { $_.PolicyName -like 'DestinationProfile-*' -and $_.Provision -ne 'No' }).Count | Should -Be 0
        @($output.Profiles | Where-Object Provision -eq No).Count | Should -Be 2
        $all = $output.Profiles | Where-Object SecurityProfileName -eq 'SecurityProfile-All-Users'
        $all.SecurityProfileLinks | Should -Match "DestinationProfile-$exceptionId-Allow:\d+"
        $all.SecurityProfileLinks | Should -Match "DestinationProfile-$profileId-Block:\d+"
        $output.Policies.RuleDestinations | Should -Contain 'example.com;*.example.com'
        $unmapped = $output.Policies | Where-Object RuleDestinations -eq 'UNMAPPED:NetskopeCategoryId:500'
        $unmapped.Provision | Should -Be 'No'
    }

    It 'preserves ports queries CIDR ranges regex and case-sensitive values verbatim in review details' {
        $output = Invoke-TestConversion $parameters
        foreach ($profile in $destinations.elements) {
            foreach ($value in $profile.values) {
                $encoded = ConvertTo-Json -InputObject $value -Compress
                @($output.Policies | Where-Object {
                    $_.PolicyName -like "DestinationProfile-$($profile.id)-*" -and
                    $_.ReviewDetails.Contains("value=$encoded")
                }).Count | Should -Be 1
            }
        }
        $regex = $output.Policies | Where-Object PolicyName -eq "DestinationProfile-$regexId-Allow"
        $regex.PolicyAction | Should -Be 'Allow'
        $regex.RuleDestinations | Should -Be 'PLACEHOLDER_DESTINATION_PROFILE'
        @($output.Policies | Where-Object { $_.RuleDestinations.Length -gt 300 }).Count | Should -Be 0
    }

    It 'accepts empty profile collections and profile-only input without a URL List file' {
        $parameters.Remove('UrlListsPath')
        $categories.elements[0].included_url_lists = @()
        $categories.elements[0].included_destination_profiles = @()
        $categories.elements[0].excluded_destination_profiles = @()
        $categories.elements[1].included_destination_profiles = @()
        Write-TestJson $categories $parameters.CustomCategoriesPath
        Write-TestJson ([PSCustomObject]@{ total_count = 0; elements = @() }) $parameters.DestinationProfilesPath
        $output = Invoke-TestConversion $parameters
        $output.Policies.Count | Should -Be 1
        @($output.Profiles | Where-Object Provision -eq No).Count | Should -Be 2
    }

    It 'accepts a direct profile array and keeps a referenced empty profile visible' {
        $destinations.elements[0].values = @()
        Write-TestJson $destinations.elements $parameters.DestinationProfilesPath
        $output = Invoke-TestConversion $parameters
        $rows = @($output.Policies | Where-Object PolicyName -eq "DestinationProfile-$profileId-Block")
        $rows.Count | Should -Be 1
        $rows[0].RuleDestinations | Should -Be 'PLACEHOLDER_DESTINATION_PROFILE'
        $rows[0].Provision | Should -Be 'No'
    }

    It 'does not fall back to a URL List when a typed Destination Profile ID is missing' {
        $categories.elements[0].included_destination_profiles = @('2')
        Write-TestJson $categories $parameters.CustomCategoriesPath
        { Convert-NSWG2EIAV2 @parameters } | Should -Throw '*missing Destination Profile*'
        @(Get-ChildItem $work -Filter '*_EIA_*.csv').Count | Should -Be 0
    }

    It 'fails when Destination Profiles were not supplied for typed category references' {
        $parameters.Remove('DestinationProfilesPath')
        { Convert-NSWG2EIAV2 @parameters } | Should -Throw '*DestinationProfilesPath*'
    }

    It 'fails instead of dropping an unresolved URL List inclusion or exclusion' -ForEach @(
        @{ Field = 'included_url_lists' },
        @{ Field = 'excluded_url_lists' }
    ) {
        $categories.elements[0].$Field = @('missing')
        Write-TestJson $categories $parameters.CustomCategoriesPath
        { Convert-NSWG2EIAV2 @parameters } | Should -Throw '*missing URL List*'
    }

    It 'rejects a partial Destination Profile collection' {
        $destinations.total_count = 4
        Write-TestJson $destinations $parameters.DestinationProfilesPath
        { Convert-NSWG2EIAV2 @parameters } | Should -Throw '*complete elements/total_count*'
    }

    It 'rejects a partial modern category collection' {
        $categories.total_count = 3
        Write-TestJson $categories $parameters.CustomCategoriesPath
        { Convert-NSWG2EIAV2 @parameters } | Should -Throw '*collection is incomplete*'
    }

    It 'rejects duplicate profile IDs and undocumented match types' -ForEach @(
        @{ Invalid = 'duplicate' },
        @{ Invalid = 'type' }
    ) {
        if ($Invalid -eq 'duplicate') { $destinations.elements[1].id = $profileId }
        else { $destinations.elements[0].type = 'exact' }
        Write-TestJson $destinations $parameters.DestinationProfilesPath
        { Convert-NSWG2EIAV2 @parameters } | Should -Throw '*Invalid or duplicate Destination Profile*'
    }

    It 'keeps overlapping source IDs in separate namespaces' {
        $destinations.elements[0].id = '2'
        $categories.elements[0].included_destination_profiles = @('2')
        Write-TestJson $destinations $parameters.DestinationProfilesPath
        Write-TestJson $categories $parameters.CustomCategoriesPath
        $output = Invoke-TestConversion $parameters
        @($output.Policies | Where-Object PolicyName -eq 'Whitelist URLs-Block').Count | Should -Be 6
        @($output.Policies | Where-Object PolicyName -eq 'DestinationProfile-2-Block').Count | Should -Be 7
    }

    It 'rejects malformed typed references instead of discarding them' {
        $categories.elements[0].included_destination_profiles = 'not-an-array'
        Write-TestJson $categories $parameters.CustomCategoriesPath
        { Convert-NSWG2EIAV2 @parameters } | Should -Throw '*expected an array of nonempty string IDs*'
    }

    It 'rejects ambiguous category name joins' {
        $categories.elements[1].name = $categories.elements[0].name
        Write-TestJson $categories $parameters.CustomCategoriesPath
        { Convert-NSWG2EIAV2 @parameters } | Should -Throw '*names must be nonempty and unique*'
    }
}

Describe 'Netskope V2 fixture export-to-conversion integration' {
    It 'round-trips the supplied examples through paginated export files and produces the same review output' {
        Mock Invoke-RestMethod -ModuleName Migrate2GSA {
            param($Uri, $Method)
            if ($Method -ne 'GET') { throw "Unexpected API method: $Method" }
            $fixtureRoot = Join-Path (Split-Path (Get-Module Migrate2GSA).ModuleBase -Parent) 'Samples/NSWG2EIA'
            $request = [uri]$Uri
            switch ($request.AbsolutePath) {
                '/api/v2/profiles/destinations' { $fixture = 'DestinationProfiles/destinations.rename_to_json' }
                '/api/v2/profiles/customcategories' { $fixture = 'DestinationProfiles/custom_categories.rename_to_json' }
                '/api/v2/policy/urllist' {
                    return Get-Content "$fixtureRoot/sample_url_lists.rename_to_json" -Raw | ConvertFrom-Json
                }
                { $_ -in @('/api/v2/steering/apps/private', '/api/v2/infrastructure/publishers',
                           '/api/v2/policy/npa/rules', '/api/v2/policy/npa/policygroups') } {
                    return [PSCustomObject]@{ data = @([PSCustomObject]@{ id = 'unrelated-synthetic-object' }) }
                }
                default { throw "Unexpected API request: $Uri" }
            }
            if ($request.Query -notmatch '^\?limit=100&offset=(\d+)$') {
                throw "Unexpected pagination query: $Uri"
            }
            $offset = [int]$Matches[1]
            $collection = Get-Content "$fixtureRoot/$fixture" -Raw | ConvertFrom-Json
            if ($offset -ge $collection.elements.Count) { throw "Unexpected offset: $offset" }
            # Short pages force every example through the pagination/serialization boundary.
            [PSCustomObject]@{
                total_count = $collection.total_count
                elements = @($collection.elements[$offset])
            }
        }

        $work = New-Item -ItemType Directory -Path "$TestDrive/$([guid]::NewGuid().ToString('N'))"
        $exportParameters = @{
            ApiToken = ConvertTo-SecureString 'synthetic-test-token' -AsPlainText -Force
            TenantUrl = 'https://example.invalid'
            OutputDirectory = "$work/export"
            RequestDelay = 0
        }
        Export-NetskopeConfigV2 @exportParameters 6>$null | Should -BeTrue
        $backup = @(Get-ChildItem "$work/export" -Directory -Filter 'backup_v2_preview_*')
        $backup.Count | Should -Be 1
        $backupDir = $backup[0].FullName
        foreach ($file in @('destinations', 'custom_categories')) {
            $expected = Get-Content "$samples/DestinationProfiles/$file.rename_to_json" -Raw | ConvertFrom-Json
            $actual = Get-Content "$backupDir/$file.json" -Raw | ConvertFrom-Json
            ($actual | ConvertTo-Json -Depth 20) | Should -BeExactly ($expected | ConvertTo-Json -Depth 20)
        }
        $sourceLists = Get-Content "$samples/sample_url_lists.rename_to_json" -Raw | ConvertFrom-Json
        $exportedLists = Get-Content "$backupDir/url_lists.json" -Raw | ConvertFrom-Json
        (ConvertTo-Json -InputObject $exportedLists -Depth 20) |
            Should -BeExactly (ConvertTo-Json -InputObject $sourceLists.data -Depth 20)
        (Get-Content "$backupDir/Export-NetskopeConfigV2.log" -Raw) | Should -Match 'EXPERIMENTAL'
        Should -Invoke Invoke-RestMethod -ModuleName Migrate2GSA -Times 3 -Exactly -ParameterFilter {
            $Uri -match '/profiles/destinations\?'
        }
        Should -Invoke Invoke-RestMethod -ModuleName Migrate2GSA -Times 2 -Exactly -ParameterFilter {
            $Uri -match '/profiles/customcategories\?'
        }
        Should -Invoke Invoke-RestMethod -ModuleName Migrate2GSA -Times 10 -Exactly

        $outputDir = New-Item -ItemType Directory -Path "$work/converted"
        $parameters = @{
            # RTP is supplied separately because the exporter does not export it.
            RealTimeProtectionPoliciesPath = "$samples/DestinationProfiles/real_time_protection_policies.rename_to_json"
            UrlListsPath = "$backupDir/url_lists.json"
            DestinationProfilesPath = "$backupDir/destinations.json"
            CustomCategoriesPath = "$backupDir/custom_categories.json"
            CategoryMappingsPath = "$samples/Netskope-to-GSA-CategoryMapping.rename_to_csv"
            OutputBasePath = $outputDir.FullName
        }
        $roundTrip = Invoke-TestConversion $parameters 6>$null
        $roundTrip.Policies.Count | Should -Be 17
        $roundTrip.Profiles.Count | Should -Be 2
        $profileRows = @($roundTrip.Policies | Where-Object PolicyName -like 'DestinationProfile-*')
        $profileRows.Count | Should -Be 10
        @($profileRows | Where-Object { $_.Provision -ne 'No' -or $_.ReviewNeeded -ne 'Yes' }).Count | Should -Be 0
        @($roundTrip.Profiles | Where-Object Provision -eq No).Count | Should -Be 2
        (Get-Content $roundTrip.Result.LogFilePath -Raw) | Should -Match 'Completed Successfully'
        foreach ($profile in $roundTrip.Profiles) {
            foreach ($link in $profile.SecurityProfileLinks.Split(';')) {
                $roundTrip.Policies.PolicyName | Should -Contain ($link -replace ':\d+$', '')
            }
        }

        $directDir = New-Item -ItemType Directory -Path "$work/direct"
        $parameters.OutputBasePath = $directDir.FullName
        $parameters.UrlListsPath = "$samples/sample_url_lists.rename_to_json"
        $parameters.DestinationProfilesPath = "$samples/DestinationProfiles/destinations.rename_to_json"
        $parameters.CustomCategoriesPath = "$samples/DestinationProfiles/custom_categories.rename_to_json"
        $direct = Invoke-TestConversion $parameters 6>$null
        ($roundTrip.Policies | Sort-Object PolicyName, RuleName | ConvertTo-Json -Depth 5) |
            Should -BeExactly ($direct.Policies | Sort-Object PolicyName, RuleName | ConvertTo-Json -Depth 5)
        ($roundTrip.Profiles | Sort-Object SecurityProfileName | ConvertTo-Json -Depth 5) |
            Should -BeExactly ($direct.Profiles | Sort-Object SecurityProfileName | ConvertTo-Json -Depth 5)
    }
}

Describe 'Netskope paginated profile export' {
    BeforeEach {
        Mock Write-LogMessage -ModuleName Migrate2GSA {}
        $work = New-Item -ItemType Directory -Path "$TestDrive/$([guid]::NewGuid().ToString('N'))"
        $exportParameters = @{
            ApiToken = ConvertTo-SecureString 'synthetic-test-token' -AsPlainText -Force
            TenantUrl = 'https://example.invalid'
            OutputDirectory = $work.FullName
            RequestDelay = 0
        }
        Mock Invoke-RestMethod -ModuleName Migrate2GSA {
            param($Uri)
            if ($Uri -match '/profiles/(destinations|customcategories)\?limit=100&offset=(\d+)$') {
                $offset = [int]$Matches[2]
                $items = if ($offset -eq 0) {
                    @(1..100 | ForEach-Object { [PSCustomObject]@{ id = "id-$_"; status = 'applied'; values = @('example.com') } })
                } elseif ($offset -eq 100) {
                    @([PSCustomObject]@{ id = 'id-101'; status = 'pending-update'; values = @('example.com:443') })
                } else { throw "Unexpected offset: $offset" }
                return [PSCustomObject]@{ total_count = 101; elements = @($items) }
            }
            if ($Uri -match '/profiles/') { throw "Unexpected profile request: $Uri" }
            return [PSCustomObject]@{ data = @([PSCustomObject]@{ id = 'legacy' }) }
        }
    }

    It 'exports all pages of profiles and categories under existing filenames, retaining pending data' {
        Export-NetskopeConfigV2 @exportParameters | Should -BeTrue
        foreach ($file in @('destinations.json', 'custom_categories.json')) {
            $path = Get-ChildItem $work -Recurse -Filter $file
            $saved = Get-Content $path.FullName -Raw | ConvertFrom-Json
            $saved.total_count | Should -Be 101
            $saved.elements.Count | Should -Be 101
            $saved.elements[-1].status | Should -Be 'pending-update'
        }
        Should -Invoke Invoke-RestMethod -ModuleName Migrate2GSA -Times 4 -Exactly -ParameterFilter { $Uri -match '/profiles/' }
    }

    It 'keeps original unpaginated export and preview export separate in the same output directory' {
        Mock Get-Date -ModuleName Migrate2GSA {
            param($Format)
            ([datetime]'2026-10-26T12:00:00').ToString($Format)
        }
        Mock Invoke-RestMethod -ModuleName Migrate2GSA -ParameterFilter { $Uri -match '/profiles/(destinations|customcategories)$' } {
            [PSCustomObject]@{ data = @([PSCustomObject]@{ id = 'legacy-profile' }) }
        }
        Export-NetskopeConfig @exportParameters -WarningVariable originalWarnings | Should -BeTrue
        $originalPath = "$work/backup_20261026_120000/destinations.json"
        $originalJson = Get-Content $originalPath -Raw
        Export-NetskopeConfigV2 @exportParameters -WarningVariable previewWarnings -WarningAction SilentlyContinue | Should -BeTrue
        $previewPath = "$work/backup_v2_preview_20261026_120000/destinations.json"
        (Get-Content $originalPath -Raw) | Should -BeExactly $originalJson
        (Get-Content $previewPath -Raw | ConvertFrom-Json).elements.Count | Should -Be 101
        $originalWarnings | Should -BeNullOrEmpty
        ($previewWarnings -join ' ') | Should -Match 'EXPERIMENTAL.*not yet validated'
        Should -Invoke Invoke-RestMethod -ModuleName Migrate2GSA -Times 2 -Exactly -ParameterFilter {
            $Uri -match '/profiles/(destinations|customcategories)$'
        }
        Should -Invoke Invoke-RestMethod -ModuleName Migrate2GSA -Times 4 -Exactly -ParameterFilter {
            $Uri -match '/profiles/(destinations|customcategories)\?limit=100&offset='
        }
    }

    It 'exports a valid empty collection rather than treating it as failure' {
        Mock Invoke-RestMethod -ModuleName Migrate2GSA -ParameterFilter { $Uri -match '/profiles/' } {
            [PSCustomObject]@{ total_count = 0; elements = @() }
        }
        Export-NetskopeConfigV2 @exportParameters | Should -BeTrue
        $path = Get-ChildItem $work -Recurse -Filter 'destinations.json'
        $saved = Get-Content $path.FullName -Raw | ConvertFrom-Json
        $saved.total_count | Should -Be 0
        ,$saved.elements | Should -BeOfType [array]
        $saved.elements.Count | Should -Be 0
    }

    It 'does not save or report success for failed or inconsistent pages: <Failure>' -ForEach @(
        @{ Failure = 'http' },
        @{ Failure = 'empty' },
        @{ Failure = 'count' },
        @{ Failure = 'duplicate' },
        @{ Failure = 'shape' }
    ) {
        $global:NetskopeTestPageFailure = $Failure
        Mock Invoke-RestMethod -ModuleName Migrate2GSA -ParameterFilter { $Uri -match '/destinations\?.*offset=100$' } {
            switch ($global:NetskopeTestPageFailure) {
                'http' { throw 'Simulated HTTP failure' }
                'empty' { return [PSCustomObject]@{ total_count = 101; elements = @() } }
                'count' { return [PSCustomObject]@{ total_count = 102; elements = @([PSCustomObject]@{ id = 'id-101' }) } }
                'duplicate' { return [PSCustomObject]@{ total_count = 101; elements = @([PSCustomObject]@{ id = 'id-1' }) } }
                'shape' { return [PSCustomObject]@{ data = @() } }
            }
        }
        try {
            { Export-NetskopeConfigV2 @exportParameters } | Should -Throw '*Backup process failed*'
            @(Get-ChildItem $work -Recurse -Filter 'destinations.json').Count | Should -Be 0
            Should -Invoke Invoke-RestMethod -ModuleName Migrate2GSA -Times 1 -Exactly -ParameterFilter { $Uri -match '/destinations\?.*offset=100$' }
        } finally {
            Remove-Variable NetskopeTestPageFailure -Scope Global
        }
    }
}
