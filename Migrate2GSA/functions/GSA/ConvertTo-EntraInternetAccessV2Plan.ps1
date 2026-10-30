function ConvertTo-EntraInternetAccessV2Plan {
    <#
    .SYNOPSIS
        Builds reviewable OMv2 web-filtering provisioning CSVs from OMv1 CSVs.
    .DESCRIPTION
        Combines linked OMv1 web-content-filtering policies into one proposed policy
        per security profile. Output uses the EIA-OMv2/1.0 toolkit CSV contract.
        All output rows require review and have Provision=No. After review, use
        Start-EntraInternetAccessProvisioning -PolicyModel OMv2.
        No tenant connection is made and the input files are not modified.
    .PARAMETER PoliciesCsvPath
        Existing Migrate2GSA OMv1 policies CSV, including rows marked Provision=No.
    .PARAMETER SecurityProfilesCsvPath
        Existing Migrate2GSA OMv1 security profiles CSV.
    .PARAMETER DefaultAction
        Explicit no-match action: Allow, Block, or ContinueEvaluation.
        ContinueEvaluation is not allowed for the baseline priority (65000).
    .PARAMETER OutputPath
        Parent directory for a new timestamped plan folder. Defaults to the current directory.
    .PARAMETER IncludePolicyName
        Optional wildcard patterns for source policies to include. Profiles are retained.
    .PARAMETER ExcludePolicyName
        Optional wildcard patterns for source policies to exclude. Exclusion wins.
        Omitted links remain visible in profile review details and source references.
    .EXAMPLE
        ConvertTo-EntraInternetAccessV2Plan -PoliciesCsvPath ./policies.csv `
            -SecurityProfilesCsvPath ./profiles.csv -DefaultAction Block -OutputPath ./output
    .OUTPUTS
        PSCustomObject with SchemaVersion, PoliciesCsvPath, SecurityProfilesCsvPath and LogPath.
    .NOTES
        Rule status is deliberately Disabled, not inferred from Provision.
        Source CSVs do not fully describe live link state or Conditional Access conditions.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$PoliciesCsvPath,

        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$SecurityProfilesCsvPath,

        [Parameter(Mandatory)]
        [ValidateSet('Allow', 'Block', 'ContinueEvaluation')]
        [string]$DefaultAction,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath = $PWD,

        [Parameter()]
        [string[]]$IncludePolicyName,

        [Parameter()]
        [string[]]$ExcludePolicyName
    )

    #region Load and validate
    function Import-PlanInput {
        param([string]$Path, [string[]]$RequiredColumns)

        $rows = @(Import-Csv -LiteralPath $Path -ErrorAction Stop)
        if ($rows.Count -eq 0) {
            throw "Input '$Path' has no data rows."
        }
        if ('SchemaVersion' -in $rows[0].PSObject.Properties.Name) {
            throw "Input '$Path' is versioned. This command accepts only OMv1 CSVs, not an OMv2 plan."
        }
        $missing = @($RequiredColumns | Where-Object { $_ -notin $rows[0].PSObject.Properties.Name })
        if ($missing.Count -gt 0) {
            throw "Input '$Path' is missing required columns: $($missing -join ', ')."
        }
        return $rows
    }

    $policies = @(Import-PlanInput -Path $PoliciesCsvPath -RequiredColumns @(
        'PolicyName', 'PolicyType', 'PolicyAction', 'RuleName', 'RuleType', 'RuleDestinations', 'Provision'
    ))
    $profiles = @(Import-PlanInput -Path $SecurityProfilesCsvPath -RequiredColumns @(
        'SecurityProfileName', 'Priority', 'SecurityProfileLinks', 'Provision'
    ))
    $policyLookup = @{}
    $sourceRowNumber = 0
    foreach ($row in $policies) {
        $sourceRowNumber++
        if ([string]::IsNullOrWhiteSpace($row.PolicyName) -or $row.PolicyName -ne $row.PolicyName.Trim()) {
            throw "Policy data row $sourceRowNumber must have a non-empty PolicyName without surrounding whitespace."
        }
        if ($row.Provision -notin @('Yes', 'No')) {
            throw "Policy '$($row.PolicyName)' has invalid Provision '$($row.Provision)'; expected Yes or No."
        }
        if (-not $policyLookup.ContainsKey($row.PolicyName)) {
            $policyLookup[$row.PolicyName] = [System.Collections.Generic.List[object]]::new()
        }
        $existingRows = $policyLookup[$row.PolicyName]
        if ($existingRows.Count -gt 0 -and (
            $existingRows[0].Row.PolicyType -ne $row.PolicyType -or
            $existingRows[0].Row.PolicyAction -ne $row.PolicyAction
        )) {
            throw "Policy '$($row.PolicyName)' has inconsistent PolicyType or PolicyAction values."
        }
        $existingRows.Add([pscustomobject]@{ Row = $row; SourceRow = $sourceRowNumber })
    }

    $profileNames = @{}
    $profilePriorities = @{}
    foreach ($profile in $profiles) {
        $name = $profile.SecurityProfileName
        if ([string]::IsNullOrWhiteSpace($name) -or $name -ne $name.Trim()) {
            throw 'SecurityProfileName must be non-empty and have no surrounding whitespace.'
        }
        if ($profileNames.ContainsKey($name)) {
            throw "Duplicate security profile '$name'."
        }
        $priority = 0
        if (-not [int]::TryParse($profile.Priority, [ref]$priority) -or $priority -lt 1 -or $priority -gt 65000) {
            throw "Profile '$name' has invalid priority '$($profile.Priority)'; expected 1 through 65000."
        }
        if ($profilePriorities.ContainsKey($priority)) {
            throw "Duplicate security profile priority '$priority'."
        }
        if ($priority -eq 65000 -and $DefaultAction -eq 'ContinueEvaluation') {
            throw "Baseline profile '$name' cannot use ContinueEvaluation. Choose Allow or Block."
        }
        if ($profile.Provision -notin @('Yes', 'No')) {
            throw "Profile '$name' has invalid Provision '$($profile.Provision)'; expected Yes or No."
        }
        $profileNames[$name] = $true
        $profilePriorities[$priority] = $true
    }
    #endregion

    #region Build review plan
    $schemaVersion = 'EIA-OMv2/1.0'
    $defaultActions = @{ Allow = 'Allow'; Block = 'Block'; ContinueEvaluation = 'ContinueEvaluation' }
    $proposedDefault = $defaultActions[$DefaultAction]
    $ruleActions = @{ Allow = 'Allow'; Block = 'Block' }
    $ruleTypes = @{ FQDN = 'URL'; URL = 'URL'; webCategory = 'webCategory' }
    $ruleRows = [System.Collections.Generic.List[object]]::new()
    $profileRows = [System.Collections.Generic.List[object]]::new()
    $referencedPolicies = @{}
    $commonReview = 'Verify default action, cross-profile evaluation, V1 coexistence and target matching before deployment.'

    foreach ($profile in ($profiles | Sort-Object { [int]$_.Priority })) {
        $name = $profile.SecurityProfileName
        $profileReview = [System.Collections.Generic.List[string]]::new()
        $profileReview.Add($commonReview)
        $profileReview.Add('Source CSV does not establish live link status or complete Conditional Access conditions.')
        if ($profile.Provision -eq 'No') {
            $profileReview.Add('Source profile is marked Provision=No.')
        }
        if (-not [string]::IsNullOrWhiteSpace($profile.Notes)) {
            $profileReview.Add("Source notes: $($profile.Notes)")
        }
        $links = [System.Collections.Generic.List[object]]::new()
        $seenLinks = @{}
        $seenPriorities = @{}
        foreach ($link in ($profile.SecurityProfileLinks -split ';')) {
            $link = $link.Trim()
            if (-not $link) { continue }
            $linkPriority = 0
            if ($link -match '^(.+):(\d+)$') {
                $sourcePolicyName = $Matches[1].Trim()
                if (-not [int]::TryParse($Matches[2], [ref]$linkPriority) -or $linkPriority -lt 1) {
                    throw "Invalid policy-link priority in '$link' for profile '$name'."
                }
            }
            elseif ($link -notmatch ':') {
                $sourcePolicyName = $link
            }
            else {
                throw "Invalid policy link '$link' in profile '$name'."
            }
            if ($seenLinks.ContainsKey($sourcePolicyName)) {
                throw "Duplicate policy link '$sourcePolicyName' in profile '$name'."
            }
            $seenLinks[$sourcePolicyName] = $true
            if (-not $policyLookup.ContainsKey($sourcePolicyName)) {
                if ($linkPriority -gt 0) {
                    throw "Profile '$name' references missing policy '$sourcePolicyName'."
                }
                $profileReview.Add("Unresolved unprioritized link retained as a source reference only: $link.")
                continue
            }
            $referencedPolicies[$sourcePolicyName] = $true
            if ($policyLookup[$sourcePolicyName][0].Row.PolicyType -ne 'WebContentFiltering') {
                $profileReview.Add("Non-web policy not converted; source link retained: $link.")
                continue
            }
            if ($linkPriority -eq 0) {
                throw "Web-content-filtering link '$sourcePolicyName' in profile '$name' needs a priority."
            }
            if ($seenPriorities.ContainsKey($linkPriority)) {
                throw "Duplicate web policy-link priority '$linkPriority' in profile '$name'."
            }
            $seenPriorities[$linkPriority] = $true
            $included = -not $IncludePolicyName -or @(
                $IncludePolicyName | Where-Object { $sourcePolicyName -like $_ }
            ).Count -gt 0
            $excluded = @($ExcludePolicyName | Where-Object { $sourcePolicyName -like $_ }).Count -gt 0
            if (-not $included -or $excluded) {
                $profileReview.Add("Policy omitted by name filter; plan is incomplete: $sourcePolicyName.")
                continue
            }
            $links.Add([pscustomobject]@{ PolicyName = $sourcePolicyName; Priority = $linkPriority })
        }

        $targetPolicyName = "$name-WebFilteringV2"
        $rulePriority = 0
        foreach ($link in ($links | Sort-Object Priority)) {
            foreach ($source in $policyLookup[$link.PolicyName]) {
                $row = $source.Row
                $rulePriority += 100
                $review = [System.Collections.Generic.List[string]]::new()
                $review.Add($commonReview)
                $review.Add('Rule deliberately disabled; Provision is not a source runtime status.')
                $action = $ruleActions[$row.PolicyAction]
                if (-not $action) {
                    $action = 'Unsupported'
                    $review.Add("Unsupported source action '$($row.PolicyAction)'; no replacement action inferred.")
                }
                $type = $ruleTypes[$row.RuleType]
                if (-not $type) {
                    $type = 'Unsupported'
                    $review.Add("Unsupported source rule type '$($row.RuleType)'; destinations retained verbatim.")
                }
                if ($row.RuleType -eq 'FQDN') {
                    $review.Add('FQDN proposed as URL; matching semantics differ. Validate host, wildcard and sub-path behavior.')
                }
                if ([string]::IsNullOrWhiteSpace($row.RuleDestinations)) {
                    $review.Add('Source destinations are empty.')
                }
                if ($row.Provision -eq 'No' -or $profile.Provision -eq 'No') {
                    $review.Add('Source rule or profile is marked Provision=No.')
                }
                if ($row.ReviewNeeded -eq 'Yes' -or -not [string]::IsNullOrWhiteSpace($row.ReviewDetails)) {
                    $review.Add("Source review: ReviewNeeded=$($row.ReviewNeeded); $($row.ReviewDetails)")
                }
                $ruleRows.Add([pscustomobject][ordered]@{
                    SchemaVersion = $schemaVersion
                    SecurityProfileName = $name
                    PolicyName = $targetPolicyName
                    Description = ''
                    PolicyDefaultAction = $proposedDefault
                    RuleName = "Rule-$rulePriority"
                    RuleDescription = ''
                    RulePriority = $rulePriority
                    RuleStatus = 'Disabled'
                    RuleAction = $action
                    RuleType = $type
                    RuleDestinations = $row.RuleDestinations
                    SourcePolicyName = $link.PolicyName
                    SourcePolicyAction = $row.PolicyAction
                    SourcePolicyLinkPriority = $link.Priority
                    SourceRuleName = $row.RuleName
                    SourceRuleType = $row.RuleType
                    SourceRow = $source.SourceRow
                    SourceProvision = $row.Provision
                    ReviewNeeded = 'Yes'
                    ReviewDetails = $review -join ' '
                    Provision = 'No'
                })
            }
        }
        if ($rulePriority -eq 0) {
            $targetPolicyName = ''
            $profileReview.Add('No selected web-filtering rules; no V2 policy proposed for this profile.')
        }
        $profileRows.Add([pscustomobject][ordered]@{
            SchemaVersion = $schemaVersion
            SecurityProfileName = $name
            Priority = $profile.Priority
            Description = ''
            ProfileState = 'Disabled'
            LinkState = 'Enabled'
            WebFilteringPolicyName = $targetPolicyName
            PolicyDefaultAction = $(if ($targetPolicyName) { $proposedDefault } else { '' })
            CADisplayName = $profile.CADisplayName
            EntraUsers = $profile.EntraUsers
            EntraGroups = $profile.EntraGroups
            ConditionalAccessPoliciesJson = ''
            SourceSecurityProfileLinks = $profile.SecurityProfileLinks
            SourceProvision = $profile.Provision
            ReviewNeeded = 'Yes'
            ReviewDetails = $profileReview -join ' '
            Provision = 'No'
        })
    }
    if ($ruleRows.Count -eq 0) {
        throw 'No linked web-content-filtering rules selected. No plan was written.'
    }
    $unlinkedPolicies = @($policyLookup.Keys | Where-Object { -not $referencedPolicies.ContainsKey($_) } | Sort-Object)
    #endregion

    #region Export
    $folder = Join-Path $OutputPath "EIA-OMv2Plan_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff')"
    if (-not $PSCmdlet.ShouldProcess($folder, 'Write review-only OMv2 CSV plan and log')) { return }
    $folder = (New-Item -Path $folder -ItemType Directory -ErrorAction Stop).FullName
    $logPath = Join-Path $folder 'EIA_OMv2_Plan.log'
    $policiesPath = Join-Path $folder 'EIA_OMv2_Policies.review.csv'
    $profilesPath = Join-Path $folder 'EIA_OMv2_SecurityProfiles.review.csv'
    try {
        Write-LogMessage "Building $schemaVersion from OMv1 CSVs. No Graph calls; no tenant changes." -LogPath $logPath
        Write-LogMessage "Proposed default action: $proposedDefault. Every row requires review and has Provision=No." -Level WARN -LogPath $logPath
        if ($unlinkedPolicies.Count -gt 0) {
            Write-LogMessage "Policies with no profile reference are not converted: $($unlinkedPolicies -join '; ')." -Level WARN -LogPath $logPath
        }
        foreach ($profileRow in $profileRows) {
            Write-LogMessage "$($profileRow.SecurityProfileName): $($profileRow.ReviewDetails)" -Level WARN -LogPath $logPath
        }
        $ruleRows | Export-Csv -LiteralPath $policiesPath -NoTypeInformation -Encoding utf8BOM -NoClobber -ErrorAction Stop
        $profileRows | Export-Csv -LiteralPath $profilesPath -NoTypeInformation -Encoding utf8BOM -NoClobber -ErrorAction Stop
        Write-LogMessage "Wrote $($ruleRows.Count) review rule rows and $($profileRows.Count) profile rows." -LogPath $logPath
        [pscustomobject]@{
            SchemaVersion = $schemaVersion
            PoliciesCsvPath = $policiesPath
            SecurityProfilesCsvPath = $profilesPath
            LogPath = $logPath
        }
    }
    catch {
        Write-LogMessage "Plan export failed; do not use partial files in '$folder': $_" -Level ERROR -LogPath $logPath
        throw
    }
    #endregion
}
