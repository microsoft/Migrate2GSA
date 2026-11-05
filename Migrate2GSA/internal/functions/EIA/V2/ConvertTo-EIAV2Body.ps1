function ConvertTo-EIAV2Body {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Row,
        [Parameter(Mandatory)][ValidateSet('Policy', 'Rule', 'Profile')][string]$Kind
    )

    $prefix = '#microsoft.graph.networkaccess.'
    if ($Kind -eq 'Policy') {
        $action = @{ Allow = 'Allow'; Block = 'Block'; ContinueEvaluation = 'ContinueEvaluation' }[$Row.PolicyDefaultAction]
        if (-not $action) { throw "Invalid PolicyDefaultAction '$($Row.PolicyDefaultAction)'." }
        return @{
            '@odata.type' = "${prefix}webFilteringPolicy"
            name = $Row.PolicyName
            description = [string]$Row.Description
            settings = @{ defaultAction = @{ '@odata.type' = "${prefix}webFilteringAction$action" } }
        }
    }
    if ($Kind -eq 'Profile') {
        $priority = 0L
        if (-not [long]::TryParse($Row.Priority, [ref]$priority) -or $priority -lt 1 -or $priority -gt 65000) {
            throw "Invalid priority '$($Row.Priority)' for profile '$($Row.SecurityProfileName)'."
        }
        if ($Row.ProfileState -notin @('Enabled', 'Disabled') -or $Row.LinkState -notin @('Enabled', 'Disabled')) {
            throw "Profile '$($Row.SecurityProfileName)' needs explicit Enabled/Disabled ProfileState and LinkState."
        }
        if ($priority -eq 65000 -and $Row.PolicyDefaultAction -eq 'ContinueEvaluation') {
            throw 'Baseline profiles cannot use ContinueEvaluation.'
        }
        return @{
            name = $Row.SecurityProfileName
            description = [string]$Row.Description
            priority = $priority
            state = $Row.ProfileState.ToLowerInvariant()
            policies = @()
        }
    }
    if ($Row.RuleType -eq 'None') {
        if ($Row.RuleName -or $Row.RuleDestinations -or $Row.RuleAction -or $Row.RulePriority -or $Row.RuleStatus) {
            throw "Default-only policy '$($Row.PolicyName)' must have empty rule fields."
        }
        return $null
    }
    $action = @{ Allow = 'Allow'; Block = 'Block' }[$Row.RuleAction]
    $targetType = @{ URL = 'webFilteringUrlDestination'; webCategory = 'webFilteringWebCategoryDestination' }[$Row.RuleType]
    if (-not $action -or -not $targetType) {
        throw "Unsupported rule '$($Row.RuleName)': action '$($Row.RuleAction)', type '$($Row.RuleType)'."
    }
    $priority = 0L
    if (-not [long]::TryParse($Row.RulePriority, [ref]$priority) -or $priority -lt 1) {
        throw "Invalid RulePriority '$($Row.RulePriority)' for '$($Row.RuleName)'."
    }
    if ($Row.RuleStatus -notin @('Enabled', 'Disabled')) { throw "Invalid RuleStatus for '$($Row.RuleName)'." }
    if ([string]::IsNullOrWhiteSpace($Row.RuleName)) { throw 'RuleName is required.' }
    $destinations = @($Row.RuleDestinations -split ';' | ForEach-Object { $_.Trim() })
    if ($destinations.Count -eq 0 -or '' -in $destinations -or @($destinations | Where-Object { $_ -match '^(UNMAPPED:|_Replace_Me)' }).Count -gt 0) {
        throw "Rule '$($Row.RuleName)' has empty or unresolved destinations."
    }
    return @{
        '@odata.type' = "${prefix}webFilteringRule"
        name = $Row.RuleName
        description = [string]$Row.RuleDescription
        priority = $priority
        action = @{ '@odata.type' = "${prefix}webFilteringAction$action" }
        settings = @{ status = $Row.RuleStatus.ToLowerInvariant() }
        matchingConditions = @{
            destinations = @{
                targets = @(@{ '@odata.type' = "$prefix$targetType"; values = $destinations })
            }
        }
    }
}
