function Get-EIAV2WritableBody {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][ValidateSet('Policy', 'Rule', 'Profile', 'Link', 'ConditionalAccess')][string]$Kind
    )

    $body = $Object | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable
    foreach ($key in @('id', 'version', 'createdDateTime', 'lastModifiedDateTime', 'modifiedDateTime')) {
        $body.Remove($key)
    }
    foreach ($key in @($body.Keys | Where-Object { $_ -like '@odata.*' })) {
        $body.Remove($key)
    }
    if ($Kind -eq 'Policy') { $body.Remove('policyRules') }
    if ($Kind -eq 'Profile') {
        $body.Remove('policies')
        $body.Remove('conditionalAccessPolicies')
    }
    if ($Kind -eq 'Link' -and $body.policy) {
        $body.policy = @{ id = $body.policy.id }
    }
    if ($Kind -eq 'ConditionalAccess') {
        $profile = $body.sessionControls.globalSecureAccessFilteringProfile
        $network = $body.sessionControls.networkAccessSecurity
        # Canary can return both representations of the same profile binding.
        if ($profile -is [System.Collections.IDictionary] -and
            $network -is [System.Collections.IDictionary] -and
            $profile.Count -eq 2 -and $network.Count -eq 2 -and
            $profile.profileId -is [string] -and -not [string]::IsNullOrWhiteSpace($profile.profileId) -and
            $profile.profileId -ceq $network.policyId -and
            $profile.isEnabled -is [bool] -and $network.isEnabled -is [bool] -and
            $profile.isEnabled -eq $network.isEnabled) {
            $body.sessionControls.Remove('networkAccessSecurity')
        }
    }
    return $body
}
