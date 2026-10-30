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
    return $body
}
