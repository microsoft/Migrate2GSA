function Assert-EIAV2Equivalent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Expected,
        [Parameter(Mandatory)][object]$Actual,
        [Parameter(Mandatory)][ValidateSet('Policy', 'Rule', 'Profile', 'Link', 'ConditionalAccess')][string]$Kind,
        [Parameter(Mandatory)][string]$Name
    )

    if ($Expected.'@odata.type' -and $Actual.'@odata.type' -and $Expected.'@odata.type' -cne $Actual.'@odata.type') {
        throw "OMv2 conflict for $Kind '$Name': different @odata.type '$($Actual.'@odata.type')'."
    }
    $expectedBody = Get-EIAV2WritableBody -Object $Expected -Kind $Kind
    $actualBody = Get-EIAV2WritableBody -Object $Actual -Kind $Kind
    $differences = @(
        foreach ($key in (@($expectedBody.Keys) + @($actualBody.Keys) | Sort-Object -Unique)) {
            $expectedValue = ConvertTo-EIAV2CanonicalJson $expectedBody[$key]
            $actualValue = ConvertTo-EIAV2CanonicalJson $actualBody[$key]
            if ($expectedValue -cne $actualValue) {
                "${key}: expected $expectedValue; existing $actualValue"
            }
        }
    )
    if ($differences.Count -gt 0) {
        throw "OMv2 conflict for $Kind '$Name': $($differences -join ' | '). No automatic update is allowed."
    }
}
