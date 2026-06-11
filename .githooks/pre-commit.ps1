#!/usr/bin/env pwsh
# Pre-commit hook: auto-bumps Migrate2GSA module version to YYYY.M.D.N when files
# under Migrate2GSA/** are staged. Enable with: git config core.hooksPath .githooks
$ErrorActionPreference = 'Stop'

$repoRoot     = (& git rev-parse --show-toplevel).Trim()
$manifestRel  = 'Migrate2GSA/Migrate2GSA.psd1'
$manifestPath = Join-Path $repoRoot $manifestRel

$staged = @(& git diff --cached --name-only --diff-filter=ACMR) | Where-Object { $_ }
if (-not $staged) { exit 0 }

$moduleChanges = $staged | Where-Object { $_ -like 'Migrate2GSA/*' -or $_ -like 'Migrate2GSA\*' }
if (-not $moduleChanges) { exit 0 }

# If the only staged module change is the manifest itself, assume an intentional manual bump.
$nonManifest = $moduleChanges | Where-Object { ($_ -replace '\\','/') -ne $manifestRel }
if (-not $nonManifest -and ($moduleChanges | Where-Object { ($_ -replace '\\','/') -eq $manifestRel })) {
    exit 0
}

if (-not (Test-Path $manifestPath)) {
    Write-Error "Manifest not found at $manifestPath"
    exit 1
}

$manifest = Import-PowerShellDataFile -Path $manifestPath
$current  = [System.Version]$manifest.ModuleVersion

$now   = Get-Date
$year  = $now.Year
$month = $now.Month
$day   = $now.Day

if ($current.Major -eq $year -and $current.Minor -eq $month -and $current.Build -eq $day) {
    $revision = [Math]::Max($current.Revision, 0) + 1
} else {
    $revision = 1
}

$newVersion = "$year.$month.$day.$revision"

Update-ModuleManifest -Path $manifestPath -ModuleVersion $newVersion
& git add -- $manifestRel | Out-Null

[Console]::Error.WriteLine("[pre-commit] Bumped ModuleVersion: $current -> $newVersion")
exit 0
