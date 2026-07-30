#!/usr/bin/env pwsh
# verify.ps1 - Readiness verify loop for Migrate2GSA.
# Validates the module manifest, imports the module, and runs Pester tests if present.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
$failures = 0

Write-Host "== Module manifest =="
$manifest = Join-Path $root 'Migrate2GSA/Migrate2GSA.psd1'
if (-not (Test-Path $manifest)) { Write-Host "  MISSING: Migrate2GSA/Migrate2GSA.psd1"; $failures++ }
else {
    try { Test-ModuleManifest -Path $manifest -ErrorAction Stop | Out-Null; Write-Host "  OK: manifest valid." }
    catch { Write-Host "  MANIFEST ERROR: $($_.Exception.Message)"; $failures++ }
}

Write-Host "== Import module =="
try { Import-Module $manifest -Force -ErrorAction Stop; Write-Host "  OK: module imported." }
catch { Write-Host "  IMPORT ERROR: $($_.Exception.Message)"; $failures++ }

Write-Host "== Pester tests (if present) =="
$tests = Get-ChildItem -Recurse -File -Filter *.Tests.ps1 -ErrorAction SilentlyContinue
if ($tests) {
    if (Get-Module -ListAvailable -Name Pester) {
        $r = Invoke-Pester -Path $tests.FullName -PassThru -Output Minimal
        if ($r.FailedCount -gt 0) { Write-Host "  $($r.FailedCount) test(s) failed."; $failures++ }
        else { Write-Host "  OK: $($r.PassedCount) test(s) passed." }
    } else { Write-Host "  SKIP: Pester not installed ($($tests.Count) test file(s) found)." }
} else { Write-Host "  No *.Tests.ps1 found (skipping)." }

Pop-Location
if ($failures -gt 0) { Write-Host "verify.ps1 FAILED with $failures error(s)." -ForegroundColor Red; exit 1 }
Write-Host "verify.ps1 PASSED." -ForegroundColor Green
exit 0
